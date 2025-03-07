#include <exception>
#include <future>
#include <stdexcept>
#include <thread>
#include <unordered_set>

#include <uuid_v4.h>

#include "service/nostr_service_base.hpp"

using namespace nlohmann;
using namespace nostr::service;
using namespace std;

NostrServiceBase::NostrServiceBase(
    shared_ptr<plog::IAppender> appender,
    shared_ptr<client::IWebSocketClient> client
) : NostrServiceBase(appender, client, {}) { };

NostrServiceBase::NostrServiceBase(
    shared_ptr<plog::IAppender> appender,
    shared_ptr<client::IWebSocketClient> client,
    vector<string> relays
) : _defaultRelays(relays), _client(client)
{
    plog::init(plog::debug, appender.get());
    client->start();
};

NostrServiceBase::~NostrServiceBase()
{
    this->_client->stop();
};

vector<string> NostrServiceBase::defaultRelays() const
{ return this->_defaultRelays; };

vector<string> NostrServiceBase::activeRelays() const
{ return this->_activeRelays; };

unordered_map<string, vector<string>> NostrServiceBase::subscriptions() const
{ return this->_subscriptions; };

vector<string> NostrServiceBase::openRelayConnections()
{
    return this->openRelayConnections(this->_defaultRelays);
};

vector<string> NostrServiceBase::openRelayConnections(vector<string> relays)
{
    PLOG_INFO << "Attempting to connect to Nostr relays.";
    vector<string> unconnectedRelays = this->_getUnconnectedRelays(relays);

    vector<thread> connectionThreads;
    for (string relay : unconnectedRelays)
    {
        thread connectionThread([this, relay]() {
            this->_connect(relay);
        });
        connectionThreads.push_back(move(connectionThread));
    }

    for (thread& connectionThread : connectionThreads)
    {
        connectionThread.join();
    }

    std::size_t targetCount = relays.size();
    std::size_t activeCount = this->_activeRelays.size();
    PLOG_INFO << "Connected to " << activeCount << "/" << targetCount << " target relays.";

    // This property should only contain successful relays at this point.
    return this->_activeRelays;
};

void NostrServiceBase::closeRelayConnections()
{
    if (this->_activeRelays.size() == 0)
    {
        PLOG_INFO << "No active relay connections to close.";
        return;
    }

    this->closeRelayConnections(this->_activeRelays);
};

void NostrServiceBase::closeRelayConnections(vector<string> relays)
{
    PLOG_INFO << "Disconnecting from Nostr relays.";
    vector<string> connectedRelays = this->_getConnectedRelays(relays);

    vector<thread> disconnectionThreads;
    for (string relay : connectedRelays)
    {
        thread disconnectionThread([this, relay]() {
            this->_disconnect(relay);
        });
        disconnectionThreads.push_back(move(disconnectionThread));

        // TODO: Close subscriptions before disconnecting.
        lock_guard<mutex> lock(this->_propertyMutex);
        this->_subscriptions.erase(relay);
    }

    for (thread& disconnectionThread : disconnectionThreads)
    {
        disconnectionThread.join();
    }
};

// TODO: Make this method return a promise.
tuple<vector<string>, vector<string>> NostrServiceBase::publishEvent(
    shared_ptr<nostr::data::Event> event
)
{
    vector<string> successfulRelays;
    vector<string> failedRelays;

    PLOG_INFO << "Attempting to publish event to Nostr relays.";

    json message;
    try
    {
        message = json::array({ "EVENT", event->serialize() });
    }
    catch (const std::invalid_argument& e)
    {
        PLOG_ERROR << "Failed to sign event: " << e.what();
        throw e;
    }
    catch (const json::exception& je)
    {
        PLOG_ERROR << "Failed to serialize event: " << je.what();
        throw je;
    }

    lock_guard<mutex> lock(this->_propertyMutex);
    vector<string> targetRelays = this->_activeRelays;
    vector<future<tuple<string, bool>>> publishFutures;
    for (const string& relay : targetRelays)
    {
        promise<tuple<string, bool>> publishPromise;
        publishFutures.push_back(move(publishPromise.get_future()));

        auto [uri, success] = this->_client->send(
            message.dump(),
            relay,
            [this, &relay, &event, &publishPromise](string response)
            {
                this->_onAcceptance(
                    response,
                    [this, &relay, &event, &publishPromise](bool isAccepted)
                    {
                        if (isAccepted)
                        {
                            PLOG_INFO << "Relay " << relay << " accepted event: " << event->id;
                            publishPromise.set_value(make_tuple(relay, true));
                        }
                        else
                        {
                            PLOG_WARNING << "Relay " << relay << " rejected event: " << event->id;
                            publishPromise.set_value(make_tuple(relay, false));
                        }
                    }
                );
            });

        if (!success)
        {
            PLOG_WARNING << "Failed to send event to relay " << relay;
            publishPromise.set_value(make_tuple(relay, false));
        }
    }

    for (auto& publishFuture : publishFutures)
    {
        auto [relay, isSuccess] = publishFuture.get();
        if (isSuccess)
        {
            successfulRelays.push_back(relay);
        }
        else
        {
            failedRelays.push_back(relay);
        }
    }

    std::size_t targetCount = targetRelays.size();
    std::size_t successfulCount = successfulRelays.size();
    PLOG_INFO << "Published event to " << successfulCount << "/" << targetCount << " target relays.";

    return make_tuple(successfulRelays, failedRelays);
};

// TODO: Add a timeout to this method to prevent hanging while waiting for the relay.
future<vector<shared_ptr<nostr::data::Event>>> NostrServiceBase::queryRelays(
    shared_ptr<nostr::data::Filters> filters)
{
    return async(launch::async, [this, filters]() -> vector<shared_ptr<nostr::data::Event>>
    {
        if (filters->limit > 64 || filters->limit < 1)
        {
            PLOG_WARNING << "Filters limit must be between 1 and 64, inclusive.  Setting limit to 16.";
            filters->limit = 16;
        }

        vector<shared_ptr<nostr::data::Event>> events;

        string subscriptionId = this->_generateSubscriptionId();
        string request;

        try
        {
            request = filters->serialize(subscriptionId);
        }
        catch (const invalid_argument& e)
        {
            PLOG_ERROR << "Failed to serialize filters - invalid object: " << e.what();
            throw e;
        }
        catch (const json::exception& je)
        {
            PLOG_ERROR << "Failed to serialize filters - JSON exception: " << je.what();
            throw je;
        }

        vector<future<tuple<string, bool>>> requestFutures;

        unordered_set<string> uniqueEventIds;

        // Send the same query to each relay.  As events trickle in from each relay, they will be added
        // to the events vector.  Duplicate copies of the same event will be ignored, as events are
        // stored on multiple relays.  The function will block until all of the relays send an EOSE or
        // CLOSE message.
        for (const string relay : this->_activeRelays)
        {
            promise<tuple<string, bool>> eosePromise;
            requestFutures.push_back(move(eosePromise.get_future()));

            auto [uri, success] = this->_client->send(
                request,
                relay,
                [this, &relay, &events, &eosePromise, &uniqueEventIds](string payload)
                {
                    this->_onSubscriptionMessage(
                        payload,
                        [&events, &uniqueEventIds](const string&, shared_ptr<nostr::data::Event> event)
                        {
                            // Check if the event is unique before adding.
                            if (uniqueEventIds.insert(event->id).second)
                            {
                                events.push_back(event);
                            }
                        },
                        [relay, &eosePromise](const string&)
                        {
                            eosePromise.set_value(make_tuple(relay, true));
                        },
                        [relay, &eosePromise](const string&, const string&)
                        {
                            eosePromise.set_value(make_tuple(relay, false));
                        });
                }
            );

            if (success)
            {
                PLOG_INFO << "Sent query to relay " << relay;
                lock_guard<mutex> lock(this->_propertyMutex);
                this->_subscriptions[subscriptionId].push_back(relay);
            }
            else
            {
                PLOG_WARNING << "Failed to send query to relay " << relay;
                eosePromise.set_value(make_tuple(uri, false));
            }
        }


        // Close open subscriptions and disconnect from relays after events are received.

        for (auto& publishFuture : requestFutures)
        {
            auto [relay, isEose] = publishFuture.get();
            if (isEose)
            {
                PLOG_INFO << "Received EOSE message from relay " << relay;
            }
            else
            {
                PLOG_WARNING << "Received CLOSE message from relay " << relay;
                this->closeRelayConnections({ relay });
            }
        }
        this->closeSubscription(subscriptionId);

        return events;
    });
};

string NostrServiceBase::queryRelays(
    shared_ptr<nostr::data::Filters> filters,
    function<void(const string&, shared_ptr<nostr::data::Event>)> eventHandler,
    function<void(const string&)> eoseHandler,
    function<void(const string&, const string&)> closeHandler
)
{
    vector<string> successfulRelays;
    vector<string> failedRelays;

    string subscriptionId = this->_generateSubscriptionId();
    string request = filters->serialize(subscriptionId);
    vector<future<tuple<string, bool>>> requestFutures;
    for (const string relay : this->_activeRelays)
    {
        unique_lock<mutex> lock(this->_propertyMutex);
        this->_subscriptions[subscriptionId].push_back(relay);
        lock.unlock();

        future<tuple<string, bool>> requestFuture = async(
            [this, &relay, &request, &eventHandler, &eoseHandler, &closeHandler]()
            {
                return this->_client->send(
                    request,
                    relay,
                    [this, &eventHandler, &eoseHandler, &closeHandler](string payload)
                    {
                        this->_onSubscriptionMessage(payload, eventHandler, eoseHandler, closeHandler);
                    });
            }
        );
        requestFutures.push_back(move(requestFuture));
    }

    for (auto& publishFuture : requestFutures)
    {
        auto [relay, isSuccess] = publishFuture.get();
        if (isSuccess)
        {
            successfulRelays.push_back(relay);
        }
        else
        {
            failedRelays.push_back(relay);
        }
    }

    std::size_t targetCount = this->_activeRelays.size();
    std::size_t successfulCount = successfulRelays.size();
    PLOG_INFO << "Sent query to " << successfulCount << "/" << targetCount << " open relay connections.";

    return subscriptionId;
};

tuple<vector<string>, vector<string>> NostrServiceBase::closeSubscription(string subscriptionId)
{
    vector<string> successfulRelays;
    vector<string> failedRelays;

    vector<string> subscriptionRelays;
    std::size_t subscriptionRelayCount;
    vector<future<tuple<string, bool>>> closeFutures;

    try
    {
        unique_lock<mutex> lock(this->_propertyMutex);
        subscriptionRelays = this->_subscriptions.at(subscriptionId);
        subscriptionRelayCount = subscriptionRelays.size();
        lock.unlock();
    }
    catch (const out_of_range& oor)
    {
        PLOG_WARNING << "Subscription " << subscriptionId << " not found.";
        return make_tuple(successfulRelays, failedRelays);
    }

    for (const string relay : subscriptionRelays)
    {
        future<tuple<string, bool>> closeFuture = async([this, subscriptionId, relay]()
        {
            bool success = this->closeSubscription(subscriptionId, relay);

            return make_tuple(relay, success);
        });
        closeFutures.push_back(move(closeFuture));
    }

    for (auto& closeFuture : closeFutures)
    {
        auto [uri, success] = closeFuture.get();
        if (success)
        {
            successfulRelays.push_back(uri);
        }
        else
        {
            failedRelays.push_back(uri);
        }
    }

    std::size_t successfulCount = successfulRelays.size();
    PLOG_INFO << "Sent CLOSE request for subscription " << subscriptionId << " to " << successfulCount << "/" << subscriptionRelayCount << " open relay connections.";

    // If there were no failures, and the subscription has been closed on all of its relays, forget
    // about the subscription.
    if (failedRelays.empty())
    {
        lock_guard<mutex> lock(this->_propertyMutex);
        this->_subscriptions.erase(subscriptionId);
    }

    return make_tuple(successfulRelays, failedRelays);
};

bool NostrServiceBase::closeSubscription(string subscriptionId, string relay)
{
    if (!this->_hasSubscription(subscriptionId, relay))
    {
        PLOG_WARNING << "Subscription " << subscriptionId << " not found on relay " << relay;
        return false;
    }

    if (!this->_isConnected(relay))
    {
        PLOG_WARNING << "Relay " << relay << " is not connected.";
        return false;
    }

    string request = this->_generateCloseRequest(subscriptionId);
    auto [uri, success] = this->_client->send(request, relay);

    if (success)
    {
        lock_guard<mutex> lock(this->_propertyMutex);
        auto it = find(
            this->_subscriptions[subscriptionId].begin(),
            this->_subscriptions[subscriptionId].end(),
            relay);

        if (it != this->_subscriptions[subscriptionId].end())
        {
            this->_subscriptions[subscriptionId].erase(it);
        }

        PLOG_INFO << "Sent close request for subscription " << subscriptionId << " to relay " << relay;
    }
    else
    {
        PLOG_WARNING << "Failed to send close request to relay " << relay;
    }

    return success;
};

vector<string> NostrServiceBase::closeSubscriptions()
{
    unique_lock<mutex> lock(this->_propertyMutex);
    vector<string> subscriptionIds;
    for (auto& [subscriptionId, relays] : this->_subscriptions)
    {
        subscriptionIds.push_back(subscriptionId);
    }
    lock.unlock();

    vector<string> remainingSubscriptions;
    for (const string& subscriptionId : subscriptionIds)
    {
        auto [successes, failures] = this->closeSubscription(subscriptionId);
        if (!failures.empty())
        {
            remainingSubscriptions.push_back(subscriptionId);
        }
    }

    return remainingSubscriptions;
};

vector<string> NostrServiceBase::_getConnectedRelays(vector<string> relays)
{
    PLOG_VERBOSE << "Identifying connected relays.";
    vector<string> connectedRelays;
    for (string relay : relays)
    {
        bool isActive = find(this->_activeRelays.begin(), this->_activeRelays.end(), relay)
            != this->_activeRelays.end();
        bool isConnected = this->_client->isConnected(relay);
        PLOG_VERBOSE << "Relay " << relay << " is active: " << isActive << ", is connected: " << isConnected;

        if (isActive && isConnected)
        {
            connectedRelays.push_back(relay);
        }
        else if (isActive && !isConnected)
        {
            this->_eraseActiveRelay(relay);
        }
        else if (!isActive && isConnected)
        {
            this->_activeRelays.push_back(relay);
            connectedRelays.push_back(relay);
        }
    }
    return connectedRelays;
};

vector<string> NostrServiceBase::_getUnconnectedRelays(vector<string> relays)
{
    PLOG_VERBOSE << "Identifying unconnected relays.";
    vector<string> unconnectedRelays;
    for (string relay : relays)
    {
        bool isActive = find(this->_activeRelays.begin(), this->_activeRelays.end(), relay)
            != this->_activeRelays.end();
        bool isConnected = this->_client->isConnected(relay);
        PLOG_VERBOSE << "Relay " << relay << " is active: " << isActive << ", is connected: " << isConnected;

        if (!isActive && !isConnected)
        {
            PLOG_VERBOSE << "Relay " << relay << " is not active and not connected.";
            unconnectedRelays.push_back(relay);
        }
        else if (isActive && !isConnected)
        {
            PLOG_VERBOSE << "Relay " << relay << " is active but not connected.  Removing from active relays list.";
            this->_eraseActiveRelay(relay);
            unconnectedRelays.push_back(relay);
        }
        else if (!isActive && isConnected)
        {
            PLOG_VERBOSE << "Relay " << relay << " is connected but not active.  Adding to active relays list.";
            this->_activeRelays.push_back(relay);
        }
    }
    return unconnectedRelays;
};

bool NostrServiceBase::_isConnected(string relay)
{
    auto it = find(this->_activeRelays.begin(), this->_activeRelays.end(), relay);
    if (it != this->_activeRelays.end()) // If the relay is in this->_activeRelays
    {
        return true;
    }
    return false;
};

void NostrServiceBase::_eraseActiveRelay(string relay)
{
    auto it = find(this->_activeRelays.begin(), this->_activeRelays.end(), relay);
    if (it != this->_activeRelays.end()) // If the relay is in this->_activeRelays
    {
        this->_activeRelays.erase(it);
    }
};

void NostrServiceBase::_connect(string relay)
{
    PLOG_VERBOSE << "Connecting to relay " << relay;
    this->_client->openConnection(relay);

    lock_guard<mutex> lock(this->_propertyMutex);
    bool isConnected = this->_client->isConnected(relay);

    if (isConnected)
    {
        PLOG_VERBOSE << "Connected to relay " << relay << ": " << isConnected;
        this->_activeRelays.push_back(relay);
    }
    else
    {
        PLOG_ERROR << "Failed to connect to relay " << relay;
    }
};

void NostrServiceBase::_disconnect(string relay)
{
    this->_client->closeConnection(relay);

    lock_guard<mutex> lock(this->_propertyMutex);
    this->_eraseActiveRelay(relay);
};

string NostrServiceBase::_generateSubscriptionId()
{
    UUIDv4::UUIDGenerator<std::mt19937_64> uuidGenerator;
    UUIDv4::UUID uuid = uuidGenerator.getUUID();
    return uuid.str();
};

string NostrServiceBase::_generateCloseRequest(string subscriptionId)
{
    json jarr = json::array({ "CLOSE", subscriptionId });
    return jarr.dump();
};

bool NostrServiceBase::_hasSubscription(string subscriptionId)
{
    lock_guard<mutex> lock(this->_propertyMutex);
    auto it = this->_subscriptions.find(subscriptionId);

    return it != this->_subscriptions.end();
};

bool NostrServiceBase::_hasSubscription(string subscriptionId, string relay)
{
    lock_guard<mutex> lock(this->_propertyMutex);
    auto subscriptionIt = this->_subscriptions.find(subscriptionId);

    if (subscriptionIt == this->_subscriptions.end())
    {
        return false;
    }

    auto relays = this->_subscriptions[subscriptionId];
    auto relayIt = find(relays.begin(), relays.end(), relay);

    return relayIt != relays.end();
};

void NostrServiceBase::_onSubscriptionMessage(
    string message,
    function<void(const string&, shared_ptr<nostr::data::Event>)> eventHandler,
    function<void(const string&)> eoseHandler,
    function<void(const string&, const string&)> closeHandler
)
{
    try
    {
        json jMessage = json::parse(message);
        string messageType = jMessage.at(0);
        if (messageType == "EVENT")
        {
            string subscriptionId = jMessage.at(1);
            nostr::data::Event event = nostr::data::Event::fromString(jMessage.at(2));
            eventHandler(subscriptionId, make_shared<nostr::data::Event>(event));
        }
        else if (messageType == "EOSE")
        {
            string subscriptionId = jMessage.at(1);
            eoseHandler(subscriptionId);
        }
        else if (messageType == "CLOSE")
        {
            string subscriptionId = jMessage.at(1);
            string reason = jMessage.at(2);
            closeHandler(subscriptionId, reason);
        }
    }
    catch (const json::out_of_range& joor)
    {
        PLOG_ERROR << "JSON out-of-range exception: " << joor.what();
        throw joor;
    }
    catch (const json::exception& je)
    {
        PLOG_ERROR << "JSON handling exception: " << je.what();
        throw je;
    }
    catch (const invalid_argument& ia)
    {
        PLOG_ERROR << "Invalid argument exception: " << ia.what();
        throw ia;
    }
};

void NostrServiceBase::_onAcceptance(
    string message,
    function<void(const bool)> acceptanceHandler
)
{
    try
    {
        json jMessage = json::parse(message);
        string messageType = jMessage[0];
        if (messageType == "OK")
        {
            bool isAccepted = jMessage[2];
            acceptanceHandler(isAccepted);
        }
    }
    catch (const json::exception& je)
    {
        PLOG_ERROR << "JSON handling exception: " << je.what();
        throw je;
    }
};
