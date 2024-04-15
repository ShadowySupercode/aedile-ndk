#include <chrono>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <plog/Appenders/ConsoleAppender.h>
#include <plog/Formatters/TxtFormatter.h>
#include <iostream>
#include <websocketpp/client.hpp>

#include <client/web_socket_client.hpp>
#include <nostr.hpp>

using nlohmann::json;
using std::function;
using std::lock_guard;
using std::make_shared;
using std::make_unique;
using std::mutex;
using std::shared_ptr;
using std::string;
using std::tuple;
using std::unordered_map;
using std::vector;
using ::testing::_;
using ::testing::Args;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::Truly;

namespace nostr_test
{
class MockWebSocketClient : public client::IWebSocketClient {
public:
    MOCK_METHOD(void, start, (), (override));
    MOCK_METHOD(void, stop, (), (override));
    MOCK_METHOD(void, openConnection, (string uri), (override));
    MOCK_METHOD(bool, isConnected, (string uri), (override));
    MOCK_METHOD((tuple<string, bool>), send, (string message, string uri), (override));
    MOCK_METHOD((tuple<string, bool>), send, (string message, string uri, function<void(const string&)> messageHandler), (override));
    MOCK_METHOD(void, receive, (string uri, function<void(const string&)> messageHandler), (override));
    MOCK_METHOD(void, closeConnection, (string uri), (override));
};

class FakeSigner : public nostr::ISigner 
{
public:
    void sign(shared_ptr<nostr::Event> event) override
    {
        event->sig = "fake_signature";
    }
};

class NostrServiceTest : public testing::Test
{
public:
    inline static const nostr::RelayList defaultTestRelays =
    {
        "wss://relay.damus.io",
        "wss://nostr.thesamecat.io"
    };

    static const nostr::Event getTextNoteTestEvent()
    {
        nostr::Event event;
        event.pubkey = "13tn5ccv2guflxgffq4aj0hw5x39pz70zcdrfd6vym887gry38zys28dask";
        event.kind = 1;
        event.tags =
        {
            { "e", "5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36", "wss://nostr.example.com" },
            { "p", "f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca" },
            { "a", "30023:f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca:abcd", "wss://nostr.example.com" }
        };
        event.content = "Hello, World!";

        return event;
    };

    static const vector<nostr::Event> getMultipleTextNoteTestEvents()
    {
        auto now = std::chrono::system_clock::now();
        std::time_t currentTime = std::chrono::system_clock::to_time_t(now);

        nostr::Event event1;
        event1.pubkey = "13tn5ccv2guflxgffq4aj0hw5x39pz70zcdrfd6vym887gry38zys28dask";
        event1.kind = 1;
        event1.tags = 
        {
            { "e", "5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36", "wss://nostr.example.com" },
            { "p", "f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca" },
            { "a", "30023:f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca:abcd", "wss://nostr.example.com" }
        };
        event1.content = "Hello, World!";
        event1.createdAt = currentTime;

        nostr::Event event2;
        event2.pubkey = "1l9d9jh67rkwayalrxcy686aujyz5pper5kzjv8jvg8pu9v9ns4ls0xvq42";
        event2.kind = 1;
        event2.tags =
        {
            { "e", "5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36", "wss://nostr.example.com" },
            { "p", "f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca" },
            { "a", "30023:f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca:abcd", "wss://nostr.example.com" }
        };
        event2.content = "Welcome to Nostr!";
        event2.createdAt = currentTime;
        
        nostr::Event event3;
        event3.pubkey = "187ujhtmnv82ftg03h4heetwk3dd9mlfkf8th3fvmrk20nxk9mansuzuyla";
        event3.kind = 1;
        event3.tags =
        {
            { "e", "5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36", "wss://nostr.example.com" },
            { "p", "f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca" },
            { "a", "30023:f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca:abcd", "wss://nostr.example.com" }
        };
        event3.content = "Time for some introductions!";
        event3.createdAt = currentTime;

        return { event1, event2, event3 };
    };

    static const nostr::Event getLongFormTestEvent()
    {
        nostr::Event event;
        event.pubkey = "13tn5ccv2guflxgffq4aj0hw5x39pz70zcdrfd6vym887gry38zys28dask";
        event.kind = 30023;
        event.tags =
        {
            { "event", "5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36", "wss://nostr.example.com" },
            { "pubkey", "f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca" },
            { "author", "30023:f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca:abcd", "wss://nostr.example.com" }
        };
        event.content = "Hello, World!";

        return event;
    }

    static const string getTestEventMessage(shared_ptr<nostr::Event> event, string subscriptionId)
    {        
        auto signer = make_unique<FakeSigner>();
        signer->sign(event);

        json jarr = json::array();
        jarr.push_back("EVENT");
        jarr.push_back(subscriptionId);
        jarr.push_back(event->serialize());

        return jarr.dump();
    }

    static const nostr::Filters getKind0And1TestFilters()
    {
        nostr::Filters filters;
        filters.authors = {
            "13tn5ccv2guflxgffq4aj0hw5x39pz70zcdrfd6vym887gry38zys28dask", 
            "1l9d9jh67rkwayalrxcy686aujyz5pper5kzjv8jvg8pu9v9ns4ls0xvq42",
            "187ujhtmnv82ftg03h4heetwk3dd9mlfkf8th3fvmrk20nxk9mansuzuyla"
        };
        filters.kinds = { 0, 1 };
        filters.limit = 10;

        return filters;
    }

    static const nostr::Filters getKind30023TestFilters()
    {
        nostr::Filters filters;
        filters.authors = {
            "13tn5ccv2guflxgffq4aj0hw5x39pz70zcdrfd6vym887gry38zys28dask", 
            "1l9d9jh67rkwayalrxcy686aujyz5pper5kzjv8jvg8pu9v9ns4ls0xvq42",
            "187ujhtmnv82ftg03h4heetwk3dd9mlfkf8th3fvmrk20nxk9mansuzuyla"
        };
        filters.kinds = { 30023 };
        filters.limit = 5;

        return filters;
    }

protected:
    shared_ptr<plog::ConsoleAppender<plog::TxtFormatter>> testAppender;
    shared_ptr<MockWebSocketClient> mockClient;
    shared_ptr<FakeSigner> fakeSigner;

    void SetUp() override
    {
        testAppender = make_shared<plog::ConsoleAppender<plog::TxtFormatter>>();
        mockClient = make_shared<MockWebSocketClient>();
        fakeSigner = make_shared<FakeSigner>();
    };
};

TEST_F(NostrServiceTest, Constructor_StartsClient)
{
    EXPECT_CALL(*mockClient, start()).Times(1);

    auto nostrService = make_unique<nostr::NostrService>(testAppender, mockClient, fakeSigner);
};

TEST_F(NostrServiceTest, Constructor_InitializesService_WithNoDefaultRelays)
{
    auto nostrService = make_unique<nostr::NostrService>(testAppender, mockClient, fakeSigner);
    auto defaultRelays = nostrService->defaultRelays();
    auto activeRelays = nostrService->activeRelays();

    ASSERT_EQ(defaultRelays.size(), 0);
    ASSERT_EQ(activeRelays.size(), 0);
};

TEST_F(NostrServiceTest, Constructor_InitializesService_WithProvidedDefaultRelays)
{
    auto nostrService = make_unique<nostr::NostrService>(
        testAppender,
        mockClient,
        fakeSigner,
        defaultTestRelays);
    auto defaultRelays = nostrService->defaultRelays();
    auto activeRelays = nostrService->activeRelays();

    ASSERT_EQ(defaultRelays.size(), defaultTestRelays.size());
    for (auto relay : defaultRelays)
    {
        ASSERT_NE(find(defaultTestRelays.begin(), defaultTestRelays.end(), relay), defaultTestRelays.end());
    }
    ASSERT_EQ(activeRelays.size(), 0);
};

TEST_F(NostrServiceTest, Destructor_StopsClient)
{
    EXPECT_CALL(*mockClient, start()).Times(1);

    auto nostrService = make_unique<nostr::NostrService>(testAppender, mockClient, fakeSigner);
};

TEST_F(NostrServiceTest, OpenRelayConnections_OpensConnections_ToDefaultRelays)
{
    mutex connectionStatusMutex;
    auto connectionStatus = make_shared<unordered_map<string, bool>>();
    connectionStatus->insert({ defaultTestRelays[0], false });
    connectionStatus->insert({ defaultTestRelays[1], false });

    EXPECT_CALL(*mockClient, openConnection(defaultTestRelays[0])).Times(1);
    EXPECT_CALL(*mockClient, openConnection(defaultTestRelays[1])).Times(1);

    EXPECT_CALL(*mockClient, isConnected(_))
        .WillRepeatedly(Invoke([connectionStatus, &connectionStatusMutex](string uri)
        {
            lock_guard<mutex> lock(connectionStatusMutex);
            bool status = connectionStatus->at(uri);
            if (status == false)
            {
                connectionStatus->at(uri) = true;
            }
            return status;
        }));
    
    auto nostrService = make_unique<nostr::NostrService>(
        testAppender,
        mockClient,
        fakeSigner,
        defaultTestRelays);
    nostrService->openRelayConnections();

    auto activeRelays = nostrService->activeRelays();
    ASSERT_EQ(activeRelays.size(), defaultTestRelays.size());
    for (auto relay : activeRelays)
    {
        ASSERT_NE(find(defaultTestRelays.begin(), defaultTestRelays.end(), relay), defaultTestRelays.end());
    }
};

TEST_F(NostrServiceTest, OpenRelayConnections_OpensConnections_ToProvidedRelays)
{
    nostr::RelayList testRelays = { "wss://nos.lol" };

    mutex connectionStatusMutex;
    auto connectionStatus = make_shared<unordered_map<string, bool>>();
    connectionStatus -> insert({ testRelays[0], false });

    EXPECT_CALL(*mockClient, openConnection(testRelays[0])).Times(1);
    EXPECT_CALL(*mockClient, openConnection(defaultTestRelays[0])).Times(0);
    EXPECT_CALL(*mockClient, openConnection(defaultTestRelays[1])).Times(0);

    EXPECT_CALL(*mockClient, isConnected(_))
        .WillRepeatedly(Invoke([connectionStatus, &connectionStatusMutex](string uri)
        {
            lock_guard<mutex> lock(connectionStatusMutex);
            bool status = connectionStatus->at(uri);
            if (status == false)
            {
                connectionStatus->at(uri) = true;
            }
            return status;
        }));

    auto nostrService = make_unique<nostr::NostrService>(
        testAppender,
        mockClient,
        fakeSigner,
        defaultTestRelays);
    nostrService->openRelayConnections(testRelays);

    auto activeRelays = nostrService->activeRelays();
    ASSERT_EQ(activeRelays.size(), testRelays.size());
    for (auto relay : activeRelays)
    {
        ASSERT_NE(find(testRelays.begin(), testRelays.end(), relay), testRelays.end());
    }
};

TEST_F(NostrServiceTest, OpenRelayConnections_AddsOpenConnections_ToActiveRelays)
{
    nostr::RelayList testRelays = { "wss://nos.lol" };

    mutex connectionStatusMutex;
    auto connectionStatus = make_shared<unordered_map<string, bool>>();
    connectionStatus->insert({ defaultTestRelays[0], false });
    connectionStatus->insert({ defaultTestRelays[1], false });
    connectionStatus->insert({ testRelays[0], false });

    EXPECT_CALL(*mockClient, openConnection(defaultTestRelays[0])).Times(1);
    EXPECT_CALL(*mockClient, openConnection(defaultTestRelays[1])).Times(1);
    EXPECT_CALL(*mockClient, openConnection(testRelays[0])).Times(1);

    EXPECT_CALL(*mockClient, isConnected(_))
        .WillRepeatedly(Invoke([connectionStatus, &connectionStatusMutex](string uri)
        {
            lock_guard<mutex> lock(connectionStatusMutex);
            bool status = connectionStatus->at(uri);
            if (status == false)
            {
                connectionStatus->at(uri) = true;
            }
            return status;
        }));

    auto nostrService = make_unique<nostr::NostrService>(
        testAppender,
        mockClient,
        fakeSigner,
        defaultTestRelays);
    nostrService->openRelayConnections();

    auto activeRelays = nostrService->activeRelays();
    ASSERT_EQ(activeRelays.size(), defaultTestRelays.size());
    for (auto relay : activeRelays)
    {
        ASSERT_NE(find(defaultTestRelays.begin(), defaultTestRelays.end(), relay), defaultTestRelays.end());
    }

    nostrService->openRelayConnections(testRelays);

    activeRelays = nostrService->activeRelays();
    ASSERT_EQ(activeRelays.size(), defaultTestRelays.size() + testRelays.size());
    for (auto relay : activeRelays)
    {
        bool isDefaultRelay = find(defaultTestRelays.begin(), defaultTestRelays.end(), relay)
            != defaultTestRelays.end();
        bool isTestRelay = find(testRelays.begin(), testRelays.end(), relay)
            != testRelays.end();
        ASSERT_TRUE(isDefaultRelay || isTestRelay);
    }
};

TEST_F(NostrServiceTest, CloseRelayConnections_ClosesConnections_ToActiveRelays)
{
    mutex connectionStatusMutex;
    auto connectionStatus = make_shared<unordered_map<string, bool>>();
    connectionStatus->insert({ defaultTestRelays[0], false });
    connectionStatus->insert({ defaultTestRelays[1], false });

    EXPECT_CALL(*mockClient, isConnected(_))
        .WillRepeatedly(Invoke([connectionStatus, &connectionStatusMutex](string uri)
        {
            lock_guard<mutex> lock(connectionStatusMutex);
            bool status = connectionStatus->at(uri);
            if (status == false)
            {
                connectionStatus->at(uri) = true;
            }
            return status;
        }));

    auto nostrService = make_unique<nostr::NostrService>(
        testAppender,
        mockClient,
        fakeSigner,
        defaultTestRelays);
    nostrService->openRelayConnections();

    EXPECT_CALL(*mockClient, closeConnection(defaultTestRelays[0])).Times(1);
    EXPECT_CALL(*mockClient, closeConnection(defaultTestRelays[1])).Times(1);

    nostrService->closeRelayConnections();

    auto activeRelays = nostrService->activeRelays();
    ASSERT_EQ(activeRelays.size(), 0);
};

TEST_F(NostrServiceTest, CloseRelayConnections_RemovesClosedConnections_FromActiveRelays)
{
    nostr::RelayList testRelays = { "wss://nos.lol" };
    nostr::RelayList allTestRelays = { defaultTestRelays[0], defaultTestRelays[1], testRelays[0] };

    mutex connectionStatusMutex;
    auto connectionStatus = make_shared<unordered_map<string, bool>>();
    connectionStatus->insert({ defaultTestRelays[0], false });
    connectionStatus->insert({ defaultTestRelays[1], false });
    connectionStatus->insert({ testRelays[0], false });

    EXPECT_CALL(*mockClient, isConnected(_))
        .WillRepeatedly(Invoke([connectionStatus, &connectionStatusMutex](string uri)
        {
            lock_guard<mutex> lock(connectionStatusMutex);
            bool status = connectionStatus->at(uri);
            if (status == false)
            {
                connectionStatus->at(uri) = true;
            }
            return status;
        }));

    auto nostrService = make_unique<nostr::NostrService>(
        testAppender,
        mockClient,
        fakeSigner,
        allTestRelays);
    nostrService->openRelayConnections();

    EXPECT_CALL(*mockClient, closeConnection(testRelays[0])).Times(1);

    nostrService->closeRelayConnections(testRelays);

    auto activeRelays = nostrService->activeRelays();
    ASSERT_EQ(activeRelays.size(), defaultTestRelays.size());
    for (auto relay : activeRelays)
    {
        bool isDefaultRelay = find(defaultTestRelays.begin(), defaultTestRelays.end(), relay)
            != defaultTestRelays.end();
        bool isTestRelay = find(testRelays.begin(), testRelays.end(), relay)
            != testRelays.end();
        ASSERT_TRUE((isDefaultRelay || isTestRelay) && !(isDefaultRelay && isTestRelay)); // XOR
    }
};

TEST_F(NostrServiceTest, PublishEvent_CorrectlyIndicates_AllSuccesses)
{
    mutex connectionStatusMutex;
    auto connectionStatus = make_shared<unordered_map<string, bool>>();
    connectionStatus->insert({ defaultTestRelays[0], false });
    connectionStatus->insert({ defaultTestRelays[1], false });

    EXPECT_CALL(*mockClient, isConnected(_))
        .WillRepeatedly(Invoke([connectionStatus, &connectionStatusMutex](string uri)
        {
            lock_guard<mutex> lock(connectionStatusMutex);
            bool status = connectionStatus->at(uri);
            if (status == false)
            {
                connectionStatus->at(uri) = true;
            }
            return status;
        }));

    auto nostrService = make_unique<nostr::NostrService>(
        testAppender,
        mockClient,
        fakeSigner,
        defaultTestRelays);
    nostrService->openRelayConnections();

    EXPECT_CALL(*mockClient, send(_, _, _))
        .Times(2)
        .WillRepeatedly(Invoke([](string message, string uri, function<void(const string&)> messageHandler)
        {
            json messageArr = json::parse(message);
            auto event = nostr::Event::fromString(messageArr[1]);

            json jarr = json::array({ "OK", event.id, true, "Event accepted" });
            messageHandler(jarr.dump());

            return make_tuple(uri, true);
        }));
    
    auto testEvent = make_shared<nostr::Event>(getTextNoteTestEvent());
    auto [successes, failures] = nostrService->publishEvent(testEvent);

    ASSERT_EQ(successes.size(), defaultTestRelays.size());
    for (auto relay : successes)
    {
        ASSERT_NE(find(defaultTestRelays.begin(), defaultTestRelays.end(), relay), defaultTestRelays.end());
    }

    ASSERT_EQ(failures.size(), 0);
};

TEST_F(NostrServiceTest, PublishEvent_CorrectlyIndicates_AllFailures)
{
    mutex connectionStatusMutex;
    auto connectionStatus = make_shared<unordered_map<string, bool>>();
    connectionStatus->insert({ defaultTestRelays[0], false });
    connectionStatus->insert({ defaultTestRelays[1], false });

    EXPECT_CALL(*mockClient, isConnected(_))
        .WillRepeatedly(Invoke([connectionStatus, &connectionStatusMutex](string uri)
        {
            lock_guard<mutex> lock(connectionStatusMutex);
            bool status = connectionStatus->at(uri);
            if (status == false)
            {
                connectionStatus->at(uri) = true;
            }
            return status;
        }));

    auto nostrService = make_unique<nostr::NostrService>(
        testAppender,
        mockClient,
        fakeSigner,
        defaultTestRelays);
    nostrService->openRelayConnections();

    // Simulate a case where the message failed to send to all relays.
    EXPECT_CALL(*mockClient, send(_, _, _))
        .Times(2)
        .WillRepeatedly(Invoke([](string message, string uri, function<void(const string&)> messageHandler)
        {
            return make_tuple(uri, false);
        }));
    
    auto testEvent = make_shared<nostr::Event>(getTextNoteTestEvent());
    auto [successes, failures] = nostrService->publishEvent(testEvent);

    ASSERT_EQ(successes.size(), 0);

    ASSERT_EQ(failures.size(), defaultTestRelays.size());
    for (auto relay : failures)
    {
        ASSERT_NE(find(defaultTestRelays.begin(), defaultTestRelays.end(), relay), defaultTestRelays.end());
    }
};

TEST_F(NostrServiceTest, PublishEvent_CorrectlyIndicates_MixedSuccessesAndFailures)
{
    mutex connectionStatusMutex;
    auto connectionStatus = make_shared<unordered_map<string, bool>>();
    connectionStatus->insert({ defaultTestRelays[0], false });
    connectionStatus->insert({ defaultTestRelays[1], false });

    EXPECT_CALL(*mockClient, isConnected(_))
        .WillRepeatedly(Invoke([connectionStatus, &connectionStatusMutex](string uri)
        {
            lock_guard<mutex> lock(connectionStatusMutex);
            bool status = connectionStatus->at(uri);
            if (status == false)
            {
                connectionStatus->at(uri) = true;
            }
            return status;
        }));

    auto nostrService = make_unique<nostr::NostrService>(
        testAppender,
        mockClient,
        fakeSigner,
        defaultTestRelays);
    nostrService->openRelayConnections();

    // Simulate a scenario where the message fails to send to one relay, but sends successfully to
    // the other, and the relay accepts it.
    EXPECT_CALL(*mockClient, send(_, defaultTestRelays[0], _))
        .Times(1)
        .WillRepeatedly(Invoke([](string message, string uri, function<void(const string&)> messageHandler)
        {
            return make_tuple(uri, false);
        }));
    EXPECT_CALL(*mockClient, send(_, defaultTestRelays[1], _))
        .Times(1)
        .WillRepeatedly(Invoke([](string message, string uri, function<void(const string&)> messageHandler)
        {
            json messageArr = json::parse(message);
            auto event = nostr::Event::fromString(messageArr[1]);

            json jarr = json::array({ "OK", event.id, true, "Event accepted" });
            messageHandler(jarr.dump());

            return make_tuple(uri, true);
        }));
    
    auto testEvent = make_shared<nostr::Event>(getTextNoteTestEvent());
    auto [successes, failures] = nostrService->publishEvent(testEvent);

    ASSERT_EQ(successes.size(), 1);
    ASSERT_EQ(successes[0], defaultTestRelays[1]);

    ASSERT_EQ(failures.size(), 1);
    ASSERT_EQ(failures[0], defaultTestRelays[0]);
};

TEST_F(NostrServiceTest, PublishEvent_CorrectlyIndicates_RejectedEvent)
{
    mutex connectionStatusMutex;
    auto connectionStatus = make_shared<unordered_map<string, bool>>();
    connectionStatus->insert({ defaultTestRelays[0], false });
    connectionStatus->insert({ defaultTestRelays[1], false });

    EXPECT_CALL(*mockClient, isConnected(_))
        .WillRepeatedly(Invoke([connectionStatus, &connectionStatusMutex](string uri)
        {
            lock_guard<mutex> lock(connectionStatusMutex);
            bool status = connectionStatus->at(uri);
            if (status == false)
            {
                connectionStatus->at(uri) = true;
            }
            return status;
        }));

    auto nostrService = make_unique<nostr::NostrService>(
        testAppender,
        mockClient,
        fakeSigner,
        defaultTestRelays);
    nostrService->openRelayConnections();

    // Simulate a scenario where the message is rejected by all target relays.
    EXPECT_CALL(*mockClient, send(_, _, _))
        .Times(2)
        .WillRepeatedly(Invoke([](string message, string uri, function<void(const string&)> messageHandler)
        {
            json messageArr = json::parse(message);
            auto event = nostr::Event::fromString(messageArr[1]);

            json jarr = json::array({ "OK", event.id, false, "Event rejected" });
            messageHandler(jarr.dump());

            return make_tuple(uri, true);
        }));
    
    auto testEvent = make_shared<nostr::Event>(getTextNoteTestEvent());
    auto [successes, failures] = nostrService->publishEvent(testEvent);

    ASSERT_EQ(failures.size(), defaultTestRelays.size());
    for (auto relay : failures)
    {
        ASSERT_NE(find(defaultTestRelays.begin(), defaultTestRelays.end(), relay), defaultTestRelays.end());
    }
};

TEST_F(NostrServiceTest, PublishEvent_CorrectlyIndicates_EventRejectedBySomeRelays)
{
    mutex connectionStatusMutex;
    auto connectionStatus = make_shared<unordered_map<string, bool>>();
    connectionStatus->insert({ defaultTestRelays[0], false });
    connectionStatus->insert({ defaultTestRelays[1], false });

    EXPECT_CALL(*mockClient, isConnected(_))
        .WillRepeatedly(Invoke([connectionStatus, &connectionStatusMutex](string uri)
        {
            lock_guard<mutex> lock(connectionStatusMutex);
            bool status = connectionStatus->at(uri);
            if (status == false)
            {
                connectionStatus->at(uri) = true;
            }
            return status;
        }));

    auto nostrService = make_unique<nostr::NostrService>(
        testAppender,
        mockClient,
        fakeSigner,
        defaultTestRelays);
    nostrService->openRelayConnections();

    // Simulate a scenario where the message fails to send to one relay, but sends successfully to
    // the other, and the relay accepts it.
    EXPECT_CALL(*mockClient, send(_, defaultTestRelays[0], _))
        .Times(1)
        .WillRepeatedly(Invoke([](string message, string uri, function<void(const string&)> messageHandler)
        {
            json messageArr = json::parse(message);
            auto event = nostr::Event::fromString(messageArr[1]);

            json jarr = json::array({ "OK", event.id, true, "Event accepted" });
            messageHandler(jarr.dump());

            return make_tuple(uri, true);
        }));
    EXPECT_CALL(*mockClient, send(_, defaultTestRelays[1], _))
        .Times(1)
        .WillRepeatedly(Invoke([](string message, string uri, function<void(const string&)> messageHandler)
        {
            json messageArr = json::parse(message);
            auto event = nostr::Event::fromString(messageArr[1]);

            json jarr = json::array({ "OK", event.id, false, "Event rejected" });
            messageHandler(jarr.dump());

            return make_tuple(uri, true);
        }));
    
    auto testEvent = make_shared<nostr::Event>(getTextNoteTestEvent());
    auto [successes, failures] = nostrService->publishEvent(testEvent);

    ASSERT_EQ(successes.size(), 1);
    ASSERT_EQ(successes[0], defaultTestRelays[0]);

    ASSERT_EQ(failures.size(), 1);
    ASSERT_EQ(failures[0], defaultTestRelays[1]);
};

// TODO: Add unit tests for queries.
TEST_F(NostrServiceTest, QueryRelays_ReturnsEvents_UpToEOSE)
{
    mutex connectionStatusMutex;
    auto connectionStatus = make_shared<unordered_map<string, bool>>();
    connectionStatus->insert({ defaultTestRelays[0], false });
    connectionStatus->insert({ defaultTestRelays[1], false });

    EXPECT_CALL(*mockClient, isConnected(_))
        .WillRepeatedly(Invoke([connectionStatus, &connectionStatusMutex](string uri)
        {
            lock_guard<mutex> lock(connectionStatusMutex);
            bool status = connectionStatus->at(uri);
            if (status == false)
            {
                connectionStatus->at(uri) = true;
            }
            return status;
        }));

    auto signer = make_unique<FakeSigner>();
    auto nostrService = make_unique<nostr::NostrService>(
        testAppender,
        mockClient,
        fakeSigner,
        defaultTestRelays);
    nostrService->openRelayConnections();

    auto testEvents = getMultipleTextNoteTestEvents();
    vector<shared_ptr<nostr::Event>> signedTestEvents;
    for (nostr::Event testEvent : testEvents)
    {
        auto signedEvent = make_shared<nostr::Event>(testEvent);
        signer->sign(signedEvent);

        auto serializedEvent = signedEvent->serialize();
        auto deserializedEvent = nostr::Event::fromString(serializedEvent);

        signedEvent = make_shared<nostr::Event>(deserializedEvent);
        signedTestEvents.push_back(signedEvent);
    }

    EXPECT_CALL(*mockClient, send(_, _, _))
        .Times(2)
        .WillRepeatedly(Invoke([&testEvents, &signer](
            string message,
            string uri,
            function<void(const string&)> messageHandler)
        {
            json messageArr = json::parse(message);
            string subscriptionId = messageArr.at(1);

            for (auto event : testEvents)
            {
                auto sendableEvent = make_shared<nostr::Event>(event);
                signer->sign(sendableEvent);
                json jarr = json::array({ "EVENT", subscriptionId, sendableEvent->serialize() });
                messageHandler(jarr.dump());
            }

            json jarr = json::array({ "EOSE", subscriptionId });
            messageHandler(jarr.dump());

            return make_tuple(uri, true);
        }));

    auto filters = make_shared<nostr::Filters>(getKind0And1TestFilters());
    auto results = nostrService->queryRelays(filters);

    // TODO: Check results size when the queryRelays method deduplicates results before returning.
    // ASSERT_EQ(results.size(), testEvents.size());

    // Check that the results contain the expected events.
    for (auto resultEvent : results)
    {
        ASSERT_NE(
            find_if(
                signedTestEvents.begin(),
                signedTestEvents.end(),
                [&resultEvent](shared_ptr<nostr::Event> testEvent)
                {
                    return *testEvent == *resultEvent;
                }),
            signedTestEvents.end());
    }
};

// TODO: Add unit tests for closing subscriptions.
} // namespace nostr_test
