#include <sstream>
#include <stdexcept>

#include "data/data.hpp"
#include "cryptography/nostr_bech32.hpp"

using namespace nlohmann;
using namespace nostr::data;
using namespace nostr::encoding;
using namespace std;

string Event::serialize()
{
    try
    {
        this->validate();
    }
    catch (const invalid_argument& e)
    {
        throw e;
    }

    // Generate the event ID from the serialized data.
    this->generateId();

    json j = *this;
    return j.dump();
};

Event Event::fromString(string jstr)
{
    json j = json::parse(jstr);
    Event event;

    try
    {
        event = Event::fromJson(j);
    }
    catch (const invalid_argument& e)
    {
        throw e;
    }

    return event;
};

Event Event::fromJson(json j)
{
    Event event = j.get<Event>();
    return event;
};

void Event::validate()
{
    bool hasPubkey = this->pubkey.length() > 0;
    if (!hasPubkey)
    {
        throw invalid_argument("Event::validate: The pubkey of the event author is required.");
    }

    bool hasCreatedAt = this->createdAt > 0;
    if (!hasCreatedAt)
    {
        this->createdAt = time(nullptr);
    }

    bool hasKind = this->kind >= 0 && this->kind < 40000;
    if (!hasKind)
    {
        throw std::invalid_argument("Event::validate: A valid event kind is required.");
    }
};

void Event::generateId()
{
    // Create a JSON array of values used to generate the event ID.
    json arr = { 0, this->pubkey, this->createdAt, this->kind, this->tags, this->content };
    string serializedData = arr.dump();

    unsigned char hash[SHA256_DIGEST_LENGTH];
    EVP_Digest(serializedData.c_str(), serializedData.length(), hash, NULL, EVP_sha256(), NULL);

    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }

    this->id = ss.str();
};

bool Event::operator==(const Event& other) const
{
    if (this->id.empty())
    {
        throw invalid_argument("Event::operator==: Cannot check equality, the left-side argument is undefined.");
    }
    if (other.id.empty())
    {
        throw invalid_argument("Event::operator==: Cannot check equality, the right-side argument is undefined.");
    }

    return this->id == other.id;
};

void adl_serializer<Event>::to_json(json& j, const Event& event)
{
    // Serialize the event to a JSON object.
    j = {
        { "id", event.id },
        { "pubkey", event.pubkey },
        { "created_at", event.createdAt },
        { "kind", event.kind },
        { "tags", event.tags },
        { "content", event.content },
        { "sig", event.sig },
    };
}

void adl_serializer<Event>::from_json(const json& j, Event& event)
{
    // TODO: Set up custom exception types for improved exception handling.
    try
    {
        event.id = j.at("id");
        event.pubkey = j.at("pubkey");
        event.createdAt = j.at("created_at");
        event.kind = j.at("kind");
        event.tags = j.at("tags");
        event.content = j.at("content");
        event.sig = j.at("sig");

        // TODO: Validate the event against its signature.
    }
    catch (const json::type_error& te)
    {
        throw te;
    }
    catch (const json::out_of_range& oor)
    {
        throw oor;
    }
}

// wrapper class implementation

NostrEvent::NostrEvent()
{
    this->data = std::make_shared<Event>();
}

NostrEvent::NostrEvent(string jsonString)
{
    this->data->fromString(jsonString);
}
NostrEvent::NostrEvent(json j)
{
    this->data->fromJson(j);
}
NostrEvent::NostrEvent(shared_ptr<Event> e)
{
    this->data = e;
}

bool NostrEvent::operator==(const NostrEvent& other) const
{
    return this->data == other.data;
}

std::string NostrEvent::toNote()
{
    NostrBech32 encoder = NostrBech32();

    NostrBech32Encoding input;
    string output;
    input.type = NOSTR_BECH32_NOTE;
    input.data.note.event_id = this->data->id;

    if(!encoder.encodeNostrBech32(input, output))
        std::cerr << "'encoder.encodeNostrBech32' failed\n";

    return output;
}

std::string NostrEvent::toNevent()
{
    NostrBech32 encoder = NostrBech32();

    NostrBech32Encoding input;
    string output;
    input.type = NOSTR_BECH32_NEVENT;
    input.data.nevent.event_id = this->data->id;

    input.data.nevent.pubkey = this->data->pubkey;
    input.data.nevent.relays = this->relays;

    if (this->data->kind == 1)
    {
        input.data.nevent.has_kind = false;
    }
    else
    {
        input.data.nevent.has_kind = true;
        input.data.nevent.kind = this->data->kind;
    }

    if(!encoder.encodeNostrBech32(input, output))
        std::cerr << "'encoder.encodeNostrBech32' failed\n";

    return output;
}

std::string NostrEvent::toNaddr()
{
    NostrBech32 encoder = NostrBech32();

    NostrBech32Encoding input;
    string output;
    input.type = NOSTR_BECH32_NADDR;

    // fetch 'd' tag from tags in the base event
    input.data.naddr.tag = "";
    for (auto tag : this->data->tags)
    {
        if (tag[0] == "d")
        {
            input.data.naddr.tag = tag[1];
            break;
        }
    }
    if (input.data.naddr.tag.empty())
    {
        std::cerr << "Could not find mandatory 'd' tag. Returning nullptr\n";
        return nullptr;
    }

    input.data.naddr.pubkey = this->data->pubkey;
    if (input.data.naddr.pubkey.empty())
    {
        std::cerr << "Could not find mandatory pubkey. Returning nullptr\n";
        return nullptr;
    }

    input.data.naddr.relays = this->relays;
    input.data.naddr.kind = this->data->kind;

    if(!encoder.encodeNostrBech32(input, output))
        std::cerr << "'encoder.encodeNostrBech32' failed\n";

    return output;
}


void NostrEvent::fromNote(std::string &encoding)
{
    NostrBech32 parser = NostrBech32();
    NostrBech32Encoding parsedData;

    if(!parser.parseNostrBech32(encoding, parsedData))
        std::cerr << "failed to decode Note encoding\n";

    this->data->id = parsedData.data.note.event_id;
}

void NostrEvent::fromNevent(std::string &encoding)
{
    NostrBech32 parser = NostrBech32();
    NostrBech32Encoding parsedData;

    if(!parser.parseNostrBech32(encoding, parsedData))
        std::cerr << "failed to decode nevent encoding\n";

    this->data->id = parsedData.data.nevent.event_id;
    this->data->pubkey = parsedData.data.nevent.pubkey;
    this->relays = parsedData.data.nevent.relays;

    if(parsedData.data.nevent.has_kind)
        this->data->kind = parsedData.data.nevent.kind;
}

void NostrEvent::fromNaddr(std::string &encoding)
{
    NostrBech32 parser = NostrBech32();
    NostrBech32Encoding parsedData;

    if(!parser.parseNostrBech32(encoding, parsedData))
        std::cerr << "failed to decode nevent encoding\n";

    this->data->tags.push_back({"d", parsedData.data.naddr.tag});
    this->data->pubkey = parsedData.data.naddr.pubkey;
    this->relays = parsedData.data.naddr.relays;
    this->data->kind = parsedData.data.naddr.kind;
}
