#include <sstream>
#include <stdexcept>

#include "data/data.hpp"
#include "cryptography/nostr_bech32.h"

using namespace nlohmann;
using namespace nostr::data;
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

std::string Event::toBech32Note()
{
    char *note = (char *)malloc(KEY_LENGTH*2 + 1);
    int ret = encode_nostr_bech32_note((char *)this->id.c_str(), note);
    if (!ret)
    {
        throw invalid_argument(
            "Event::toBech32Note: encode_nostr_bech32_note function failed to return true.");
    }
    std::string str_note = std::string(note);
    free(note);
    return str_note;
}

std::string Event::toBech32Naddr()
{
    std::string tag = "";

    // look for 'd' tag, if found save it.
    for (auto t: this->tags)
    {
        if (t[0] == "d")
        {
            tag = t[1];
            break;
        }
    }

    uint32_t kind = (uint32_t)this->kind;
    char *pubkey = (char *)this->pubkey.c_str();

    // add up the data lengths accouting for TLV to know
    // the size of the naddr encoding output;
    // 2 bytes for type and length and then length bytes for each entry
    int naddr_len = 2 + strlen(pubkey) + 2 + tag.length() + 2 + 4;

    char **relays;
    *relays = (char *)malloc(this->relays.size());

    // convert relays vector to char**
    for (int i = 0; i < this->relays.size(); i++) {
        naddr_len += 2 + this->relays[i].length();
        relays[i] = (char *)malloc(this->relays[i].length());
        relays[i] = (char *)this->relays[i].c_str();
    }

    char *naddr = (char *)malloc(naddr_len);

    int ret = encode_nostr_bech32_naddr((char *)tag.c_str(), &kind, pubkey, naddr, this->relays.size(), relays);
    if (!ret)
    {
        throw invalid_argument(
            "Event::toBech32Note: encode_nostr_bech32_note function failed to return true.");
    }
    std::string str_naddr = std::string(naddr);
    free(naddr);
    return str_naddr;
}

std::string Event::toBech32Nevent()
{
    int ret;

    // add up the data lengths accouting for TLV to know
    // the size of the naddr encoding output;
    // 2 bytes for type and length and then length bytes for each entry
    int nevent_len = 2 + this->pubkey.length() + 2 + this->id.length() + 2 + 4;

    char **relays;
    *relays = (char *)malloc(this->relays.size());

    // convert relays vector to char**
    for (int i = 0; i < this->relays.size(); i++)
    {
        nevent_len += 2 + this->relays[i].length();
        relays[i] = (char *)malloc(this->relays[i].length());
        relays[i] = (char *)this->relays[i].c_str();
    }

    char *nevent = (char *)malloc(nevent_len);

    if (this->kind > 1) {
        ret = encode_nostr_bech32_nevent(
            (char *)this->id.c_str(), nevent, (uint32_t *)&this->kind,
            (char *)this->pubkey.c_str(), this->relays.size(), relays);

        if (!ret)
        {
            throw invalid_argument(
                "Event::toBech32Nevent: encode_nostr_bech32_nevent function failed to return true.");
        }
    }
    else
    {
        ret = encode_nostr_bech32_nevent(
            (char *)this->id.c_str(), nevent, nullptr,
            (char *)this->pubkey.c_str(), this->relays.size(), relays);

        if (!ret)
        {
            throw invalid_argument(
                "Event::toBech32Nevent: encode_nostr_bech32_nevent without kind function failed to return true.");
        }
    }

    std::string str_nevent = std::string(nevent);
    free(nevent);
    return str_nevent;

}

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
