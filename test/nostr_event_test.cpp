#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "data/data.hpp"
#include "cryptography/nostr_bech32.hpp"

using namespace nostr::data;
using namespace nostr::encoding;
using namespace std;
using namespace ::testing;

shared_ptr<Event> testEvent()
{
    auto event = make_shared<Event>();

    event->pubkey = "13tn5ccv2guflxgffq4aj0hw5x39pz70zcdrfd6vym887gry38zys28dask";
    event->createdAt = 1627846261;
    event->kind = 1;
    event->tags = {
        { "e", "5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36", "wss://gitcitadel.nostr1.com" },
        { "p", "f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca" },
        { "a", "30023:f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca:abcd", "wss://gitcitadel.nostr1.com" }
    };
    event->content = "Hello, World!";

    return event;
}

shared_ptr<Event> testBech32()
{
    auto event = make_shared<Event>();

    event->pubkey = "dc4cd086cd7ce5b1832adf4fdd1211289880d2c7e295bcb0e684c01acee77c06";
    event->id = "bf39598ec3b67e208e26f54e3744e5adf5221dbf1c480f9b673f21dddac8c7ef";
    event->createdAt = 1741372469;
    event->kind = 30023;
    event->tags = {
        { "d", "mfayffebPrMI520ftzIlE" }
    };
    event->content = "Hello, World!";

    return event;
}

shared_ptr<NostrEvent> makeNostrEvent()
{
    auto base_event = testBech32();
    return std::make_shared<NostrEvent>(NostrEvent(base_event));
}

TEST(NostrEventTest, Equivalent_Events_Have_Same_ID)
{
    // Create two events with the same values
    auto event1 = testEvent();
    auto event2 = testEvent();

    // Serialize both events
    string serializedEvent1 = event1->serialize();
    string serializedEvent2 = event2->serialize();

    auto event1WithId = Event::fromString(serializedEvent1);
    auto event2WithId = Event::fromString(serializedEvent2);

    // Hash both serialized events using sha256
    string id1 = event1WithId.id;
    string id2 = event2WithId.id;

    // Verify that both hashes are equal
    ASSERT_EQ(id1, id2);
}

TEST(NostrEventTest, Special_Characters_Are_Escaped_When_Serialized)
{
    // Test backspace (0x08)
    auto backspaceEvent = testEvent();
    backspaceEvent->content = string("Hello") + char(0x08) + "World";
    string serializedBackspace = backspaceEvent->serialize();
    EXPECT_THAT(serializedBackspace, HasSubstr("\\b"));

    // Test tab (0x09)
    auto tabEvent = testEvent();
    tabEvent->content = string("Hello") + char(0x09) + "World";
    string serializedTab = tabEvent->serialize();
    EXPECT_THAT(serializedTab, HasSubstr("\\t"));

    // Test newline (0x0A)
    auto newlineEvent = testEvent();
    newlineEvent->content = string("Hello") + char(0x0A) + "World";
    string serializedNewline = newlineEvent->serialize();
    EXPECT_THAT(serializedNewline, HasSubstr("\\n"));

    // Test form feed (0x0C)
    auto formFeedEvent = testEvent();
    formFeedEvent->content = string("Hello") + char(0x0C) + "World";
    string serializedFormFeed = formFeedEvent->serialize();
    EXPECT_THAT(serializedFormFeed, HasSubstr("\\f"));

    // Test carriage return (0x0D)
    auto crEvent = testEvent();
    crEvent->content = string("Hello") + char(0x0D) + "World";
    string serializedCr = crEvent->serialize();
    EXPECT_THAT(serializedCr, HasSubstr("\\r"));

    // Test double quote (0x22)
    auto quoteEvent = testEvent();
    quoteEvent->content = string("Hello") + char(0x22) + "World";
    string serializedQuote = quoteEvent->serialize();
    EXPECT_THAT(serializedQuote, HasSubstr("\\\""));

    // Test backslash (0x5C)
    auto backslashEvent = testEvent();
    backslashEvent->content = string("Hello") + char(0x5C) + "World";
    string serializedBackslash = backslashEvent->serialize();
    EXPECT_THAT(serializedBackslash, HasSubstr("\\\\"));
}

TEST(NostrEventTest, Bech32_On_Wrapper_Class)
{
    auto nostr_event = makeNostrEvent();
    std::string naddr = nostr_event->toNaddr();
    std::string note = nostr_event->toNote();
    std::string nevent = nostr_event->toNevent();

    ASSERT_FALSE(naddr.empty());
    ASSERT_FALSE(note.empty());
    ASSERT_FALSE(nevent.empty());

    NostrEvent decoded = NostrEvent();
    decoded.fromNaddr(naddr);
    std::string reencoded_naddr = decoded.toNaddr();

    ASSERT_EQ(reencoded_naddr, naddr);

    decoded = NostrEvent();
    decoded.fromNote(note);
    std::string reencoded_note = decoded.toNote();
    ASSERT_EQ(reencoded_note, note);

    decoded = NostrEvent();
    decoded.fromNevent(nevent);
    std::string reencoded_nevent = decoded.toNevent();
    ASSERT_EQ(reencoded_nevent, nevent);
}