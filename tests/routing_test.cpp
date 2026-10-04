#include "check.hpp"
#include <string_view>

#include "norr/routing.hpp"

namespace {
norr::Address address_of(std::string_view text) {
  const auto parsed = norr::parse_address(text);
  NORR_CHECK(parsed.has_value());
  return *parsed;
}

norr::Prefix prefix_of(std::string_view text) {
  const auto parsed = norr::parse_prefix(text);
  NORR_CHECK(parsed.has_value());
  return *parsed;
}

void add(norr::RoutingTable& table, norr::PeerId peer, std::string_view prefix) {
  const auto added = table.add(peer, prefix_of(prefix));
  NORR_CHECK(added.has_value());
}

norr::IpPacketView packet(std::string_view source, std::string_view destination,
                          std::uint8_t hop_limit = 64) {
  const auto from = address_of(source);
  return norr::IpPacketView{
      .family = from.family(),
      .source = from,
      .destination = address_of(destination),
      .protocol = 6,
      .hop_limit = hop_limit,
      .header_length = norr::kIpv4HeaderSize,
      .total_length = norr::kIpv4HeaderSize,
  };
}
}

int main() {
  {
    norr::RoutingTable table;
    add(table, 1, "10.0.0.0/8");
    add(table, 2, "10.1.0.0/16");
    add(table, 3, "10.1.2.0/24");

    NORR_CHECK(table.lookup(address_of("10.9.9.9")) == 1);
    NORR_CHECK(table.lookup(address_of("10.1.9.9")) == 2);
    NORR_CHECK(table.lookup(address_of("10.1.2.9")) == 3);
    NORR_CHECK(table.lookup(address_of("11.0.0.1")) == norr::kNoPeer);
  }

  {
    norr::RoutingTable table;
    add(table, 3, "10.1.2.0/24");
    add(table, 1, "10.0.0.0/8");
    add(table, 2, "10.1.0.0/16");

    NORR_CHECK(table.lookup(address_of("10.1.2.9")) == 3);
    NORR_CHECK(table.lookup(address_of("10.1.9.9")) == 2);
    NORR_CHECK(table.lookup(address_of("10.9.9.9")) == 1);
  }

  {
    norr::RoutingTable table;
    add(table, 1, "0.0.0.0/0");
    add(table, 2, "10.0.0.0/8");
    NORR_CHECK(table.lookup(address_of("10.0.0.1")) == 2);
    NORR_CHECK(table.lookup(address_of("8.8.8.8")) == 1);
  }

  {
    norr::RoutingTable table;
    add(table, 1, "10.0.0.0/8");
    const auto conflict = table.add(2, prefix_of("10.0.0.0/8"));
    NORR_CHECK(!conflict.has_value() && conflict.error() == norr::RoutingError::duplicate_prefix);

    const auto repeat = table.add(1, prefix_of("10.0.0.0/8"));
    NORR_CHECK(repeat.has_value());
    NORR_CHECK(table.size() == 1);

    const auto same = table.add(2, prefix_of("10.1.2.3/8"));
    NORR_CHECK(!same.has_value() && same.error() == norr::RoutingError::duplicate_prefix);
  }

  {
    norr::RoutingTable table;
    const auto invalid = table.add(norr::kNoPeer, prefix_of("10.0.0.0/8"));
    NORR_CHECK(!invalid.has_value() && invalid.error() == norr::RoutingError::invalid_peer);
  }

  {
    norr::RoutingTable table;
    add(table, 1, "10.0.0.0/8");
    add(table, 2, "2001:db8::/32");
    NORR_CHECK(table.lookup(address_of("10.0.0.1")) == 1);
    NORR_CHECK(table.lookup(address_of("2001:db8::1")) == 2);
    NORR_CHECK(table.lookup(address_of("2001:dead::1")) == norr::kNoPeer);
  }

  {
    norr::RoutingTable table;
    add(table, 1, "10.1.0.0/16");
    add(table, 2, "10.2.0.0/16");

    NORR_CHECK(table.is_authorized(1, address_of("10.1.0.5")));
    NORR_CHECK(!table.is_authorized(1, address_of("10.2.0.5")));
    NORR_CHECK(!table.is_authorized(2, address_of("10.1.0.5")));
    NORR_CHECK(!table.is_authorized(norr::kNoPeer, address_of("10.1.0.5")));
  }

  {
    norr::RoutingTable table;
    add(table, 1, "10.1.0.0/16");
    add(table, 2, "10.2.0.0/16");

    const auto allowed = table.classify(packet("10.1.0.5", "10.2.0.7"), 1);
    NORR_CHECK(allowed.decision == norr::ForwardDecision::forward);
    NORR_CHECK(allowed.peer == 2);
    NORR_CHECK(static_cast<bool>(allowed));

    const auto spoofed = table.classify(packet("10.2.0.5", "10.1.0.7"), 1);
    NORR_CHECK(spoofed.decision == norr::ForwardDecision::source_not_authorized);
    NORR_CHECK(spoofed.peer == norr::kNoPeer);
    NORR_CHECK(!static_cast<bool>(spoofed));

    const auto local = table.classify(packet("192.0.2.1", "10.1.0.7"), norr::kNoPeer);
    NORR_CHECK(local.decision == norr::ForwardDecision::forward);
    NORR_CHECK(local.peer == 1);

    const auto to_internet = table.classify(packet("10.1.0.5", "203.0.113.1"), 1);
    NORR_CHECK(to_internet.decision == norr::ForwardDecision::deliver_local);
    NORR_CHECK(static_cast<bool>(to_internet));

    const auto unrouted = table.classify(packet("192.0.2.1", "203.0.113.1"), norr::kNoPeer);
    NORR_CHECK(unrouted.decision == norr::ForwardDecision::no_route);

    NORR_CHECK(!norr::parse_prefix("10.0.0.1/256").has_value());
    NORR_CHECK(!norr::parse_prefix("10.0.0.1/33").has_value());
    NORR_CHECK(!norr::parse_prefix("fd00::/129").has_value());
    NORR_CHECK(norr::parse_prefix("fd00::/128").has_value());

    const auto loop = table.classify(packet("10.1.0.5", "10.1.0.9"), 1);
    NORR_CHECK(loop.decision == norr::ForwardDecision::routing_loop);

    NORR_CHECK(table.classify(packet("10.1.0.5", "224.0.0.1"), 1).decision ==
           norr::ForwardDecision::multicast_denied);
    NORR_CHECK(table.classify(packet("10.1.0.5", "0.0.0.0"), 1).decision ==
           norr::ForwardDecision::unspecified_address);
    NORR_CHECK(table.classify(packet("0.0.0.0", "10.2.0.7"), 1).decision ==
           norr::ForwardDecision::unspecified_address);
    NORR_CHECK(table.classify(packet("10.1.0.5", "127.0.0.1"), 1).decision ==
           norr::ForwardDecision::loopback_address);

    NORR_CHECK(table.classify(packet("10.1.0.5", "10.2.0.7", 1), 1).decision ==
           norr::ForwardDecision::hop_limit_exceeded);
    NORR_CHECK(table.classify(packet("10.1.0.5", "10.2.0.7", 0), 1).decision ==
           norr::ForwardDecision::hop_limit_exceeded);
    NORR_CHECK(table.classify(packet("10.1.0.5", "10.2.0.7", 2), 1).decision ==
           norr::ForwardDecision::forward);

    NORR_CHECK(table.classify(packet("10.9.9.9", "224.0.0.1"), 1).decision ==
           norr::ForwardDecision::multicast_denied);
  }

  {
    norr::RoutingTable table;
    add(table, 1, "10.99.0.2/32");
    NORR_CHECK(table.add_local(prefix_of("10.99.0.1/32")).has_value());

    NORR_CHECK(table.is_local(address_of("10.99.0.1")));
    NORR_CHECK(!table.is_local(address_of("10.99.0.2")));

    const auto inbound = table.classify(packet("10.99.0.2", "10.99.0.1"), 1);
    NORR_CHECK(inbound.decision == norr::ForwardDecision::deliver_local);
    NORR_CHECK(static_cast<bool>(inbound));
    NORR_CHECK(inbound.peer == norr::kNoPeer);

    const auto onward = table.classify(packet("10.99.0.1", "10.99.0.2"), norr::kNoPeer);
    NORR_CHECK(onward.decision == norr::ForwardDecision::forward);
    NORR_CHECK(onward.peer == 1);

    const auto spoofed = table.classify(packet("10.88.0.5", "10.99.0.1"), 1);
    NORR_CHECK(spoofed.decision == norr::ForwardDecision::source_not_authorized);

    NORR_CHECK(table.add_local(prefix_of("10.99.0.1/32")).has_value());
    NORR_CHECK(table.is_local(address_of("10.99.0.1")));
  }

  {
    norr::RoutingTable table;
    add(table, 1, "10.50.0.0/16");
    NORR_CHECK(table.add_local(prefix_of("10.50.0.7/32")).has_value());

    NORR_CHECK(table.classify(packet("192.168.1.1", "10.50.0.7"), norr::kNoPeer).decision ==
               norr::ForwardDecision::deliver_local);
    NORR_CHECK(table.classify(packet("192.168.1.1", "10.50.0.8"), norr::kNoPeer).decision ==
               norr::ForwardDecision::forward);
  }

  {
    norr::RoutingTable table;
    for (std::size_t index = 0; index < norr::RoutingTable::kMaximumPrefixes; ++index) {
      const auto octet_high = static_cast<std::uint8_t>(index / 256U);
      const auto octet_low = static_cast<std::uint8_t>(index % 256U);
      std::array<std::byte, 4> octets{std::byte{10}, static_cast<std::byte>(octet_high),
                                      static_cast<std::byte>(octet_low), std::byte{0}};
      const auto prefix =
          norr::Prefix::create(norr::Address::from_bytes(norr::AddressFamily::ipv4, octets), 24);
      NORR_CHECK(prefix.has_value());
      const auto added = table.add(1, *prefix);
      NORR_CHECK(added.has_value());
    }
    NORR_CHECK(table.size() == norr::RoutingTable::kMaximumPrefixes);

    const auto overflow = table.add(1, prefix_of("192.0.2.0/24"));
    NORR_CHECK(!overflow.has_value() && overflow.error() == norr::RoutingError::too_many_prefixes);
  }
}
