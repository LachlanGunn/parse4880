#include <cstdint>
#include <cstdio>

#include <string>
#include <memory>
#include <stdexcept>

#ifdef INCLUDE_TESTS
#include <gtest/gtest.h>
#endif

#include "parser_types.h"
#include "parser.h"
#include "exceptions.h"

namespace parse4880 {

namespace {

enum PacketLengthType {
  kNormalPacket = 0,
  kPartialPacket,
  kIndeterminatePacket
};

struct find_length_result {
  uint64_t         length;
  int              length_field_length;
  PacketLengthType length_type;
};

/**
 * Find the length of a new-style packet chunk.
 *
 * A new-style packet encodes its length type in the first octet rather
 * than in the header.  We check the first octet to see what kind of
 * length record we have---one-octet, two-octet, five-octet, or a partial
 * record---then decode and return it.
 *
 * @todo Deal with partial-length records.
 */
struct find_length_result find_length_new(const ustring& string_data,
                                          size_t field_position,
                                          bool allow_partial,
                                          size_t packet_start_position) {
  struct find_length_result result;

  // Now we have to get the length.
  if (string_data.length() < field_position + 1) {
    throw packet_header_length_error(packet_start_position);
  }
  result.length = (unsigned char)string_data[field_position];
  result.length_field_length = 1;

  // If the packet length is less than 192, then it is equal to the first
  // octet and we are done.
  if (result.length < 192) {
    // Do nothing.
  }
  // If the first octet is from 192 to 223, then we have a two-octet length.
  // But if we don't allow partial packets (as in signature subpackets), then
  // this can go up to 254.
  else if (result.length > 191 &&
           ( ( allow_partial && result.length < 224) ||
             (!allow_partial && result.length < 255)) ) {
    // Check that the buffer is large enough
    if (string_data.length() <= field_position + 1) {
      throw packet_header_length_error(packet_start_position);
    }
    // The two-octet length is defined in RFC4880§4.2.2.2
    result.length =
        ( (string_data[field_position    ] - 192 ) << 8)
        +  string_data[field_position + 1]
        + 192;
    result.length_field_length = 2;
  }
  // If the first octet is from 224 to 254, then we have a partial length
  // header.
  else if (allow_partial && (result.length >= 224 && result.length < 255)) {
    // TODO: Deal with these.
    throw unsupported_feature_error(field_position,
                                    "partial body lengths");
  }
  // If the first octet is 255, then we have a five-octet length.
  else {
    // Check that the buffer is large enough
    if (string_data.length() < field_position + 5) {
      throw packet_header_length_error(packet_start_position);
    }
    // The five-octet length is defined in RFC4880§4.2.2.3
    result.length =
          ((uint64_t)string_data[field_position + 1] << 24)
        + ((uint64_t)string_data[field_position + 2] << 16)
        + ((uint64_t)string_data[field_position + 3] << 8)
        +  (uint64_t)string_data[field_position + 4];
    result.length_field_length = 5;
  }
  
  return result;
}

#ifdef INCLUDE_TESTS

TEST(PacketLengths, NewFormat) {
  struct find_length_result length;
  length = find_length_new(ustring((uint8_t*)"\x64",1),0,true,0);
  ASSERT_EQ(length.length, 100);

  length = find_length_new(ustring((uint8_t*)"\xC5\xFB",2),0,true,0);
  ASSERT_EQ(length.length, 1723);

  length = find_length_new(ustring((uint8_t*)"\xFF\x00\x01\x86\xA0",5),0,true,0);
  ASSERT_EQ(length.length, 100000);
}

#endif  // INCLUDE_TESTS


/**
 * Find the length of a old-style packet chunk.
 *
 * An old-style packet encodes its length type in the header
 * rather than in the first octet.  The two lower-order bits of
 * the header contain a value N; the header is followed by a
 * length field of 2^N octets.
 *
 * The exception to this is where N=3.  Then, the packet
 * continues until the end of of the data.
 */
struct find_length_result find_length_old(const ustring& data,
                                          size_t field_position,
                                          int length_type,
                                          size_t packet_start_position) {
  struct find_length_result result;

  if (length_type == 3) {
    result.length = data.length() - field_position;
    result.length_field_length = 0;
  }
  else {
    result.length_field_length = 1 << length_type ;
    // Check that the buffer is large enough
    if (data.length() <= field_position + result.length_field_length) {
      throw packet_header_length_error(packet_start_position);
    }

    result.length = ReadInteger(data.substr(field_position,
                                            result.length_field_length));
  }
  
  return result;
}

} // namespace

uint64_t ReadInteger(ustring encoded_integer) {
  uint64_t parsed_integer = 0;
  for (size_t i = 0; i < encoded_integer.length(); i++) {
    parsed_integer <<= 8;
    parsed_integer += encoded_integer.at(i);
  }
  return parsed_integer;
}

ustring WriteInteger(uint64_t value, uint8_t length) {
  ustring result((size_t)length, '\x00');
  for (int i = length-1; i >= 0; i--) {
    result[i] = (uint8_t)(value & 0xFF);
    value >>= 8;
  }
  return result;
}

#ifdef INCLUDE_TESTS

TEST(ScalarNumbers, RoundTrip) {
  for (int length = 1; length < 3; length++) {
    for (uint64_t i = 0; i < (uint64_t{1}<<(length*8))-1; i++) {
      ASSERT_EQ(i, parse4880::ReadInteger(parse4880::WriteInteger(i, length)));
    }
  }
}

#endif

void parse(ustring data,
           std::function<bool(std::shared_ptr<PGPPacket>)> callback) {
  size_t packet_start_position = 0;
  while(true) {
    // Check that we have enough data left.  We need at one byte for the
    // header and at least one byte for the length field.
    if (data.length() < packet_start_position + 1) {
      break;
    }

    if (data.length() < packet_start_position + 2) {
      throw packet_header_length_error(packet_start_position);
    }

    // Check whether we have a valid new-style packet header.
    //
    // It should look like:
    //
    //       ---------------
    //       1|1|x|x|x|x|x|x
    //   -------------------
    //   Bit 7|6|5|4|3|2|1|0
    //
    // Bit seven is always one, bit six determines whether we have an
    // old-style (zero) or new-style (one) packet.
    //
    // See RFC4880 §4.2.
    uint8_t header = data[packet_start_position];
    uint8_t packet_tag;
    int64_t packet_length = 0;
    int     packet_length_length;

    // Bit seven should always be set
    if (0x80 != (header & 0x80)) {
      throw invalid_header_error(packet_start_position);
    }
    // Bit six is set if and only if we have a new-style packet.
    if (0x40 != (header & 0x40)) {
      packet_tag = (header & 0x3C) >> 2;
      uint8_t length_type = header & 0x03;

      struct find_length_result length
          = find_length_old(data, packet_start_position+1, length_type,
                            packet_start_position);

      packet_length = length.length;
      packet_length_length = length.length_field_length;
    }
    else {
      // First, we  extract the packet tag in bits [5:0]
      packet_tag = header & 0x3F;

      // Next, we get the length.
      struct find_length_result length
          = find_length_new(data, packet_start_position+1, true,
                            packet_start_position);

      packet_length = length.length;
      packet_length_length = length.length_field_length;
    }
      
    // Now that we know how long the packet should be, we can check that we
    // have enough data.
    std::size_t packet_length_with_overhead =
        1                     // Header
        + packet_length_length  // Length
        + packet_length;        // Data
    
    if (data.length() < packet_start_position+packet_length_with_overhead) {
      throw packet_length_error(packet_start_position,
                                packet_length_with_overhead,
                                data.length() - packet_start_position);
    }
    // Finally, we can create the packet.
    if (!callback(
        PGPPacket::ParsePacket(packet_tag, data.substr(
            packet_start_position + packet_length_length + 1, packet_length)))) {
      packet_start_position += packet_length_with_overhead;
      break;
    }

    packet_start_position += packet_length_with_overhead;
  }

}

std::list<std::shared_ptr<PGPPacket>> parse(ustring data) {
  std::list<std::shared_ptr<PGPPacket>> parsed_packets;
  parse(data, [&parsed_packets](std::shared_ptr<PGPPacket> packet) -> bool {
      parsed_packets.push_back(std::move(packet));
      return true;
    });
  return parsed_packets;
}

std::list<std::shared_ptr<PGPPacket>> parse_subpackets(ustring data) {
  std::list<std::shared_ptr<PGPPacket>> subpackets;
  for (size_t packet_start_position = 0; packet_start_position < data.length();) {
    // First we need to extract the packet length.  This is a new-style
    // length, so it has a variable length itself.
    struct find_length_result packet_length_result =
        find_length_new(data, packet_start_position, false, -1);

    // Now that we have decoded the length field, we can find the
    // full size of the packet plus header.
    int64_t packet_length_with_overhead =
          packet_length_result.length_field_length
        + packet_length_result.length;

    // Check that the packet has a nonzero length that doesn't extend
    // beyond the data that we have been given.  It has to be nonzero
    // because the first octet of the packet is the subpacket tag.
    if (data.length() < packet_start_position + packet_length_with_overhead
        || packet_length_result.length == 0) {
      throw packet_length_error(-1,
                                packet_length_with_overhead,
                                data.length() - packet_start_position); 
    }

    // Extract the tag octet from the packet.
    uint8_t packet_tag =
        data[packet_start_position + packet_length_result.length_field_length];

    // Push the newly-extracted packet into our return-value list.
    //
    // As yet we have not implemented proper container classes for the
    // various subpackets, and instead just use an UnknownPGPPacket.
    // Probably subpackets should have a somewhat separate hierarchy,
    // but this is yet to be decided.
    subpackets.push_back(std::shared_ptr<PGPPacket>(new UnknownPGPPacket(
        packet_tag,
        data.substr(packet_start_position
                    + packet_length_result.length_field_length
                    + 1,
                    packet_length_result.length - 1))));

    // Skip forward to the next packet.
    packet_start_position += packet_length_with_overhead;
  }

  return subpackets;
}

}
