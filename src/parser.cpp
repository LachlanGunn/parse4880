#include <cstdint>
#include <cstdio>

#include <string>
#include <memory>
#include <stdexcept>

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
  int64_t          length;
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
 * TODO: Deal with partial-length records.
 */
struct find_length_result find_length_new(const std::string& string_data,
                                          int field_position,
                                          bool allow_partial) {
  struct find_length_result result;
  const unsigned char* data =
      reinterpret_cast<const unsigned char*>(string_data.c_str());

  // Now we have to get the length.  This is a bit tricky.
  // When we first checked the length, we made sure that the first
  // octet was available---this tells us how long the total length is.
  result.length = (unsigned char)data[field_position];
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
      throw invalid_header_error(field_position);
    }
    // The two-octet length is defined in RFC4880§4.2.2.2
    result.length =
        ( (data[field_position    ] - 192 ) << 8)
        +  data[field_position + 1]
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
    if (string_data.length() < field_position + 6) {
      throw invalid_header_error(field_position);
    }
    // The five-octet length is defined in RFC4880§4.2.2.3
    result.length =
          (data[field_position + 1] << 24)
        + (data[field_position + 2] << 16)
        + (data[field_position + 3] << 8)
        +  data[field_position + 4];
    result.length_field_length = 5;
  }
  
  return result;
}

/**
 * Find the length of a old-style packet chunk.
 *
 * An old-style packet encodes its length type in the header
 * than in the header.
 */
struct find_length_result find_length_old(const std::string& data,
                                          int field_position,
                                          int length_type) {
  struct find_length_result result;

  if (length_type == 3) {
    result.length = data.length() - field_position;
    result.length_field_length = 0;
  }
  else {
    result.length_field_length = 1 << length_type ;
    // Check that the buffer is large enough
    if (data.length() <= field_position + result.length_field_length) {
      throw invalid_header_error(field_position);
    }

    result.length = ReadInteger(data.substr(field_position,
                                            result.length_field_length));
  }
  
  return result;
}

}

/**
 * Parse an OpenPGP-style small (as opposed to multiprecision) integer.
 *
 * @param   encoded_integer    An string to be converted to an integer.
 *
 * @return  The decoded integer value.
 */
int64_t ReadInteger(std::string encoded_integer) {
  int64_t parsed_integer = 0;
  for (int i = 0; i < encoded_integer.length(); i++) {
    parsed_integer +=
        encoded_integer[i] << ( 8*(encoded_integer.length() - i - 1) );
  }
  return parsed_integer;
}

/**
 * Encode an OpenPGP-style small (as opposed to multiprecision) integer.
 *
 * @param   encoded_integer    An string to be converted to an integer.
 *
 * @return  The decoded integer value.
 */
std::string WriteInteger(int64_t value, uint8_t length) {
  std::string result((size_t)length, ' ');
  for (int i = length-1; i >= 0; i--) {
    std::fprintf(stderr, "WriteInteger: %d\n", i);
    result[i] = value & 0xFF;
    value >>= 8;
  }
  return result;
}


std::list<std::shared_ptr<PGPPacket>> parse(std::string data) {
  std::list<std::shared_ptr<PGPPacket>> parsed_packets;
      
  int64_t packet_start_position = 0;
  while(true) {
    // Check that we have enough data left.  We need at one byte for the
    // header and at least one byte for the length field.
    if(data.length() <= packet_start_position + 1) {
      break;
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
          = find_length_old(data, packet_start_position+1, length_type);

      packet_length = length.length;
      packet_length_length = length.length_field_length;
    }
    else {
      // First, we  extract the packet tag in bits [5:0]
      packet_tag = header & 0x3F;

      // Next, we get the length.
      struct find_length_result length
          = find_length_new(data, packet_start_position+1, true);

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
    parsed_packets.push_back(
        PGPPacket::ParsePacket(packet_tag, data.substr(
            packet_start_position + packet_length_length + 1, packet_length)));

    packet_start_position += packet_length_with_overhead;
  }

  return parsed_packets;
}

std::list<std::shared_ptr<PGPPacket>> parse_subpackets(std::string data) {
  std::list<std::shared_ptr<PGPPacket>> subpackets;
  for (int64_t packet_start_position = 0; packet_start_position < data.length();) {
    struct find_length_result packet_length_result =
        find_length_new(data, packet_start_position, false);

    int64_t packet_length_with_overhead =
          packet_length_result.length_field_length
        + packet_length_result.length;

    if (data.length() < packet_start_position + packet_length_with_overhead
        || packet_length_result.length == 0) {
      throw packet_length_error(-1,
                                packet_length_with_overhead,
                                data.length() - packet_start_position); 
    }

    uint8_t packet_tag =
        data[packet_start_position + packet_length_result.length_field_length];

    subpackets.push_back(std::shared_ptr<PGPPacket>(new UnknownPGPPacket(
        packet_tag,
        data.substr(packet_start_position
                    + packet_length_result.length_field_length
                    + 1,
                    packet_length_result.length - 1))));
    packet_start_position += packet_length_with_overhead;
  }

  return subpackets;
}

}
