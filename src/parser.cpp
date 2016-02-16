#include <cstdint>
#include <cstdio>

#include <memory>
#include <stdexcept>

#include "parser.h"
#include "exceptions.h"

namespace parse4880 {

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
      if (length_type == 3) {
        packet_length = data.length() - packet_start_position - 1;
        packet_length_length = 0;
      }
      else {
        packet_length_length = 1 << length_type ;
        // Check that the buffer is large enough
        if (data.length() <= packet_start_position + packet_length_length) {
          throw invalid_header_error(packet_start_position);
        }
        for (int i = 0; i < packet_length_length; i++) {
          packet_length += data[packet_start_position+i+1]
              << (8*(packet_length_length-i-1));
        }
      }
    }
    else {
      // First, we  extract the packet tag in bits [5:0]
      packet_tag = header & 0x3F;

      // Now we have to get the length.  This is a bit tricky.
      // When we first checked the length, we made sure that the first
      // octet was available---this tells us how long the total length is.
      packet_length = data[packet_start_position+1];
      packet_length_length = 1;

      // If the packet length is less than 192, then it is equal to the first
      // octet and we are done.

      // If the first octet is from 192 to 223, then we have a two-octet length.
      if (packet_length > 191 && packet_length < 224) {
        // Check that the buffer is large enough
        if (data.length() <= packet_start_position + 3) {
          throw invalid_header_error(packet_start_position);
        }
        // The two-octet length is defined in RFC4880§4.2.2.2
        packet_length =
            ( (data[packet_start_position + 1] - 192 ) << 8)
            +  data[packet_start_position + 2]
            + 192;
        packet_length_length = 2;
      }
      // If the first octet is from 224 to 254, then we have a partial length
      // header.
      else if (packet_length >= 224 && packet_length < 255) {
        // TODO: Deal with these.
        throw unsupported_feature_error(packet_start_position,
                                        "partial body lengths");
      }
      // If the first octet is 255, then we have a five-octet length.
      else if (packet_length == 255) {
        // Check that the buffer is large enough
        if (data.length() <= packet_start_position + 6) {
          throw invalid_header_error(packet_start_position);
        }
        // The five-octet length is defined in RFC4880§4.2.2.3
        packet_length =
            (data[packet_start_position + 2] << 24)
            + (data[packet_start_position + 3] << 16)
            + (data[packet_start_position + 4] << 8)
            +  data[packet_start_position + 5];
        packet_length_length = 5;
      }
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
        std::shared_ptr<PGPPacket>(
            new PGPPacket(packet_tag, data.substr(
                packet_start_position + packet_length_length, packet_length))));

    packet_start_position += packet_length_with_overhead;
  }

  return parsed_packets;
}

}
