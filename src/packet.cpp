#include "packet.h"

#include <cstdint>
#include <string>

namespace parse4880 {

PGPPacket::PGPPacket(uint8_t tag, std::string contents)
    : tag_(tag), contents_(contents) {}

uint8_t PGPPacket::tag() {
  return tag_;
}

const std::string& PGPPacket::contents() {
  return contents_;
}

}
