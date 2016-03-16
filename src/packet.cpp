#include <cstdio>
#include <cstdint>
#include <string>
#include <memory>
#include <list>

#include "boost/format.hpp"

#include "packet.h"
#include "exceptions.h"
#include "parser.h"

namespace parse4880 {

PGPPacket::PGPPacket(std::string contents) : contents_(contents) {
}

std::shared_ptr<PGPPacket> PGPPacket::ParsePacket(uint8_t tag,
                                                  std::string packet) {
  try {
    switch (tag) {
      case 2:
        return std::shared_ptr<PGPPacket>(new SignaturePacket(packet));
      case 6:
        return std::shared_ptr<PGPPacket>(new PublicKeyPacket(packet));
      case 13:
        return std::shared_ptr<PGPPacket>(new UserIDPacket(packet));
      case 14:
        return std::shared_ptr<PGPPacket>(new PublicSubkeyPacket(packet));
      default:
        return std::shared_ptr<PGPPacket>(new UnknownPGPPacket(tag, packet));
    }
  } catch (parse4880_error e) {
    return std::shared_ptr<PGPPacket>(new UnknownPGPPacket(tag, packet));
  }
}

const std::list<std::shared_ptr<PGPPacket>>& PGPPacket::subpackets() const {
  return subpackets_;
}

const std::string& PGPPacket::contents() const {
  return contents_;
}


}
