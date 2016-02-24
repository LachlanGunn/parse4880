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
  switch (tag) {
    case 2:
      return std::shared_ptr<PGPPacket>(new SignaturePacket(packet));
      break;
    case 6:
      return std::shared_ptr<PGPPacket>(new PublicKeyPacket(packet));
      break;
    case 13:
      return std::shared_ptr<PGPPacket>(new UserIDPacket(packet));
      break;
    case 14:
      return std::shared_ptr<PGPPacket>(new PublicSubkeyPacket(packet));
      break;

    default:
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
