#include <string>
#include <memory>
#include <list>

#include "boost/format.hpp"

#include "packet.h"
#include "exceptions.h"
#include "parser.h"

namespace parse4880 {

UnknownPGPPacket::UnknownPGPPacket(uint8_t tag, std::string contents)
    : PGPPacket(contents), tag_(tag) {}

uint8_t UnknownPGPPacket::tag() const {
  return tag_;
}

std::string UnknownPGPPacket::str() const {
  return (boost::format("Type %1%") % static_cast<int>(tag_)).str();
}

}
