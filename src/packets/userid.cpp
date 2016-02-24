#include <boost/format.hpp>

#include "packet.h"

namespace parse4880 {

UserIDPacket::UserIDPacket(std::string contents)
    : PGPPacket(contents) {
  user_id_ = contents;
}

uint8_t UserIDPacket::tag() const {
  return 13;
}

std::string UserIDPacket::str() const {
  return (boost::format("User ID: %s") % user_id_).str();
}

const std::string& UserIDPacket::user_id() const {
  return user_id_;
}

}
