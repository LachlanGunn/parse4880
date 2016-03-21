#include <boost/format.hpp>

#include "packet.h"
#include "parser_types.h"

namespace parse4880 {

UserIDPacket::UserIDPacket(ustring contents)
    : PGPPacket(contents) {
  user_id_ = contents;
}

uint8_t UserIDPacket::tag() const {
  return 13;
}

std::string UserIDPacket::str() const {
  return (boost::format("User ID: %s")
          % std::string(user_id_.begin(), user_id_.end())).str();
}

std::string UserIDPacket::user_id() const {
  return std::string(user_id_.begin(), user_id_.end());
}

}
