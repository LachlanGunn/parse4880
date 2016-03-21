#ifndef PARSE4880_INCLUDE_PACKETS_USERID_H_
#define PARSE4880_INCLUDE_PACKETS_USERID_H_

/**
 * @file userid.h
 *
 * User ID packet class.
 */

#include "parser_types.h"

namespace parse4880 {

/**
 * Parser for user-id packets.
 */
class UserIDPacket : public PGPPacket {
 public:
  /**
   * Parse a user-id packet.
   *
   * @param contents  The packet data to parse.
   */
  UserIDPacket(ustring contents);
  
  virtual uint8_t tag() const;
  virtual std::string str() const;

  /**
   * The packet's user-id.
   *
   * @return A string containing the user-id.
   */
  std::string user_id() const;

 private:
  ustring user_id_;
};

}

#endif  // PARSE4880_INCLUDE_PACKETS_USERID_H_
