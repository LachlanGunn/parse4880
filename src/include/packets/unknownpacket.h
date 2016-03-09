#ifndef PARSE4880_INCLUDE_PACKETS_UNKNOWNPACKET_H_
#define PARSE4880_INCLUDE_PACKETS_UNKNOWNPACKET_H_

/**
 * @file unknownpacket.h
 *
 * Miscellaneous packet class.
 */

namespace parse4880 {

/**
 * A placeholder for unknown OpenPGP packets.
 */
class UnknownPGPPacket : public PGPPacket {
 public:
  /**
   * Construct the placeholder.
   *
   * @param tag       The packet type code.
   * @param contents  The contents of the packet.
   */
  UnknownPGPPacket(uint8_t tag, std::string contents);
  
  virtual uint8_t tag() const;
  virtual std::string str() const;

 private:
  uint8_t tag_;
};

}

#endif  // PARSE4880_INCLUDE_PACKETS_UNKNOWNPACKET_H_
