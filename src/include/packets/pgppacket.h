#ifndef PARSE4880_INCLUDE_PACKETS_PGPPACKET_H_
#define PARSE4880_INCLUDE_PACKETS_PGPPACKET_H_

/**
 * @file pgppacket.h
 *
 * Generic PGP packet type.
 */

#include "parser_types.h"

namespace parse4880 {

/**
 * Base class for PGP packet types.
 *
 * The PGPPacket class describes the elements of the packet tree,
 * providing basic packet information and a list of subpackets.
 */
class PGPPacket {
 public:
  /**
   * Construct a PGPPacket from binary data.  As this class is
   * abstract, this simply stores the contents for e.g. signature
   * verification.
   *
   * @param contents  The contents of the packet.
   */
  PGPPacket(ustring contents);

  /**
   * Get a list of subpackets.
   *
   * @return A list of shared_ptr<PGPPacket>s to the subpackets.
   */
  const std::list<std::shared_ptr<PGPPacket>>& subpackets() const;

  /**
   * Return the packet ID, as specified in RFC4880.
   *
   * @return The packet ID.
   */
  virtual uint8_t tag() const = 0;

  /**
   * Construct a human-readable description of the packet contents.
   *
   * @return A packet description.
   */
  virtual std::string str() const = 0;

  /**
   * Get the raw contents of the packet.
   *
   * @return The packet contents.
   */
  const ustring& contents() const;

 protected:
  /**
   * A list of the packet's subpackets.
   */
  std::list<std::shared_ptr<PGPPacket>> subpackets_;

 private:
  ustring contents_;

 public:
  /**
   * Parse a single packet.
   *
   * @param tag     The packet tag.
   * @param packet  The raw packet data to be parsed.
   */
  static std::shared_ptr<PGPPacket> ParsePacket(uint8_t tag,
                                                ustring packet);
};

}

#endif  // PARSE4880_INCLUDE_PACKETS_PGPPACKET_H_
