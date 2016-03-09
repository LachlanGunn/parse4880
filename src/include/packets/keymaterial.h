#ifndef PARSE4880_INCLUDE_PACKETS_KEYMATERIAL_H_
#define PARSE4880_INCLUDE_PACKETS_KEYMATERIAL_H_

/**
 * @file keymaterial.h
 *
 * Key-related packet classes.
 */

#include "packet.h"

namespace parse4880 {

/**
 * Base class for packets containing key material.
 */
class KeyMaterialPacket : public PGPPacket {
 public:
  /**
   * Key version.
   *
   * @return The version of the key, either 3 or 4 in RFC4880.
   */
  uint8_t version() const;

  /**
   * Key creation time.
   *
   * @return the creation time of the key, in seconds since the UNIX epoch.
   */
  int64_t creation_time() const;

  /**
   * Public key algorithm.
   *
   * @return the OpenPGP code representing the algorithm for this key.
   */
  uint8_t public_key_algorithm() const;

 protected:
  /**
   * Constructor, sets fields that are independent of key type.
   *
   * @param content  The field to parse.
   */
  KeyMaterialPacket(std::string content);

 protected:
  /**
   * Version field for the key.
   */
  uint8_t version_;

  /**
   * Creation time of the key, in seconds since the UNIX epoch.
   */
  int64_t creation_time_;

  /**
   * Public key algorithm of the key, as specified in RFC4880.
   */
  uint8_t public_key_algorithm_;
};

/**
 * Public key packet.  Holds the key material for a public key.
 */
class PublicKeyPacket : public KeyMaterialPacket {
 public:
  /**
   * Parse raw public key packet data.
   *
   * @param contents  Packet data to be parsed.
   */
  PublicKeyPacket(const std::string& contents);

  virtual uint8_t tag() const;
  virtual std::string str() const;

  /**
   * The fingerprint of the key.
   *
   * @return The fingerprint of the key, in binary format.
   */
  const std::string& fingerprint() const;

  /**
   * The raw key material of the packet.
   *
   * @return A string containing the packet's raw key material.
   */
  const std::string& key_material() const;

 private:
  std::string key_material_;
  std::string fingerprint_;
};

/**
 * Public subkey packet.  This is identical to a normal public key
 * packet, but with a different tag.
 */
class PublicSubkeyPacket : public PublicKeyPacket {
 public:
  /**
   * Parse the public-key part of a subkey.
   *
   * @param contents  Packet data to be parsed.
   */
  PublicSubkeyPacket(std::string contents);

  virtual uint8_t tag() const;
  virtual std::string str() const;
};

}

#endif  // PARSE4880_INCLUDE_PACKETS_KEYMATERIAL_H_
