#ifndef PARSE4880_INCLUDE_PACKETS_SIGNATURE_H_
#define PARSE4880_INCLUDE_PACKETS_SIGNATURE_H_

/**
 * @file signature.h
 *
 * Signature packet class.
 */

#include <list>
#include <memory>

#include "packet.h"

namespace parse4880 {

/**
 * Parser for OpenPGP signature packets.
 */
class SignaturePacket : public PGPPacket {
 public:
  /**
   * Parse a signature packet.
   *
   * @param packet_data  Packet data to parse.
   */
  explicit SignaturePacket(std::string packet_data);

  virtual uint8_t tag() const;
  virtual std::string str() const;

  /**
   * The signature version.
   *
   * @return The version of the signature, can be either 3 or 4.
   */
  uint8_t version() const;

  /**
   * The long (64-bit) key-id of the signing key.
   *
   * @return A string containing the long key-id in binary form.
   */
  const std::string& key_id() const;

  /**
   * The type of the signature.
   *
   * Every signature has a type, described in RFC4880 §5.2.1,
   * which describes the data to be signed.
   *
   * @return The signature type code.
   */
  uint8_t signature_type() const;

  /**
   * The public key algorithm used by the signature.
   *
   * @return The public key algorithm type code.
   */
  uint8_t public_key_algorithm() const;

  /**
   * The hash algorithm used by the signature.
   *
   * @return The hash algorithm type code.
   */
  uint8_t hash_algorithm() const;

  /**
   * The raw subpacket data that is to be hashed.
   *
   * @return A string containing the raw subpackets.
   */
  const std::string& hashed_subpacket_data() const;

  /**
   * The raw subpacket data that is not to be hashed.
   *
   * @return A string containing the raw subpackets.
   */
  const std::string& unhashed_subpacket_data() const;

  /**
   * The left sixteen bits of the hash, for quick verification.
   *
   * @return A pointer a uint8_t array containing the two bytes.
   */
  const uint8_t* hash_left_16bits() const;

  /**
   * The raw signature.
   *
   * @return A string containing the raw signature data.
   */
  const std::string& signature() const;

  /**
   * The entirety of the hashed data from the signature packet.
   *
   * The data hashed when signing or verifying has two parts.  The
   * first is the data of interest, whereas the second is the beginning
   * of the signature packet.
   *
   * We therefore need to provide a copy of the entirety of the
   * signature data to be hashed before we can verify the signature.
   *
   * @return A string to be appended to the data being verified before
   *         it is hashed.
   */
  const std::string& hashed_data() const;

 private:
  void SetSignaturePropertiesFromSubpackets();

 private:
  uint8_t version_;
  std::string key_id_;
  uint8_t signature_type_;
  uint8_t public_key_algorithm_;
  uint8_t hash_algorithm_;
  std::string hashed_subpacket_data_;
  std::string unhashed_subpacket_data_;
  uint8_t hash_left_16bits_[2];
  std::string signature_;
  std::string hashed_data_;
};

}

#endif  // PARSE4880_INCLUDE_PACKETS_SIGNATURE_H_
