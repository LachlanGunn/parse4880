#ifndef PARSE4880_INCLUDE_KEYS_KEY_H_
#define PARSE4880_INCLUDE_KEYS_KEY_H_

/**
 * @file key.h
 *
 * Public key and verification functionality.
 */

#include <memory>
#include <string>

#include "packet.h"

namespace parse4880 {

/**
 * Verify a signature.
 *
 * The VerificationContext class is performs the verification of a
 * PGP signature.  It has a hash-like update/final interface, however
 * unlike a hash function it gives a true/false response.
 *
 * @see Key::GetVerificationContext
 */
class VerificationContext {
 public:
  virtual ~VerificationContext();

  /**
   * Provide data to be verified.
   *
   * The Update method incrementally hashes data to be verified. It may
   * be repeatedly called with additional data in order to allow signatures
   * to be verified without storing all of the data in memory.
   *
   * @param data  Additional data to be verified.
   * @see Verify
   */
  virtual void Update(const std::string& data) = 0;

  /**
   * Provide data to be from a C string..
   *
   * The Update method incrementally hashes data to be verified. It may
   * be repeatedly called with additional data in order to allow signatures
   * to be verified without storing all of the data in memory.
   *
   * @param data    Additional data to be verified.
   * @param length  The length of the supplied string.
   * @see Verify
   */
  virtual void Update(const uint8_t* data, size_t length) = 0;

  /**
   * Verify the signature.
   *
   * After adding the data to be verified using repeated calls to Update,
   * a call to Verify will hash the appropriate parts of the signature
   * packet and then verify the signature.
   *
   * @return  true if the signature is valid, false if not.
   * @see Update
   */
  virtual bool Verify() = 0;
};

/**
 * Represent a public key.
 *
 * The key object represents a public key, useful for signature operations.
 * It can be used to create a VerificationContext, allowing the verification
 * of PGP signature packets with arbitrary data.
 *
 * @see VerificationContext
 */
class Key {
 public:
  /**
   * Get a verification context corresponding to the attached signature.
   *
   * @param signature  The signature to be verified.
   *
   * @return A verification context.
   */
  virtual std::unique_ptr<VerificationContext>
  GetVerificationContext(const SignaturePacket& signature) const = 0;

  virtual ~Key();

 public:
  /**
   * Construct an algorithm-specific public-key object from a public
   * key packet.
   *
   * @param packet  The packet that is to be parsed.
   *
   * @return A unique_ptr to the resulting key object.
   */
  static std::unique_ptr<Key> ParseKey(const PublicKeyPacket& packet);
};

}

#endif  // PARSE4880_INCLUDE_KEYS_KEY_H_
