#ifndef PARSE4880_INCLUDE_KEYS_RSAKEY_H_
#define PARSE4880_INCLUDE_KEYS_RSAKEY_H_

/**
 * @file rsakey.h
 *
 * Machinery for RSA public keys.
 */

#include "packets/signature.h"
#include "packets/keymaterial.h"
#include "keys/key.h"

namespace parse4880 {

/**
 * Represent an RSA public key.
 *
 * @see Key
 */
class RSAKey : public Key {
 public:
  /**
   * Construct an RSAKey from a PublicKeyPacket.
   *
   * RSAKeys are created from a PublicKeyPacket, which contains
   * a blob with the key information.
   */
  explicit RSAKey(const PublicKeyPacket& rhs);
  virtual ~RSAKey();
  
  virtual std::unique_ptr<VerificationContext> GetVerificationContext(
      const SignaturePacket& Signature) const;

 private:
  class impl;
  std::unique_ptr<impl> impl_;
};

}

#endif  // PARSE4880_INCLUDE_KEYS_RSAKEY_H_
