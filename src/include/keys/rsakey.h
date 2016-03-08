#ifndef PARSE4880_INCLUDE_KEYS_RSAKEY_H_
#define PARSE4880_INCLUDE_KEYS_RSAKEY_H_

#include "packets/signature.h"
#include "packets/keymaterial.h"
#include "keys/key.h"

namespace parse4880 {

class RSAKey : public Key {
 public:
  explicit RSAKey(const PublicKeyPacket& rhs);
  virtual ~RSAKey();
  
  virtual std::unique_ptr<VerificationContext> GetVerificationContext(
      const SignaturePacket& Signature);

 private:
  class impl;
  std::unique_ptr<impl> impl_;
};

}

#endif  // PARSE4880_INCLUDE_KEYS_RSAKEY_H_
