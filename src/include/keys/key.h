#ifndef PARSE4880_INCLUDE_KEYS_KEY_H_
#define PARSE4880_INCLUDE_KEYS_KEY_H_

#include <memory>

namespace parse4880 {

class VerificationContext {
 public:
  virtual void Update(const std::string& data) = 0;
  virtual bool Verify() = 0;
};

class Key {
 public:
  virtual std::unique_ptr<VerificationContext>
  GetVerificationContext(const SignaturePacket& signature) = 0;
};

}

#endif  // PARSE4880_INCLUDE_KEYS_KEY_H_
