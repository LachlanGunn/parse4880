#include "keys/key.h"
#include "keys/rsakey.h"
#include "constants.h"

namespace parse4880 {

/**
 * Virtual destructor.  Do nothing.
 */
VerificationContext::~VerificationContext() {
}

/**
 * Virtual destructor. Do nothing.
 */
Key::~Key() {
}

std::unique_ptr<Key> Key::ParseKey(const PublicKeyPacket& packet) {
  switch (packet.public_key_algorithm()) {
    case kPublicKeyRSAEncryptOrSign:
    case kPublicKeyRSAEncryptOnly:
    case kPublicKeyRSASignOnly:
      return std::unique_ptr<Key>(new RSAKey(packet));
      break;
    default:
      return nullptr;
  }
}

}
