#include <exception>

#include "exceptions.h"
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
  std::unique_ptr<Key> parsed_key;
  switch (packet.public_key_algorithm()) {
    case kPublicKeyRSAEncryptOrSign:
    case kPublicKeyRSAEncryptOnly:
    case kPublicKeyRSASignOnly:
      parsed_key.reset(new RSAKey(packet));
      if (nullptr == parsed_key) {
        // FIXME: This should be a custom type.
        throw std::runtime_error("Parsing failed.");
      }
      return parsed_key;
      break;
    default:
      throw invalid_packet_error("Unsupported key type.");
  }
}

}
