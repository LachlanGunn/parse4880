#include <stdlib.h>
#include <memory.h>

#include <string>

#include <mbedtls/md.h>

#include <boost/format.hpp>

#include "exceptions.h"
#include "parser.h"
#include "packet.h"

namespace parse4880 {

KeyMaterialPacket::KeyMaterialPacket(std::string content)
    : PGPPacket(content) {
}

uint8_t KeyMaterialPacket::version() const {
  return version_;
}

int64_t KeyMaterialPacket::creation_time() const {
  return creation_time_;
}

uint8_t KeyMaterialPacket::public_key_algorithm() const {
  return public_key_algorithm_;
}

PublicKeyPacket::PublicKeyPacket(const std::string& data)
    : KeyMaterialPacket(data) {
  /*
   * A public key packet contains the following:
   *
   *   [1] Version
   *   [4] Creation time
   *   [1] Public key algorithm
   *   [?] Key material
   */
  if (data.length() < 1) {
    throw invalid_header_error(-1);
  }

  version_ = data[0];
  if (version_ != 4) {
    throw unsupported_feature_error(-1, "non-v4 keys");
  }

  if (data.length() < 6) {
    throw invalid_header_error(-1);
  }

  creation_time_ = ReadInteger(data.substr(1,4));
  public_key_algorithm_ = data[5];
  key_material_ = data.substr(6);

  /*
   * The fingerprint is calculated as the SHA-1 hash of the following:
   *
   *   1. The constant octet 0x99
   *   2. A two-octet length of of the packet.
   *   3. The entirety of the packet data.
   */
  mbedtls_md_context_t md_ctx;
  const mbedtls_md_info_t* md_type = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
  mbedtls_md_init(&md_ctx);
  mbedtls_md_setup(&md_ctx, md_type, 0);
  mbedtls_md_starts(&md_ctx);

  mbedtls_md_update(&md_ctx, reinterpret_cast<const unsigned char*>("\x99"), 1);
  mbedtls_md_update(&md_ctx, reinterpret_cast<const unsigned char*>(
      WriteInteger(data.length(),2).c_str()), 2);
  mbedtls_md_update(&md_ctx, reinterpret_cast<const unsigned char*>(data.c_str()),
              data.length());

  size_t digest_length = mbedtls_md_get_size(md_type);
  std::unique_ptr<char[]> digest(new char[digest_length]);
  memset(digest.get(), '\0', digest_length);
  mbedtls_md_finish(&md_ctx, reinterpret_cast<unsigned char*>(digest.get()));
  mbedtls_md_free(&md_ctx);

  fingerprint_ = std::string(digest.get(), digest_length);
}

uint8_t PublicKeyPacket::tag() const {
  return 6;
}

std::string PublicKeyPacket::str() const {
  const std::string& key_fingerprint = fingerprint();
  char key_id[41]; // Flawfinder: ignore (fingerprints have known length)
  for(int i = 0; i < 20; i+=1) {
    snprintf(key_id+i*2, 3, "%02X",
             static_cast<unsigned char>(key_fingerprint[i]));
  }
  return (boost::format("Public key: %s") % key_id).str();
}

const std::string& PublicKeyPacket::fingerprint() const {
  return fingerprint_;
}

const std::string& PublicKeyPacket::key_material() const {
  return key_material_;
}

PublicSubkeyPacket::PublicSubkeyPacket(std::string contents)
    : PublicKeyPacket(contents) {}

uint8_t PublicSubkeyPacket::tag() const {
  return 14;
}

std::string PublicSubkeyPacket::str() const {
  const std::string& key_fingerprint = fingerprint();
  char key_id[41]; // Flawfinder: ignore (fingerprints have known length)
  for(int i = 0; i < 20; i+=1) {
    snprintf(key_id+i*2, 3, "%02X",
             static_cast<unsigned char>(key_fingerprint[i]));
  }
  return (boost::format("Public subkey: %s") % key_id).str();
}

}
