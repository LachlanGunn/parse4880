#include <assert.h>

#include <string>

#include <mbedtls/bignum.h>
#include <mbedtls/md.h>
#include <mbedtls/rsa.h>

#include "parser_types.h"
#include "parser.h"
#include "constants.h"
#include "exceptions.h"
#include "keys/rsakey.h"
#include "packets/signature.h"

namespace parse4880 {

/// @cond SHOW_INTERNAL

/**
 * Storage class for RSA key material.
 *
 * This class is necessary in order to avoid a Crypto++ dependency
 * in key.h.
 */
class RSAKey::impl {
 public:
  mbedtls_rsa_context rsa_context;
};

namespace {

/**
 * Verification context for RSA signatures with PKCSv1.5.
 *
 * @see VerificationContext
 */
template <mbedtls_md_type_t hash_id>
class RSAVerificationContext : public VerificationContext {
 public:
  explicit RSAVerificationContext(const mbedtls_rsa_context& public_key,
                                  const SignaturePacket& signature);
  virtual ~RSAVerificationContext();

  virtual void Update(const uint8_t* data, std::size_t len);
  virtual void Update(const ustring& data);
  virtual bool Verify();

 private:
  SignaturePacket signature_;
  mbedtls_md_context_t hash_ctx_;
  mbedtls_rsa_context public_key_;
};

/**
 * Read an RSA public key from a public key packet's key material
 * section.
 *
 * The last part of public key packet---that containing the key itself---is
 * algorithm-dependent.  This function parses this part into a Crypto++
 * RSAFunction object from which we may create a verifier.
 *
 * @param key_material    The public key to be parsed.
 * @param public_key_ctx  The public key context to be initialised.
 */
void ReadRSAPublicKey(ustring key_material,
                      mbedtls_rsa_context* public_key) {
  /*
   * The public key format is simply two multiprecision integers.
   * We start by making sure that there is a length field...
   */
  if (key_material.length() < 2) {
    throw parse4880::invalid_header_error(-1);
  }

  // Then we read it and check that there are enough bits in the string.
  size_t modulus_length = parse4880::ReadInteger(key_material.substr(0,2));

  modulus_length = ((modulus_length+7) / 8);
  if (key_material.length() < 4 + modulus_length) {
    throw parse4880::invalid_header_error(-1);
  }

  // First comes the modulus.  We extract and decode it.
  const ustring modulus_encoded = key_material.substr(2, modulus_length);
  assert(modulus_encoded.length() == modulus_length);
  mbedtls_mpi_read_binary(
      &public_key->N,
      reinterpret_cast<const uint8_t*>(modulus_encoded.c_str()),
      modulus_length);

  // We need to set the key length too.
  public_key->len = modulus_length;

  // Now the exponent.  We have already checked that the header is there.
  size_t exponent_length = parse4880::ReadInteger(
      key_material.substr(2+modulus_length,2));
  exponent_length = ((exponent_length +7) / 8);
  if (key_material.length() < 4 + modulus_length + exponent_length) {
    throw parse4880::invalid_header_error(-1);
  }

  const ustring exponent_encoded =
      key_material.substr(4+modulus_length, exponent_length);
  assert(exponent_encoded.length() == exponent_length);
  mbedtls_mpi_read_binary(
      &public_key->E,
      reinterpret_cast<const uint8_t*>(exponent_encoded.c_str()),
      exponent_length);

}

template <mbedtls_md_type_t hash_id>
RSAVerificationContext<hash_id>::RSAVerificationContext(
    const mbedtls_rsa_context& public_key,
    const SignaturePacket& signature)
    : signature_(signature) {

  mbedtls_md_init(&hash_ctx_);
  mbedtls_md_setup(&hash_ctx_, mbedtls_md_info_from_type(hash_id), 0);
  mbedtls_md_starts(&hash_ctx_);

  mbedtls_rsa_init(&public_key_, MBEDTLS_RSA_PKCS_V15, 0);
  mbedtls_rsa_copy(&public_key_, &public_key);
}

template <mbedtls_md_type_t hash_id>
RSAVerificationContext<hash_id>::~RSAVerificationContext() {
  mbedtls_md_free(&hash_ctx_);
  mbedtls_rsa_free(&public_key_);
}

template <mbedtls_md_type_t hash_id>
void RSAVerificationContext<hash_id>::Update(const uint8_t* data,
                                             std::size_t len) {
  mbedtls_md_update(&hash_ctx_, data, len);
}

template <mbedtls_md_type_t hash_id>
void RSAVerificationContext<hash_id>::Update(const ustring& data) {
  Update(data.c_str(), data.length());
}

template <mbedtls_md_type_t hash_id>
bool RSAVerificationContext<hash_id>::Verify() {
  Update(signature_.hashed_data());

  if (4 == signature_.version()) {
    const uint8_t trailer[]  = {0x04, 0xFF};
    Update(trailer, sizeof(trailer));
    Update(WriteInteger(signature_.hashed_data().length(), 4));
  }

  uint8_t hash_size = mbedtls_md_get_size(mbedtls_md_info_from_type(hash_id));
  std::unique_ptr<uint8_t[]> hash(new uint8_t[hash_size]);
  mbedtls_md_finish(&hash_ctx_, hash.get());
  mbedtls_md_free(&hash_ctx_);

  // Extract the signature itself from the packet.
  ustring signature = signature_.signature().substr(2);

  // MbedTLS requires that the signature have the same length as
  // the key, so we pad it with zeros if it is less.
  signature = ustring('\0', public_key_.len - signature.length())
      + signature;

  int result = mbedtls_rsa_rsassa_pkcs1_v15_verify(
      &public_key_, NULL, NULL, MBEDTLS_RSA_PUBLIC, hash_id, hash_size,
      hash.get(),
      reinterpret_cast<const uint8_t*>(signature.c_str()));

  return (result == 0);
}

}

RSAKey::RSAKey(const PublicKeyPacket& rhs)
    : impl_(new impl) {
  if (kPublicKeyRSAEncryptOrSign != rhs.public_key_algorithm()) {
    throw wrong_algorithm_error();
  }

  mbedtls_rsa_init(&impl_->rsa_context, MBEDTLS_RSA_PKCS_V15, 0);
  ReadRSAPublicKey(rhs.key_material(), &(impl_->rsa_context));
}

RSAKey::~RSAKey() {
  mbedtls_rsa_free(&impl_->rsa_context);
}

std::unique_ptr<VerificationContext>
RSAKey::GetVerificationContext(const SignaturePacket& signature) const {
  VerificationContext* ctx;
  switch (signature.hash_algorithm()) {
    case kHashSHA1:
      ctx = new RSAVerificationContext<MBEDTLS_MD_SHA1>(
          impl_->rsa_context, signature);
      break;
    case kHashSHA224:
      ctx = new RSAVerificationContext<MBEDTLS_MD_SHA224>(
          impl_->rsa_context, signature);
      break;
    case kHashSHA256:
      ctx = new RSAVerificationContext<MBEDTLS_MD_SHA256>(
          impl_->rsa_context, signature);
      break;
    case kHashSHA384:
      ctx = new RSAVerificationContext<MBEDTLS_MD_SHA384>(
          impl_->rsa_context, signature);
      break;
    case kHashSHA512:
      ctx = new RSAVerificationContext<MBEDTLS_MD_SHA512>(
          impl_->rsa_context, signature);
      break;
    default:
      throw unsupported_feature_error(-1, "Unsupported hash function.");
  }

  return std::unique_ptr<VerificationContext>(ctx);
}

/// @endcond

}
