#include <string>

#include <cryptopp/rsa.h>

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
  CryptoPP::RSAFunction public_transformation;
};

namespace {

/**
 * Verification context for RSA signatures with PKCSv1.5.
 *
 * @see VerificationContext
 */
template <class Hash>
class RSAVerificationContext : public VerificationContext {
 public:
  explicit RSAVerificationContext(const CryptoPP::RSAFunction& public_key,
                                  const SignaturePacket& signature);
  virtual ~RSAVerificationContext();

  virtual void Update(const uint8_t* data, std::size_t len);
  virtual void Update(const std::string& data);
  virtual bool Verify();

 private:
  SignaturePacket signature_;
  typename CryptoPP::RSASS<CryptoPP::PKCS1v15, Hash>::Verifier verifier_;
  CryptoPP::PK_MessageAccumulator* accumulator_;
};

/**
 * Read an RSA public key from a public key packet's key material
 * section.
 *
 * The last part of public key packet---that containing the key itself---is
 * algorithm-dependent.  This function parses this part into a Crypto++
 * RSAFunction object from which we may create a verifier.
 *
 * @param key_material  The public key to be parsed.
 *
 * @return An RSAFunction corresponding to the encoded exponent and modulus.
 */
CryptoPP::RSAFunction ReadRSAPublicKey(std::string key_material) {
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
  CryptoPP::Integer modulus;
  modulus.OpenPGPDecode(reinterpret_cast<const uint8_t*>(
      key_material.substr(0, 2+modulus_length).c_str()), 2+modulus_length);

  size_t exponent_length = parse4880::ReadInteger(
      key_material.substr(2+modulus_length,2));
  exponent_length = ((exponent_length +7) / 8);
  if (key_material.length() < 4 + modulus_length + exponent_length) {
    throw parse4880::invalid_header_error(-1);
  }

  CryptoPP::Integer exponent;
  exponent.OpenPGPDecode(reinterpret_cast<const uint8_t*>(
      key_material.substr(2+modulus_length, 2+exponent_length).c_str()),
                        2+exponent_length);

  CryptoPP::RSAFunction pk;
  pk.Initialize(modulus, exponent);
  return pk;
}

template <class Hash>
RSAVerificationContext<Hash>::RSAVerificationContext(
    const CryptoPP::RSAFunction& public_key,
    const SignaturePacket& signature)
    : signature_(signature),
      verifier_(public_key),
      accumulator_(verifier_.NewVerificationAccumulator()) {
}

template <class Hash>
RSAVerificationContext<Hash>::~RSAVerificationContext() {
  delete accumulator_;
}

template <class Hash>
void RSAVerificationContext<Hash>::Update(const uint8_t* data, std::size_t len) {
  accumulator_->Update(data, len);
}

template <class Hash>
void RSAVerificationContext<Hash>::Update(const std::string& data) {
  Update(reinterpret_cast<const uint8_t*>(data.c_str()), data.length());
}

template <class Hash>
bool RSAVerificationContext<Hash>::Verify() {
  Update(signature_.hashed_data());

  if (4 == signature_.version()) {
    const uint8_t trailer[]  = {0x04, 0xFF};
    Update(trailer, sizeof(trailer));
    Update(WriteInteger(signature_.hashed_data().length(), 4));
  }

  verifier_.InputSignature(*accumulator_,
                           reinterpret_cast<const uint8_t*>(
                               signature_.signature().substr(2).c_str()),
                           signature_.signature().length() - 2);
  return verifier_.VerifyAndRestart(*accumulator_);
}

}

RSAKey::RSAKey(const PublicKeyPacket& rhs)
    : impl_(new impl) {
  if (kPublicKeyRSAEncryptOrSign != rhs.public_key_algorithm()) {
    throw wrong_algorithm_error();
  }

  impl_->public_transformation = ReadRSAPublicKey(rhs.key_material());
}

RSAKey::~RSAKey() = default;

std::unique_ptr<VerificationContext>
RSAKey::GetVerificationContext(const SignaturePacket& signature) {
  VerificationContext* ctx;
  switch (signature.hash_algorithm()) {
    case kHashSHA1:
      ctx = new RSAVerificationContext<CryptoPP::SHA1>(
          impl_->public_transformation, signature);
      break;
    case kHashSHA224:
      ctx = new RSAVerificationContext<CryptoPP::SHA224>(
          impl_->public_transformation, signature);
      break;
    case kHashSHA256:
      ctx = new RSAVerificationContext<CryptoPP::SHA256>(
          impl_->public_transformation, signature);
      break;
    case kHashSHA384:
      ctx = new RSAVerificationContext<CryptoPP::SHA384>(
          impl_->public_transformation, signature);
      break;
    case kHashSHA512:
      ctx = new RSAVerificationContext<CryptoPP::SHA512>(
          impl_->public_transformation, signature);
      break;
    default:
      throw unsupported_feature_error(-1, "Unsupported hash function.");
  }

  return std::unique_ptr<VerificationContext>(ctx);
}

/// @endcond

}
