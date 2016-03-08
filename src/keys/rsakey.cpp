#include <string>

#include <cryptopp/rsa.h>

#include "parser.h"
#include "constants.h"
#include "exceptions.h"
#include "keys/rsakey.h"
#include "packets/signature.h"

namespace parse4880 {

class RSAKey::impl {
 public:
  CryptoPP::RSAFunction public_transformation;
};

namespace {

template <class Hash>
class RSAVerificationContext : public VerificationContext {
 public:
  explicit RSAVerificationContext(const CryptoPP::RSAFunction& public_key,
                                  const SignaturePacket& signature);

  virtual void Update(const uint8_t* data, std::size_t len);
  virtual void Update(const std::string& data);
  virtual bool Verify();

 private:
  SignaturePacket signature_;
  typename CryptoPP::RSASS<CryptoPP::PKCS1v15, Hash>::Verifier verifier_;
  CryptoPP::PK_MessageAccumulator* accumulator_;
};

CryptoPP::RSAFunction ReadRSAPublicKey(std::string key_material) {
  if (key_material.length() < 2) {
    throw parse4880::invalid_header_error(-1);
  }

  size_t modulus_length = parse4880::ReadInteger(key_material.substr(0,2));

  modulus_length = ((modulus_length+7) / 8);
  if (key_material.length() < 2 + modulus_length) {
    throw parse4880::invalid_header_error(-1);
  }

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
  
  const uint8_t trailer[]  = {0x04, 0xFF};
  Update(trailer, sizeof(trailer));
  Update(WriteInteger(signature_.hashed_data().length(), 4));

  verifier_.InputSignature(*accumulator_,
                           reinterpret_cast<const uint8_t*>(
                               signature_.signature().substr(2).c_str()),
                           signature_.signature().length() - 2);
  return verifier_.Verify(accumulator_);
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
    default:
      throw unsupported_feature_error(-1, "Unsupported hash function.");
  }

  return std::unique_ptr<VerificationContext>(ctx);
}

}
