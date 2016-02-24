#ifndef PARSE4880_INCLUDE_PACKETS_SIGNATURE_H_
#define PARSE4880_INCLUDE_PACKETS_SIGNATURE_H_

#include <list>
#include <memory>

#include "packet.h"

namespace parse4880 {

class SignaturePacket : public PGPPacket {
 public:
  explicit SignaturePacket(std::string packet_data);

  virtual uint8_t tag() const;
  virtual std::string str() const;

  uint8_t version() const;
  const std::string& key_id() const;
  uint8_t signature_type() const;
  uint8_t public_key_algorithm() const;
  uint8_t hash_algorithm() const;
  const std::string& hashed_subpacket_data() const;
  const std::string& unhashed_subpacket_data() const;
  const uint8_t* hash_left_16bits() const;
  const std::string& signature() const;
  const std::string& hashed_data() const;

 private:
  void SetSignaturePropertiesFromSubpackets();

 private:
  uint8_t version_;
  std::string key_id_;
  uint8_t signature_type_;
  uint8_t public_key_algorithm_;
  uint8_t hash_algorithm_;
  std::string hashed_subpacket_data_;
  std::string unhashed_subpacket_data_;
  uint8_t hash_left_16bits_[2];
  std::string signature_;
  std::string hashed_data_;
};

}

#endif  // PARSE4880_INCLUDE_PACKETS_SIGNATURE_H_
