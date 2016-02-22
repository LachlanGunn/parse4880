#ifndef PARSE4880_INCLUDE_PACKET_H_
#define PARSE4880_INCLUDE_PACKET_H_

#include <cstdint>
#include <string>
#include <memory>
#include <list>

namespace parse4880 {

class PGPPacket {
 public:
  const std::list<std::shared_ptr<PGPPacket>>& subpackets();

  virtual uint8_t tag() const = 0;
  virtual std::string str() const = 0;

 protected:
  PGPPacket();

 protected:
  std::list<std::shared_ptr<PGPPacket>> subpackets_;

 public:
  static std::shared_ptr<PGPPacket> ParsePacket(uint8_t tag,
                                                std::string packet);
};

class UnknownPGPPacket : public PGPPacket {
 public:
  UnknownPGPPacket(uint8_t tag, std::string contents);
  
  virtual uint8_t tag() const;
  virtual std::string str() const;
  const std::string& contents();

 protected:
  uint8_t tag_;
  std::string contents_;
};

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
  uint16_t hash_left_16bits() const;
  const std::string& signature() const;

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
  uint16_t hash_left_16bits_;
  std::string signature_;
};

}

#endif  // PARSE4880_INCLUDE_PACKET_H_
