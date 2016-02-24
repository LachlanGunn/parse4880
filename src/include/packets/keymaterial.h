#ifndef PARSE4880_INCLUDE_PACKETS_KEYMATERIAL_H_
#define PARSE4880_INCLUDE_PACKETS_KEYMATERIAL_H_

namespace parse4880 {

class KeyMaterialPacket : public PGPPacket {
 public:
  uint8_t  version() const;
  int64_t  creation_time() const;
  uint8_t  public_key_algorithm() const;

 protected:
  uint8_t version_;
  int64_t creation_time_;
  uint8_t public_key_algorithm_;
};

class PublicKeyPacket : public KeyMaterialPacket {
 public:
  PublicKeyPacket(const std::string& contents);

  virtual uint8_t tag() const;
  virtual std::string str() const;

  const std::string& fingerprint() const;

 protected:
  const std::string& key_material() const;

 protected:
  std::string key_material_;
  std::string fingerprint_;
};

class PublicSubkeyPacket : public PublicKeyPacket {
 public:
  PublicSubkeyPacket(std::string contents);

  virtual uint8_t tag() const;
  virtual std::string str() const;
};

}

#endif  // PARSE4880_INCLUDE_PACKETS_KEYMATERIAL_H_
