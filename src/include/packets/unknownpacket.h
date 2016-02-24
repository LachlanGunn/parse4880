#ifndef PARSE4880_INCLUDE_PACKETS_UNKNOWNPACKET_H_
#define PARSE4880_INCLUDE_PACKETS_UNKNOWNPACKET_H_

namespace parse4880 {

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

}

#endif  // PARSE4880_INCLUDE_PACKETS_UNKNOWNPACKET_H_
