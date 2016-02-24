#ifndef PARSE4880_INCLUDE_PACKETS_PGPPACKET_H_
#define PARSE4880_INCLUDE_PACKETS_PGPPACKET_H_

namespace parse4880 {

class PGPPacket {
 public:
  PGPPacket(std::string contents);

  const std::list<std::shared_ptr<PGPPacket>>& subpackets();

  virtual uint8_t tag() const = 0;
  virtual std::string str() const = 0;

  const std::string& contents() const;

 protected:

 protected:
  std::list<std::shared_ptr<PGPPacket>> subpackets_;
  std::string contents_;

 public:
  static std::shared_ptr<PGPPacket> ParsePacket(uint8_t tag,
                                                std::string packet);
};

}

#endif  // PARSE4880_INCLUDE_PACKETS_PGPPACKET_H_
