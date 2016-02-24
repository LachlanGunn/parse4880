#ifndef PARSE4880_INCLUDE_PACKETS_USERID_H_
#define PARSE4880_INCLUDE_PACKETS_USERID_H_

namespace parse4880 {

class UserIDPacket : public PGPPacket {
 public:
  UserIDPacket(std::string contents);
  
  virtual uint8_t tag() const;
  virtual std::string str() const;
  const std::string& user_id() const;

 protected:
  std::string user_id_;
};

}

#endif  // PARSE4880_INCLUDE_PACKETS_USERID_H_
