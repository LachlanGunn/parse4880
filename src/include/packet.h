#ifndef PARSE4880_INCLUDE_PACKET_H_
#define PARSE4880_INCLUDE_PACKET_H_

#include <cstdint>
#include <string>

namespace parse4880 {

class PGPPacket {
public:
  PGPPacket(uint8_t tag, std::string contents);
  uint8_t tag();
  const std::string& contents();
  
protected:
  uint8_t tag_;
  std::string contents_;
};

}

#endif  // PARSE4880_INCLUDE_PACKET_H_
