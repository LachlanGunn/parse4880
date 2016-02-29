#include <list>
#include <memory>
#include <string>

#include "packet.h"

namespace parse4880 {

std::list<std::shared_ptr<PGPPacket>> parse(std::string data);
std::list<std::shared_ptr<PGPPacket>> parse_subpackets(std::string data);

int64_t     ReadInteger(std::string encoded_integer);
std::string WriteInteger(int64_t value, uint8_t length);

}