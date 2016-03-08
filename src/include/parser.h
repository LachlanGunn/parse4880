#include <list>
#include <memory>
#include <string>

#include "packet.h"

namespace parse4880 {

std::list<std::shared_ptr<PGPPacket>> parse(std::string data);
std::list<std::shared_ptr<PGPPacket>> parse_subpackets(std::string data);

uint64_t    ReadInteger(std::string encoded_integer);
std::string WriteInteger(uint64_t value, uint8_t length);

}
