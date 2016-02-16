#include <list>
#include <memory>
#include <string>

#include "packet.h"

namespace parse4880 {

std::list<std::shared_ptr<PGPPacket>> parse(std::string data);

}
