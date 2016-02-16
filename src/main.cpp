#include <cstdio>

#include <iostream>
#include <fstream>
#include <sstream>
#include <list>
#include <memory>

#include "parser.h"
#include "packet.h"

int main(int argc, char** argv) {
  if (argc < 2) {
    std::cerr << "USAGE: parsepgp <file>" << std::endl;
    return 1;
  }

  std::ifstream pgp_file;
  pgp_file.open(argv[1]);

  std::stringstream str_stream;
  str_stream << pgp_file.rdbuf();

  std::list<std::shared_ptr<parse4880::PGPPacket>> packets
      = parse4880::parse(str_stream.str());

  for (auto i = packets.begin(); i != packets.end(); i++) {
    printf("Packet: type %d, length %ld\n",
           (*i)->tag(), (*i)->contents().length());
  }
}
