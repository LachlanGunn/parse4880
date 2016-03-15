#include <cstdio>

#include <iostream>
#include <fstream>
#include <sstream>
#include <list>
#include <memory>

#include "parser.h"
#include "packet.h"
#include "exceptions.h"

void print_packets(std::list<std::shared_ptr<parse4880::PGPPacket>> packets,
                   int level) {
  std::string newline_replacement = "";
  for(int i = 0; i < level; i++) {
    newline_replacement += "    ";
  }
  for (auto i = packets.begin(); i != packets.end(); i++) {
    printf("%sPacket: %s\n", newline_replacement.c_str(), (*i)->str().c_str());
    print_packets((*i)->subpackets(), level+1);
  }
}

int main(int argc, char** argv) {
  if (argc < 2) {
    std::cerr << "USAGE: parsepgp <file>" << std::endl;
    return 1;
  }

  std::ifstream pgp_file;
  pgp_file.open(argv[1]); // Flawfinder: ignore (give the user what they want)

  std::stringstream str_stream;
  str_stream << pgp_file.rdbuf();

  std::list<std::shared_ptr<parse4880::PGPPacket>> packets;
  try {
    packets = parse4880::parse(str_stream.str());
  }
  catch(parse4880::parse4880_error e) {
    fprintf(stderr, "Parse error:\n\t%s\n", e.what());
  }

  print_packets(packets, 0);
}
