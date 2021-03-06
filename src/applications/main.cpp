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
                   int level);
void print_packet(const parse4880::PGPPacket& packet, int level);


void print_packet(const parse4880::PGPPacket& packet, int level) {
  std::string newline_replacement = "";
  for(int i = 0; i < level; i++) {
    newline_replacement += "    ";
  }
  printf("%sPacket: %s\n", newline_replacement.c_str(), packet.str().c_str());
  print_packets(packet.subpackets(), level+1);
}

void print_packets(std::list<std::shared_ptr<parse4880::PGPPacket>> packets,
                   int level) {

  for (auto i = packets.begin(); i != packets.end(); i++) {
    print_packet(**i, level);
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

  try {
    std::string file_contents = str_stream.str();
    parse4880::parse(
        parse4880::ustring(file_contents.begin(), file_contents.end()),
        [](std::shared_ptr<parse4880::PGPPacket> packet) -> bool {
          print_packet(*packet, 0);
          return true;
        });
  }
  catch(const parse4880::parse4880_error& e) {
    fprintf(stderr, "Parse error:\n\t%s\n", e.what());
    return 1;
  }
}
