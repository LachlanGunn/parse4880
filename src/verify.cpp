#include <cstdio>

#include <iostream>
#include <fstream>
#include <sstream>
#include <list>
#include <memory>

#include <cryptopp/sha.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>

#include "parser.h"
#include "packet.h"
#include "exceptions.h"
#include "keys/rsakey.h"
#include "packets/keymaterial.h"

std::string read_file(std::string filename) {
  std::ifstream file;
  file.open(filename); // Flawfinder: ignore (give the user what they want)

  std::stringstream str_stream;
  str_stream << file.rdbuf();

  return str_stream.str();
}
                      
std::list<std::shared_ptr<parse4880::PGPPacket>> parse_file(std::string file) {
  return parse4880::parse(read_file(file));
}



int main(int argc, char** argv) {
  if (argc < 4) {
    std::cerr << "USAGE: verifypgp <file> <signature> <keys>" << std::endl;
    return 1;
  }

  std::string to_verify = read_file(argv[1]);
  std::list<std::shared_ptr<parse4880::PGPPacket>> packets
      = parse_file(argv[2]);

  std::list<std::shared_ptr<parse4880::PGPPacket>> key_packets
      = parse_file(argv[3]);

  std::shared_ptr<parse4880::PublicKeyPacket> pk_packet
      = std::dynamic_pointer_cast<parse4880::PublicKeyPacket>(
          key_packets.front());

  if (nullptr == pk_packet) {
    fprintf(stderr, "Bad key file.\n");
    return 1;
  }

  for (auto i = packets.begin(); i != packets.end(); i++) {
    std::shared_ptr<parse4880::SignaturePacket> signature_ptr
        = std::dynamic_pointer_cast<parse4880::SignaturePacket>(*i);
    if (nullptr == signature_ptr) {
      continue;
    }

    parse4880::RSAKey key(*pk_packet);
    std::unique_ptr<parse4880::VerificationContext> ctx =
        key.GetVerificationContext(*signature_ptr);
    ctx->Update(to_verify);
    printf("Verification: %d\n", ctx->Verify());
  }
  
  return 0;
}
