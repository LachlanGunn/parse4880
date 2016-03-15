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
#include "constants.h"
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
  std::list<std::shared_ptr<parse4880::PGPPacket>> packets;
  try {
    packets = parse_file(argv[2]);
  }
  catch(parse4880::parse4880_error e) {
    fprintf(stderr, "Parse error in signature file:\n\t%s\n", e.what());
  }


  std::list<std::shared_ptr<parse4880::PGPPacket>> key_packets;
  try {
    key_packets = parse_file(argv[3]);
  }
  catch(parse4880::parse4880_error e) {
    fprintf(stderr, "Parse error in keyring:\n\t%s\n", e.what());
  }


  if (1 != packets.size()) {
    fprintf(stderr, "ERROR: %s is not a detached signature.\n", argv[2]);
    return 1;
  }

  std::shared_ptr<parse4880::SignaturePacket> signature_packet
      = std::dynamic_pointer_cast<parse4880::SignaturePacket>(
          packets.front());

  if (nullptr == signature_packet) {
    fprintf(stderr, "ERROR: %s is not a detached signature.\n", argv[2]);
    return 1;
  }

  if (signature_packet->signature_type() != parse4880::kSignatureBinary) {
    fprintf(stderr, "ERROR: %s is not a detached signature.\n", argv[2]);
    return 1;
  }

  for (auto i = key_packets.begin(); i != key_packets.end(); i++) {
    std::shared_ptr<parse4880::PublicKeyPacket> key_ptr
        = std::dynamic_pointer_cast<parse4880::PublicKeyPacket>(*i);

    if (nullptr == key_ptr ||
        key_ptr->fingerprint().substr(12) != signature_packet->key_id()) {
      continue;
    }

    fprintf(stderr, "Found key: %s\n", key_ptr->str().c_str());

    try {
      parse4880::RSAKey key(*key_ptr);
      std::unique_ptr<parse4880::VerificationContext> ctx =
          key.GetVerificationContext(*signature_packet);
      ctx->Update(to_verify);
      fprintf(stderr, "Verification: %d\n", ctx->Verify());
    }
    catch (parse4880::parse4880_error e) {
      fprintf(stderr, "Error during verification:\n\t%s\n", e.what());
      return 1;
    }

  }
  
  return 0;
}
