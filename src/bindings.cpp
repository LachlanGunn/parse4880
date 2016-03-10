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
  if (argc < 2) {
    std::cerr << "USAGE: verifypgp <keys>" << std::endl;
    return 1;
  }

  std::list<std::shared_ptr<parse4880::PGPPacket>> key_packets
      = parse_file(argv[1]);

  std::shared_ptr<parse4880::PublicKeyPacket> key_ptr = nullptr;
  std::shared_ptr<parse4880::UserIDPacket> uid_ptr = nullptr;

  for (auto i = key_packets.begin(); i != key_packets.end(); i++) {

    if (typeid(**i) == typeid(parse4880::PublicKeyPacket)) {
      key_ptr = std::dynamic_pointer_cast<parse4880::PublicKeyPacket>(*i);
    }
    else if(typeid(**i) == typeid(parse4880::UserIDPacket)) {
      uid_ptr = std::dynamic_pointer_cast<parse4880::UserIDPacket>(*i);
    }
    else if(typeid(**i) == typeid(parse4880::SignaturePacket)) {
      std::shared_ptr<parse4880::SignaturePacket> signature_ptr =
          std::dynamic_pointer_cast<parse4880::SignaturePacket>(*i);

      if (nullptr == key_ptr || nullptr == uid_ptr
          || key_ptr->fingerprint().substr(12) != signature_ptr->key_id()) {
        continue;
      }

      switch (signature_ptr->signature_type()) {
        case parse4880::kSignatureCertificationGeneric:
        case parse4880::kSignatureCertificationCasual:
        case parse4880::kSignatureCertificationPositive:
          break;
        default:
          continue;
      }


      fprintf(stderr, "Certification by %s on\n\t%s\n\t%s\n",
              signature_ptr->str().c_str(),
              uid_ptr->str().c_str(),
              key_ptr->str().c_str());
      parse4880::RSAKey key(*key_ptr);
      std::unique_ptr<parse4880::VerificationContext> ctx =
          key.GetVerificationContext(*signature_ptr);

      uint8_t key_header[] = {0x99};
      ctx->Update(key_header, sizeof(key_header));
      ctx->Update(parse4880::WriteInteger(key_ptr->contents().length(), 2));
      ctx->Update(key_ptr->contents());

      uint8_t uid_header[] = {0xB4};
      ctx->Update(uid_header, sizeof(uid_header));
      ctx->Update(parse4880::WriteInteger(uid_ptr->contents().length(), 4));
      ctx->Update(uid_ptr->contents());      

      fprintf(stderr, "Verification: %d\n", ctx->Verify());
}
    else {
      continue;
    }
    

    /*
    fprintf(stderr, "Found key: %s\n", key_ptr->str().c_str());

    parse4880::RSAKey key(*key_ptr);
    std::unique_ptr<parse4880::VerificationContext> ctx =
        key.GetVerificationContext(*signature_packet);
    ctx->Update(to_verify);
    fprintf(stderr, "Verification: %d\n", ctx->Verify());
    */
  }
  
  return 0;
}
