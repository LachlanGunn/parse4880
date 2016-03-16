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
#include "keys/key.h"
#include "packets/keymaterial.h"
#include "verify.h"

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

template <class T, class U>
bool IsA(const std::shared_ptr<U>& ptr) {
  return (std::dynamic_pointer_cast<T>(ptr) != nullptr);
}

int main(int argc, char** argv) {
  if (argc < 2) {
    std::cerr << "USAGE: verifypgp <keys>" << std::endl;
    return 1;
  }

  std::list<std::shared_ptr<parse4880::PGPPacket>> key_packets;
  try {
    key_packets = parse_file(argv[1]);
  }
  catch(parse4880::parse4880_error e) {
    fprintf(stderr, "Parse error:\n\t%s\n", e.what());
    return 1;
  }

  std::shared_ptr<parse4880::PublicKeyPacket> key_ptr = nullptr;
  std::shared_ptr<parse4880::PublicSubkeyPacket> subkey_ptr = nullptr;
  std::shared_ptr<parse4880::UserIDPacket> uid_ptr = nullptr;

  for (auto i = key_packets.begin(); i != key_packets.end(); i++) {

    if (IsA<parse4880::PublicSubkeyPacket>(*i)) {
      subkey_ptr = std::dynamic_pointer_cast<parse4880::PublicSubkeyPacket>(*i);
    }
    else if (IsA<parse4880::PublicKeyPacket>(*i)) {
      key_ptr = std::dynamic_pointer_cast<parse4880::PublicKeyPacket>(*i);
    }
    else if (IsA<parse4880::UserIDPacket>(*i)) {
      uid_ptr = std::dynamic_pointer_cast<parse4880::UserIDPacket>(*i);
    }
    else if(IsA<parse4880::SignaturePacket>(*i)) {
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
          fprintf(stderr, "Certification by %s on\n\t%s\n\t%s\n",
                  signature_ptr->str().c_str(),
                  uid_ptr->str().c_str(),
                  key_ptr->str().c_str());

          try {
            std::unique_ptr<parse4880::Key> key =
                parse4880::Key::ParseKey(*key_ptr);

            fprintf(stderr, "Verification: %d\n",
                    parse4880::verify_uid_binding(*key_ptr, *uid_ptr,
                                                  *key, *signature_ptr));

          }
          catch (parse4880::parse4880_error e) {
            fprintf(stderr, "Error during verification:\n\t%s\n", e.what());
            return 1;
          }
          break;

        case parse4880::kSignatureSubkeyBinding:
          fprintf(stderr, "Subkey binding certification\n");
          try {
            fprintf(stderr, "Verification: %d\n",
                    parse4880::verify_subkey_binding(*key_ptr, *subkey_ptr,
                                                     *signature_ptr));

          }
          catch (parse4880::parse4880_error e) {
            fprintf(stderr, "Error during verification:\n\t%s\n", e.what());
            return 1;
          }
          break;

        default:
          continue;
      }

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
