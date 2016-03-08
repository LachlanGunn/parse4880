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

CryptoPP::RSAFunction ReadRSAPublicKey(std::string key_material) {
  if (key_material.length() < 2) {
    throw parse4880::invalid_header_error(-1);
  }

  fprintf(stderr, "T: %ld\n", key_material.length());

  int64_t modulus_length = parse4880::ReadInteger(key_material.substr(0,2));

  modulus_length = ((modulus_length+7) / 8);
  if (key_material.length() < 2 + modulus_length) {
    throw parse4880::invalid_header_error(-1);
  }
  fprintf(stderr, "n: %ld\n", modulus_length);

  CryptoPP::Integer modulus;
  modulus.OpenPGPDecode(reinterpret_cast<const uint8_t*>(
      key_material.substr(0, 2+modulus_length).c_str()), 2+modulus_length);

  int64_t exponent_length = parse4880::ReadInteger(
      key_material.substr(2+modulus_length,2));
  fprintf(stderr, "e: %ld\n", exponent_length);
  exponent_length = ((exponent_length +7) / 8);
  if (key_material.length() < 4 + modulus_length + exponent_length) {
    throw parse4880::invalid_header_error(-1);
  }

  CryptoPP::Integer exponent;
  exponent.OpenPGPDecode(reinterpret_cast<const uint8_t*>(
      key_material.substr(2+modulus_length, 2+exponent_length).c_str()),
                        2+exponent_length);

  CryptoPP::RSAFunction pk;
  pk.Initialize(modulus, exponent);
  return pk;
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

  CryptoPP::RSAFunction pk = ReadRSAPublicKey(pk_packet->key_material());
  CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA1>::Verifier verifier(pk);
  printf("Bits: %d\n", pk.GetModulus().BitCount());

  CryptoPP::NonblockingRng rng;
  printf("Validation: %d\n", pk.Validate(rng, 3));

  for (auto i = packets.begin(); i != packets.end(); i++) {
    std::shared_ptr<parse4880::SignaturePacket> signature_ptr
        = std::dynamic_pointer_cast<parse4880::SignaturePacket>(*i);
    if (nullptr == signature_ptr) {
      continue;
    }

    CryptoPP::PK_MessageAccumulator* acc
        = verifier.NewVerificationAccumulator();
    //std::unique_ptr<CryptoPP::SHA1> acc(new CryptoPP::SHA1);
    std::string message = to_verify;

    const std::string& signature_hashed = signature_ptr->hashed_data();
    acc->Update(reinterpret_cast<const unsigned char*>(to_verify.c_str()),
                to_verify.length());
    acc->Update(reinterpret_cast<const unsigned char*>(
        signature_hashed.c_str()),
                signature_hashed.length());
    message += signature_hashed;

    uint8_t trailer[2] = {0x04, 0xFF};
    acc->Update(trailer, 2);
    message += std::string(reinterpret_cast<const char*>(trailer), 2);

    acc->Update(reinterpret_cast<const unsigned char*>(
        parse4880::WriteInteger(signature_hashed.length(), 4).c_str()), 4);
    message += parse4880::WriteInteger(signature_hashed.length(), 4);
    //acc->Update(reinterpret_cast<const uint8_t*>(message.c_str()), message.length());
    //unsigned char digest[CryptoPP::SHA1::DIGESTSIZE];
    //acc->Final(digest);
    //printf("%02x %02x\n", digest[0], digest[1]);

    CryptoPP::Integer signature_int;
    signature_int.OpenPGPDecode(reinterpret_cast<const uint8_t*>(
        signature_ptr->signature().c_str()),
                                signature_ptr->signature().length());

    CryptoPP::Integer recovered_digest
        = pk.ApplyFunction(signature_int);
    std::cout << "Recovered: " << std::hex <<  recovered_digest << std::endl;

    verifier.InputSignature(*acc,
                            reinterpret_cast<const uint8_t*>(
                                signature_ptr->signature().substr(2).c_str()),
                            signature_ptr->signature().length()-2);

    //uint8_t expected[2] = {0x89, 0x13};
    //printf("Verification: %d\n", acc->TruncatedVerify(expected, 2));
    printf("Verification: %d\n", verifier.Verify(acc));
    printf("Upfront: %d\n", verifier.SignatureUpfront());

    parse4880::RSAKey key(*pk_packet);
    std::unique_ptr<parse4880::VerificationContext> ctx =
        key.GetVerificationContext(*signature_ptr);
    ctx->Update(to_verify);
    printf("Verification: %d\n", ctx->Verify());
  }
  
  return 0;
}
