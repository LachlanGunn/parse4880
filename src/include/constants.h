#ifndef PARSE4880_INCLUDE_CONSTANTS_H
#define PARSE4880_INCLUDE_CONSTANTS_H

namespace parse4880 {
  
enum PublicKeyAlgorithmCodes {
  kPublicKeyRSAEncryptOrSign = 1,
  kPublicKeyRSAEncryptOnly   = 2,
  kPublicKeyRSASignOnly      = 3,
  kPublicKeyElGamal          = 16,
  kPublicKeyDSA              = 17  
};

enum HashAlgorithmCodes {
  kHashMD5 = 1,
  kHashSHA1 = 2,
  kHashRIPEMD160 = 3,
  kHashSHA256 = 8,
  kHashSHA384 = 9,
  kHashSHA512 = 10,
  kHashSHA224 = 11
};

}

#endif  // PARSE4880_INCLUDE_CONSTANTS_H
