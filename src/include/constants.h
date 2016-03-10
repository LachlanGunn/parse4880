#ifndef PARSE4880_INCLUDE_CONSTANTS_H
#define PARSE4880_INCLUDE_CONSTANTS_H

/**
 * @file constants.h
 *
 * Constants from the OpenPGP standard.
 */

namespace parse4880 {

/**
 * Public key algorithm codes from RFC4880.
 */
enum PublicKeyAlgorithmCodes {
  kPublicKeyRSAEncryptOrSign = 1,
  kPublicKeyRSAEncryptOnly   = 2,
  kPublicKeyRSASignOnly      = 3,
  kPublicKeyElGamal          = 16,
  kPublicKeyDSA              = 17  
};

/**
 * Hash algorithm codes from RFC4880.
 */
enum HashAlgorithmCodes {
  kHashMD5 = 1,
  kHashSHA1 = 2,
  kHashRIPEMD160 = 3,
  kHashSHA256 = 8,
  kHashSHA384 = 9,
  kHashSHA512 = 10,
  kHashSHA224 = 11
};

/**
 * Signature type codes from RFC4880.
 */
enum SignatureTypeCodes {
  kSignatureBinary     = 0x00,
  kSignatureText       = 0x01,
  kSignatureStandalone = 0x02,

  kSignatureCertificationGeneric  = 0x10,
  kSignatureCertificationPersona  = 0x11,
  kSignatureCertificationCasual   = 0x12,
  kSignatureCertificationPositive = 0x13,

  kSignatureSubkeyBinding     = 0x18,
  kSignaturePrimaryKeyBinding = 0x19,

  kSignatureKey = 0x1F,

  kSignatureRevocationKey           = 0x20,
  kSignatureRevocationSubkey        = 0x28,
  kSignatureRevocationCertification = 0x30,

  kSignatureTimestamp = 0x40,

  kSignatureThirdPartyConfirmation = 0x50
};

}

#endif  // PARSE4880_INCLUDE_CONSTANTS_H
