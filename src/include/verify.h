// Copyright 2016 Lachlan Ginn

#ifndef PARSE4880_SRC_INCLUDE_VERIFY_H_
#define PARSE4880_SRC_INCLUDE_VERIFY_H_

#include "packet.h"
#include "keys/key.h"

namespace parse4880 {

/**
 * Verify a key-to-UID binding.
 */
bool verify_uid_binding(const PublicKeyPacket& key, const UserIDPacket& uid,
                        const Key& attester, const SignaturePacket& signature);

/**
 * Verify a key-to-subkey binding.
 *
 * @return 0 if verification failed,
 *         1 if the subkey binding was verified,
 *         2 if the subkey and a primary-key binding were verified.
 */
int verify_subkey_binding(const PublicKeyPacket&    key,
                          const PublicSubkeyPacket& subkey,
                          const SignaturePacket&    signature);

}  // namespace parse4880

#endif  // PARSE4880_SRC_INCLUDE_VERIFY_H_
