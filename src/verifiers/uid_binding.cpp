// Copyright 2016 Lachlan Gunn

#include "verify.h"
#include "packet.h"
#include "keys/key.h"
#include "parser.h"

namespace parse4880 {

bool verify_uid_binding(const PublicKeyPacket& key, const UserIDPacket& uid,
                        const Key& attester, const SignaturePacket& signature) {
  std::unique_ptr<VerificationContext> ctx =
      attester.GetVerificationContext(signature);

  ctx->Update("\x99");
  ctx->Update(WriteInteger(key.contents().length(), 2));
  ctx->Update(key.contents());
  
  ctx->Update("\xB4");
  ctx->Update(WriteInteger(uid.contents().length(), 4));
  ctx->Update(uid.contents());

  return ctx->Verify();
}

}  // namespace parse4880
