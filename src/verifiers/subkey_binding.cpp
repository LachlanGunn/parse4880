// Copyright 2016 Lachlan Gunn

#include "verify.h"
#include "packet.h"
#include "keys/key.h"
#include "parser.h"

namespace parse4880 {

bool verify_subkey_binding(const PublicKeyPacket&    key_packet,
                           const PublicSubkeyPacket& subkey_packet,
                           const SignaturePacket&    signature) {
  std::unique_ptr<Key> key = Key::ParseKey(key_packet);

  std::unique_ptr<VerificationContext> ctx =
      key->GetVerificationContext(signature);

  ctx->Update("\x99");
  ctx->Update(WriteInteger(key_packet.contents().length(), 2));
  ctx->Update(key_packet.contents());
  
  ctx->Update("\x99");
  ctx->Update(WriteInteger(subkey_packet.contents().length(), 2));
  ctx->Update(subkey_packet.contents());

  return ctx->Verify(); // FIXME: We need to verify the subpacket.
}

}  // namespace parse4880
