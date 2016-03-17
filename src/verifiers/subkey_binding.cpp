// Copyright 2016 Lachlan Gunn

#include <algorithm>
#include <list>

#include "verify.h"
#include "packet.h"
#include "keys/key.h"
#include "parser.h"
#include "exceptions.h"

namespace parse4880 {

namespace {

void UpdateContextWithKey(VerificationContext& ctx, const PublicKeyPacket& key) {
  ctx.Update("\x99");
  ctx.Update(WriteInteger(key.contents().length(), 2));
  ctx.Update(key.contents());
}

}  // namespace

int verify_subkey_binding(const PublicKeyPacket&    key_packet,
                           const PublicSubkeyPacket& subkey_packet,
                           const SignaturePacket&    signature) {
  // First we need to get the primary key out of the packet.
  std::unique_ptr<Key> key = Key::ParseKey(key_packet);

  // Next, we validate the top-level signature.
  std::unique_ptr<VerificationContext> ctx =
      key->GetVerificationContext(signature);

  UpdateContextWithKey(*ctx, key_packet);
  UpdateContextWithKey(*ctx, subkey_packet);

  int verifies = ctx->Verify();

  // The first signature having been validated, we need to check for and
  // validate the second binding signature.
  const std::list<std::shared_ptr<PGPPacket>>& subpackets = signature.subpackets();
  auto subsignature_iterator =
      std::find_if(subpackets.begin(), subpackets.end(),
                   [](const std::shared_ptr<PGPPacket>& x) -> bool {
                     return (x->tag() == 32);
                   });

  if (subsignature_iterator != subpackets.end()) {
    try {
      std::unique_ptr<Key> subkey = Key::ParseKey(subkey_packet);
      SignaturePacket subsignature_packet((**subsignature_iterator).contents());
      std::unique_ptr<VerificationContext> ctx_subsignature =
          subkey->GetVerificationContext(subsignature_packet);
      UpdateContextWithKey(*ctx_subsignature, key_packet);
      UpdateContextWithKey(*ctx_subsignature, subkey_packet);

      // We should signal somehow a verification failure.
      verifies += ctx_subsignature->Verify();
    } catch(parse4880::parse4880_error e) {
      return verifies;
    }
  }

  return verifies;
}

}  // namespace parse4880
