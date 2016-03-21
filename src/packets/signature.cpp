#include <memory>
#include <list>

#include "boost/format.hpp"

#include "parser_types.h"
#include "packet.h"
#include "exceptions.h"
#include "parser.h"

namespace parse4880 {

/**
 * @todo Copy the creation time.
 * @todo Copy the quick-check field.
 */
SignaturePacket::SignaturePacket(ustring packet_data)
    : PGPPacket(packet_data) {
  // We need to parse a signature subpacket.  This could be either
  // a v3 or v4 signature, so we need to check first and switch on that.
  if (packet_data.length() < 1) {
    throw invalid_header_error(-1);
  }
  version_ = packet_data.at(0);
  if (version_ == 3) {
    // A version three signature packet has the following:
    //
    // [1] Version
    // [1] Length of hashed material
    // [1]   Signature type
    // [4]   Creation time
    // [8] Key ID
    // [1] Public-key algorithm
    // [1] Hash algorithm
    // [2] Left sixteen-most bits of hash value
    // [?] Signature
    //
    // This adds up to nineteen bytes plus the signature.
    if (packet_data.length() < 19) {
      throw invalid_header_error(-1);
    }

    // There should always be five bytes of hashed material, so check
    // that the provided length is correct.
    if (5 != packet_data.at(1)) {
      throw invalid_header_error(-1);
    }

    // We already know that the remainder of the data is there, so
    // we can just go ahead and copy it.

    // Signature type (byte 2)
    signature_type_ = packet_data.at(2);

    // TODO: Copy the creation time (bytes 3--6)

    // Key ID (bytes 7--14)
    key_id_ = packet_data.substr(7,8).c_str();

    // Algorithms (bytes 14--15)
    public_key_algorithm_ = packet_data.at(15);
    hash_algorithm_ = packet_data.at(16);

    // TODO: Copy the hash quick-check field (bytes 17--18)

    // The rest of the packet is the signature.
    signature_ = packet_data.substr(19);

    // Finally, save the signature data to be hashed.
    hashed_data_ = packet_data.substr(2, 5);
  }
  else if(version_ == 4) {
    // A version four signature has the following:
    //
    //   [1] Version number
    //   [1] Signature type
    //   [1] Public-key algorithm
    //   [1] Hash algorithm
    //   [2] Hashed subpacket data count
    //     [?] Hashed subpacket data
    //   [2] Unhashed subpacket data count
    //     [?] Unhashed subpacket data
    //   [2] Left sixteen bits of hash value
    //   [?] Signature

    if (packet_data.length() < 10) {
      throw invalid_header_error(0);
    }

    signature_type_       = packet_data.at(1);
    public_key_algorithm_ = packet_data.at(2);
    hash_algorithm_       = packet_data.at(3);

    size_t hashed_data_count = ReadInteger(packet_data.substr(4,2));
    if (packet_data.length() < 10+hashed_data_count) {
      throw invalid_header_error(1);
    }
    hashed_subpacket_data_ = packet_data.substr(6, hashed_data_count);
    subpackets_ = parse_subpackets(hashed_subpacket_data_);

    hashed_data_ = packet_data.substr(0, 6+hashed_data_count);

    size_t unhashed_data_count =
        ReadInteger(packet_data.substr(6+hashed_data_count, 2));

    if (packet_data.length() < 10+hashed_data_count+unhashed_data_count) {
      throw invalid_header_error(2);
    }
    unhashed_subpacket_data_ =
        packet_data.substr(6+hashed_data_count+2, unhashed_data_count);

    subpackets_.splice(subpackets_.end(),
                       parse_subpackets(unhashed_subpacket_data_));

    // TODO: Left sixteen bits

    signature_ = packet_data.substr(6 + hashed_data_count
                                    + 2 + unhashed_data_count + 2);
  }
  else {
    throw unsupported_feature_error(-1, "non-v3/v4 signatures");
  }

  SetSignaturePropertiesFromSubpackets();
}

uint8_t SignaturePacket::tag() const {
  return 2;
}

std::string SignaturePacket::str() const {
  char uid_string[17]; // Flawfinder: ignore (uids have known length)
  const unsigned char* unsigned_key_id =
      reinterpret_cast<const unsigned char*>(key_id_.c_str());
  snprintf(uid_string, 17, "%02x%02x%02x%02x%02x%02x%02x%02x",
           unsigned_key_id[0], unsigned_key_id[1], unsigned_key_id[2],
           unsigned_key_id[3], unsigned_key_id[4], unsigned_key_id[5],
           unsigned_key_id[6], unsigned_key_id[7]);
  return (boost::format("Signature, version %d, type 0x%02x, "
                        "uid %s")
          % static_cast<int>(version_)
          % static_cast<int>(signature_type_)
          % uid_string).str();
}

uint8_t SignaturePacket::version() const {
  return version_;
}

uint8_t SignaturePacket::signature_type() const {
  return signature_type_;
}

uint8_t SignaturePacket::public_key_algorithm() const {
  return public_key_algorithm_;
}

uint8_t SignaturePacket::hash_algorithm() const {
  return hash_algorithm_;
}

const ustring& SignaturePacket::hashed_subpacket_data() const {
  return hashed_subpacket_data_;
}

const ustring& SignaturePacket::unhashed_subpacket_data() const {
  return unhashed_subpacket_data_;
}

const uint8_t* SignaturePacket::hash_left_16bits() const {
  return hash_left_16bits_;
}

const ustring& SignaturePacket::signature() const {
  return signature_;
}

const ustring& SignaturePacket::key_id() const {
  return key_id_;
}

void SignaturePacket::SetSignaturePropertiesFromSubpackets() {
  const std::list<std::shared_ptr<PGPPacket>>& subpackets = this->subpackets();
  for (auto current_subpacket_ptr  = subpackets.begin();
            current_subpacket_ptr != subpackets.end();
            current_subpacket_ptr++) {
    // FIXME: This is bad.
    std::shared_ptr<UnknownPGPPacket> subpacket =
        std::dynamic_pointer_cast<UnknownPGPPacket>(*current_subpacket_ptr);

    if (nullptr == subpacket) {
      continue;
    }

    if (16 == subpacket->tag()) {
      ustring subpacket_key_id = subpacket->contents();
      if (8 != subpacket_key_id.length()) {
        throw invalid_packet_error(
            "Signature issuer subpacket has wrong length.");
      }
      key_id_ = subpacket_key_id;
    }
  }
}

const ustring& SignaturePacket::hashed_data() const {
  return hashed_data_;
}

}
