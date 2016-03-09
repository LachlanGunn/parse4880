#ifndef PARSE4880_INCLUDE_PACKET_H_
#define PARSE4880_INCLUDE_PACKET_H_

/**
 * @file packet.h
 *
 * Parent header file for all packet types.
 */

#include <cstdint>
#include <string>
#include <memory>
#include <list>

#include "packets/pgppacket.h"
#include "packets/unknownpacket.h"
#include "packets/signature.h"
#include "packets/keymaterial.h"
#include "packets/userid.h"

#endif  // PARSE4880_INCLUDE_PACKET_H_
