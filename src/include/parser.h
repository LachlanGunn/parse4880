#ifndef PARSE4880_INCLUDE_PARSER_H_
#define PARSE4880_INCLUDE_PARSER_H_

/**
 * @file parser.h
 *
 * Parser for PGP binary format.
 */

#include <list>
#include <memory>
#include <string>

#include "packet.h"
#include "parser_types.h"

/**
 * Namespace for all library functionality.
 */
namespace parse4880 {

/**
 * Parse a series of PGP packets.
 *
 * Here we parse a series of PGP packets, as occurs in a standard
 * PGP binary file.  Recognised packets will have their respective
 * classes generated, other packets will result in the emission of
 * an UnknownPGPPacket.
 *
 * @param data  The binary data to be parsed.
 *
 * @return A list of shared_ptr<PGPPacket>s to each of the packets
 *         in the provided data.
 *
 * @see PGPPacket
 * @see parse4880::parse_subpackets()
 */
std::list<std::shared_ptr<PGPPacket>> parse(ustring data);

/**
 * Parse a series of signature subpackets.
 *
 * The parse_subpackets function parses a series of signature
 * subpackets, yielding a list of shared_ptr<PGPPacket>s to UnknownPGPPackets.
 *
 * Signature packets contain a series of subpackets that have a somewhat
 * different format to the usual one:
 *
 *   - New-style length (no partials)
 *     + Tag
 *     + Data
 *   - New-style length (no partials)
 *     + Tag
 *     + Data
 *   - ...
 *
 * We thus require a different parser.
 *
 * @param data  The binary data to be parsed.
 *
 * @return A list of shared_ptr<PGPPacket>s to each of the subpackets in
 *         the provided data.
 *
 * @see parse4880::parse()
 */
std::list<std::shared_ptr<PGPPacket>> parse_subpackets(ustring data);

/**
 * Read a PGP normal integer.
 *
 * @param encoded_integer  The encoded integer.
 *
 * @return The integer value contained in the encoded string.
 */
uint64_t    ReadInteger(ustring encoded_integer);

/**
 * Encode an integer into PGP format.
 *
 * @param value   The value to encode.
 * @param length  The length of the integer format to be used.
 *
 * @return The encoded form of the provided integer.
 */
ustring WriteInteger(uint64_t value, uint8_t length);

}

#endif  // PARSE4880_INCLUDE_PARSER_H_
