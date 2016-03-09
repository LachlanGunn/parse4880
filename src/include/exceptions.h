#ifndef PARSE4880_INCLUDE_EXCEPTIONS_H_
#define PARSE4880_INCLUDE_EXCEPTIONS_H_

/**
 * @file exceptions.h
 *
 * Exception types.
 */

/**
 * @addtogroup Exceptions
 *
 * @{
 */

#include <boost/format.hpp>

using boost::format;

namespace parse4880 {

/**
 * Base class for all Parse4880 exceptions.
 */
class parse4880_error {};

/**
 * Base class for all parsing errors.
 */
class format_error : public parse4880_error, public std::runtime_error {
 public:
  /**
   * Construct an error without further explanation.
   *
   * @param position  The position in the file at which the error occurred.
   */
  format_error(std::size_t position);

  /**
   * Construct an error with a textual explanation.
   *
   * @param position  The position in the file at which the error occurred.
   * @param error     A human-readable description of the error.
   */
  format_error(std::size_t position, std::string error);

  /**
   * The position at which the error occured.
   *
   * @return The offset from the beginning of the file at which the
   *         error was found.
   */
  std::size_t position();
  
 private:
  std::size_t position_;
};

/**
 * Errors relating to errors in the packet header.
 *
 * @todo We have used this as a catch-all, we need to do something.
 */
class invalid_header_error : public format_error {
 public:
  /**
   * Constructor.
   *
   * @param position  The position at which the error occurred.
   */
  invalid_header_error(std::size_t position);
};

/**
 * Errors in which the packet is shorter than demanded by its
 * length fields.
 */
class packet_length_error : public format_error {
 public:
  /**
   * Constructor.
   *
   * @param position        The position at which the error occurred.
   * @param claimed_length  The length that the packet should be.
   * @param actual_length   How long the packet actually is.
   */
  packet_length_error(std::size_t position,
                      std::size_t claimed_length,
                      std::size_t actual_length);
};

/**
 * A packet type has been used that is no longer supported.
 */
class old_packet_error : public format_error {
 public:
  /**
   * Constructor.
   *
   * @param position  The position at which the error occurred.
   */
  old_packet_error(std::size_t position);
};

/**
 * An unsupported OpenPGP feature has been used.
 */
class unsupported_feature_error : public format_error {
 public:
  /**
   * Constructor.
   *
   * @param position  The position at which the error occurred.
   * @param feature   The feature that has not been implemented.
   */
  unsupported_feature_error(std::size_t position, std::string feature);
 private:
  std::string feature_;
};

/**
 * A miscellaneous error in the packet.
 */
class invalid_packet_error : public format_error {
public:
  /**
   * Constructor.
   *
   * @param problem The problem that occurred.
   */
  invalid_packet_error(std::string problem);
private:
  std::string problem_;
};

/**
 * A mismatch between algorithms used in a public key and a signature.
 */
class wrong_algorithm_error : public parse4880_error, public std::logic_error {
 public:
  /**
   * Constructor.
   */
  wrong_algorithm_error();
};

}

/**
 * @{
 */

 */

#endif  // PARSE4880_INCLUDE_EXCEPTIONS_H_
