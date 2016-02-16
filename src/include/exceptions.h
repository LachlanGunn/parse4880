#ifndef PARSE4880_INCLUDE_EXCEPTIONS_H_
#define PARSE4880_INCLUDE_EXCEPTIONS_H_

#include <boost/format.hpp>

using boost::format;

namespace parse4880 {

class format_error : public std::runtime_error {
 public:
  format_error(std::size_t position);
  format_error(std::size_t position, std::string error);

  std::size_t position();
  
 private:
  std::size_t position_;
};

class invalid_header_error : public format_error {
 public:
  invalid_header_error(std::size_t position);
};

class packet_length_error : public format_error {
 public:
  packet_length_error(std::size_t position,
                      std::size_t claimed_length,
                      std::size_t actual_length);
 private:
  std::size_t claimed_length_;
  std::size_t actual_length_;
};

class old_packet_error : public format_error {
 public:
  old_packet_error(std::size_t position);
};

class unsupported_feature_error : public format_error {
 public:
  unsupported_feature_error(std::size_t position, std::string feature);
 private:
  std::string feature_;
};

}

#endif  // PARSE4880_INCLUDE_EXCEPTIONS_H_
