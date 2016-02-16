#include <stdexcept>

#include <boost/format.hpp>

#include "exceptions.h"

namespace parse4880 {

format_error::format_error(std::size_t position)
    : std::runtime_error((format(
          "Packet error at position %1%.") % position).str()),
      position_(position) {}

format_error::format_error(std::size_t position, std::string error)
    : std::runtime_error((format(
          "Packet error at position %1%: %2%.") % position % error).str()),
      position_(position) {}


std::size_t format_error::position() {
  return position_;
}

invalid_header_error::invalid_header_error(std::size_t position)
    : format_error(position, "invalid packet header") {}

packet_length_error::packet_length_error(std::size_t position,
                                         std::size_t claimed_length,
                                         std::size_t actual_length)
    : format_error(position,
                   (format("expected %1% bytes, but only %2% remain.")
                    % claimed_length % actual_length ).str()),
      claimed_length_(claimed_length),
      actual_length_(actual_length) {}

old_packet_error::old_packet_error(std::size_t position)
    : format_error(position, "unsupported old-format packet found") {}

unsupported_feature_error::unsupported_feature_error(
    std::size_t position, std::string feature)
    : format_error(position, (format("%1% not supported") % feature).str()),
      feature_(feature) {}

}
