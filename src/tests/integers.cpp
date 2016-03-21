#include <gtest/gtest.h>

#include <parser_types.h>
#include <parser.h>

TEST(ScalarNumbers, RoundTrip) {
  for (int length = 1; length < 4; length++) {
    for (uint64_t i = 0; i < (1<<(length*8))+1; i++) {
      ASSERT_EQ(i, parse4880::ReadInteger(parse4880::WriteInteger(i, 8)));
    }
  }
}
