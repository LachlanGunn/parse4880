CMAKE_MINIMUM_REQUIRED(VERSION 2.8.0)

PROJECT(Parse4880)

IF(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  SET(CMAKE_CXX_FLAGS
    "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -Werror -Wextra -pedantic -g -Wno-sign-compare -Wno-unused-parameter")
ELSEIF(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  SET(CMAKE_CXX_FLAGS
    "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -Wextra -Werror -ftemplate-depth=1024 -Wunreachable-code -Wimplicit-fallthrough -g")
ENDIF()

# Boost
FIND_PACKAGE(Boost REQUIRED)
INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIRS})

# Crypto++
FIND_LIBRARY(CRYPTOPP_LIBRARIES crypto++)
IF(NOT CRYPTOPP_LIBRARIES)
  MESSAGE(SEND_ERROR "Could not find Crypto++")
ENDIF(NOT CRYPTOPP_LIBRARIES)

SUBDIRS(src)
