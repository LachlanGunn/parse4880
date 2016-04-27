CMAKE_MINIMUM_REQUIRED(VERSION 2.8.0)

PROJECT(Parse4880)

IF(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  IF(CMAKE_CXX_COMPILER_VERSION VERSION_GREATER 4.6)
    SET(GCC_CXX_STD "c++11")
  ELSE()
    SET(GCC_CXX_STD "c++0x")
  ENDIF()
  SET(CMAKE_CXX_FLAGS
    "${CMAKE_CXX_FLAGS} -std=${GCC_CXX_STD} -Wall -Werror -Wextra -pedantic -g -Wno-sign-compare -Wno-unused-parameter -Wno-missing-field-initializers")
ELSEIF(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  SET(CMAKE_CXX_FLAGS
    "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -Wextra -Werror -ftemplate-depth=1024 -Wunreachable-code -Wimplicit-fallthrough -Wno-missing-field-initializers -g")
ENDIF()

# Boost
FIND_PACKAGE(Boost REQUIRED)
INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIRS})

# MbedTLS
FIND_LIBRARY(MBEDCRYPTO_LIBRARIES mbedcrypto)
IF(NOT MBEDCRYPTO_LIBRARIES)
  MESSAGE(SEND_ERROR "Could not find MbedCrypto")
ENDIF(NOT MBEDCRYPTO_LIBRARIES)

# GTest
# FIXME: This should be more portable
SUBDIRS(/usr/src/gtest)

# Doxygen
FIND_PACKAGE(Doxygen)
IF(DOXYGEN_FOUND)
  CONFIGURE_FILE(
    ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in
    ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)

  FILE(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/doc)
  ADD_CUSTOM_TARGET(doc
    ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/doc
    COMMENT "Generating API documentation with Doxygen" VERBATIM
    )
ENDIF(DOXYGEN_FOUND)


SUBDIRS(src)
