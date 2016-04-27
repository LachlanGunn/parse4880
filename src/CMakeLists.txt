INCLUDE_DIRECTORIES(include)

SET(PARSE4880_SOURCES
  common/parser.cpp common/packet.cpp common/exceptions.cpp
  packets/signature.cpp packets/unknownpacket.cpp packets/keymaterial.cpp
  packets/userid.cpp
  keys/key.cpp keys/rsakey.cpp
  verifiers/uid_binding.cpp verifiers/subkey_binding.cpp)

ADD_LIBRARY(parse4880 ${PARSE4880_SOURCES})
TARGET_LINK_LIBRARIES(parse4880 ${MBEDCRYPTO_LIBRARIES})

ADD_EXECUTABLE(parsepgp applications/main.cpp)
TARGET_LINK_LIBRARIES(parsepgp parse4880)

ADD_EXECUTABLE(verify applications/verify.cpp)
TARGET_LINK_LIBRARIES(verify parse4880)

ADD_EXECUTABLE(bindings applications/bindings.cpp)
TARGET_LINK_LIBRARIES(bindings parse4880)

ADD_EXECUTABLE(runtests ${PARSE4880_SOURCES})
TARGET_LINK_LIBRARIES(runtests ${MBEDCRYPTO_LIBRARIES} gtest_main)
TARGET_COMPILE_DEFINITIONS(runtests PRIVATE INCLUDE_TESTS)
#SET_TARGET_PROPERTIES(runtests PROPERTIES COMPILE_OPTIONS "")

GET_TARGET_PROPERTY(TESTPROPS runtests COMPILE_FLAGS)
MESSAGE("Options: ${TESTPROPS}")
