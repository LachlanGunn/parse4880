INCLUDE_DIRECTORIES(include)

ADD_LIBRARY(parse4880
  common/parser.cpp common/packet.cpp common/exceptions.cpp
  packets/signature.cpp packets/unknownpacket.cpp packets/keymaterial.cpp
  packets/userid.cpp
  keys/key.cpp keys/rsakey.cpp
  verifiers/uid_binding.cpp verifiers/subkey_binding.cpp)
TARGET_LINK_LIBRARIES(parse4880 ${MBEDCRYPTO_LIBRARIES})

ADD_EXECUTABLE(parsepgp applications/main.cpp)
TARGET_LINK_LIBRARIES(parsepgp parse4880)

ADD_EXECUTABLE(verify applications/verify.cpp)
TARGET_LINK_LIBRARIES(verify parse4880)

ADD_EXECUTABLE(bindings applications/bindings.cpp)
TARGET_LINK_LIBRARIES(bindings parse4880)

ADD_EXECUTABLE(runtests tests/integers.cpp)
TARGET_LINK_LIBRARIES(runtests parse4880 gtest_main)
