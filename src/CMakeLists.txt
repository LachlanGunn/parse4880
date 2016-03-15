INCLUDE_DIRECTORIES(include)

ADD_LIBRARY(parse4880
  parser.cpp packet.cpp exceptions.cpp
  packets/signature.cpp packets/unknownpacket.cpp packets/keymaterial.cpp
  packets/userid.cpp
  keys/key.cpp keys/rsakey.cpp)
TARGET_LINK_LIBRARIES(parse4880 ${CRYPTOPP_LIBRARIES})

ADD_EXECUTABLE(parsepgp main.cpp)
TARGET_LINK_LIBRARIES(parsepgp parse4880)

ADD_EXECUTABLE(verify verify.cpp)
TARGET_LINK_LIBRARIES(verify parse4880)

ADD_EXECUTABLE(bindings bindings.cpp)
TARGET_LINK_LIBRARIES(bindings parse4880)
