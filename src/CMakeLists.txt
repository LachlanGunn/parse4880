INCLUDE_DIRECTORIES(include)

ADD_LIBRARY(parse4880 parser.cpp packet.cpp exceptions.cpp)

ADD_EXECUTABLE(parsepgp main.cpp)
TARGET_LINK_LIBRARIES(parsepgp parse4880)
