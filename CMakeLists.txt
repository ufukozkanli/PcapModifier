cmake_minimum_required(VERSION 3.7)

project(PcapSample)
set (CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR})

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES
         pcapWriter.cpp)
find_package(PCAP REQUIRED)

add_executable(PcapSample ${SOURCE_FILES} ${PCAP_INCLUDE_DIR})
target_link_libraries(PcapSample
        ${CMAKE_DL_LIBS}
        ${PCAP_LIBRARIES}
)