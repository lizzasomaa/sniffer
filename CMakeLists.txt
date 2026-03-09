cmake_minimum_required(VERSION 3.10)
project(sniffer C)

set(CMAKE_C_STANDARD 11)

find_package(Threads REQUIRED)
find_library(PCAP_LIB pcap REQUIRED)

set(SOURCES
    parser.c
    process.c
    live_process.c
    queue.c
    tcp_sessions.c
    ftp.c
)

add_executable(sniffer ${SOURCES})

target_link_libraries(sniffer Threads::Threads ${PCAP_LIB})
