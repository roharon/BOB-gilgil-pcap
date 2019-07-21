cmake_minimum_required(VERSION 3.14)
project(pcap_find C)

set(CMAKE_C_STANDARD 11)

add_compile_options(-lpcap)
target_compile_options(pcap_find -lpcap)

add_executable(pcap_find main.c)