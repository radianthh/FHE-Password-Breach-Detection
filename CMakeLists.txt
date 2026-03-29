cmake_minimum_required(VERSION 3.16)

project(FHE-Password-Breach-Detection)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(SEAL CONFIG REQUIRED)

add_executable(fhe_pwd main.cpp)

target_link_libraries(fhe_pwd PRIVATE SEAL::seal_shared)