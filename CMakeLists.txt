cmake_minimum_required(VERSION 3.16)

project(FHE-Password-Breach-Detection)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(OPENSSL_ROOT_DIR /opt/homebrew/opt/openssl@3)

find_package(SEAL CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(fhe_pwd main.cpp utils.cpp server.cpp)

target_link_libraries(fhe_pwd PRIVATE SEAL::seal_shared OpenSSL::Crypto)
target_include_directories(fhe_pwd PRIVATE /opt/homebrew/opt/openssl@3/include)