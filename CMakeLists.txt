cmake_minimum_required(VERSION 3.16)

project(FHE-Password-Breach-Detection)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(OPENSSL_ROOT_DIR /opt/homebrew/opt/openssl@3)

find_package(SEAL CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(fhe_pwd
    main.cpp
    utils/utils.cpp
    client/client.cpp
    server/server.cpp
    methods/subtraction.cpp
    methods/fermat.cpp
)

target_compile_definitions(fhe_pwd PRIVATE
    DB_PATH="${CMAKE_SOURCE_DIR}/data/breach_db.txt"
)

target_link_libraries(fhe_pwd PRIVATE SEAL::seal_shared OpenSSL::Crypto)

target_include_directories(fhe_pwd PRIVATE
    ${CMAKE_SOURCE_DIR}
    /opt/homebrew/opt/openssl@3/include
)
