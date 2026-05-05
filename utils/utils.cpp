#include "utils.h"
#include <openssl/sha.h>
#include <sstream>

// SHA-256 해시의 상위 8바이트를 uint64_t로 읽은 뒤 평문 모듈러스(65537)로 mod
uint64_t hashPassword(const std::string& password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(password.c_str()), password.size(), hash);
    uint64_t result = 0;
    // 32바이트 중 상위 8바이트를 꺼내서 result 저장 후, 65537 범위로 축소
    for (int i = 0; i < 8; i++)
        result = (result << 8) | hash[i];
    return result % 65537; // BFV의 plain_modulus -> 65537
}

// uint64_t를 SEAL 평문 형식(16진수 문자열)으로 변환
// SEAL의 Plaintext는 16진수 문자열을 입력을 받기 때문
std::string toHex(uint64_t val) {
    std::ostringstream ss;
    ss << std::hex << val;
    return ss.str();
}