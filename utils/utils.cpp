#include "utils.h"
#include <openssl/sha.h>
#include <sstream>

// SHA-256(password)의 상위 8바이트를 uint64_t로 조합한 뒤 plain_modulus(65537)로 mod
// 65537 범위로 줄이는 이유: BFV의 평문 공간이 Z_65537이므로 이 범위를 벗어나면 오버플로우
uint64_t hashPassword(const std::string& password) {
    unsigned char hash[SHA256_DIGEST_LENGTH]; // 32바이트
    SHA256(reinterpret_cast<const unsigned char*>(password.c_str()), password.size(), hash); // SHA256 해싱
    uint64_t result = 0;
    for (int i = 0; i < 8; i++)
        result = (result << 8) | hash[i]; // 8비트 왼쪽으로 밀기 + hash 값 채우기
    return result % 65537;
}

// uint64_t → 16진수 문자열 변환
// SEAL의 Plaintext 생성자가 16진수 문자열 요구
std::string toHex(uint64_t val) {
    std::ostringstream ss; // 문자열 스트림
    ss << std::hex << val;
    return ss.str(); // ss 내부 버퍼에 hex로 변환된 문자열 쌓임
}