#include "utils.h"
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>

// 문자열 → SHA256 → 정수 변환
uint64_t hashPassword(const string& password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)password.c_str(), password.size(), hash);

    // 앞 8바이트만 uint64_t로 변환
    uint64_t result = 0;
    for (int i = 0; i < 8; i++) {
        result = (result << 8) | hash[i];
    }
    return result % 65537; // plain_modulus 크기 때문에 mod 연산 적용
}

// 정수 → hex 문자열 (SEAL Plaintext용)
string toHex(uint64_t val) {
    stringstream ss;
    ss << hex << val;
    return ss.str();
}