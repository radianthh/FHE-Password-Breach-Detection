#pragma once
#include <string>
#include <cstdint>

// SHA-256 해시 → uint64_t (mod 65537)
uint64_t hashPassword(const std::string& password);

// uint64_t → 16진수 문자열 (SEAL 평문 입력 형식)
std::string toHex(uint64_t val);
