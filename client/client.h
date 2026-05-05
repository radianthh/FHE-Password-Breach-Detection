#pragma once
#include "seal/seal.h"
#include <cstdint>
#include <memory>

// 클라이언트: 키 관리, 암·복호화 담당
class Client {
public:
    // deep_mult=true: 16회 제곱 연산용 custom coeff_modulus (보안레벨 없음, 데모 전용)
    explicit Client(size_t poly_modulus_degree, bool deep_mult = false);

    seal::Ciphertext encrypt(uint64_t val);
    uint64_t decrypt(const seal::Ciphertext& ct);

    const seal::PublicKey& publicKey() const { return public_key_; }
    const seal::RelinKeys& relinKeys() const { return relin_keys_; }
    seal::SEALContext& context() { return context_; }

private:
    seal::SEALContext context_;
    seal::SecretKey secret_key_;
    seal::PublicKey public_key_;
    seal::RelinKeys relin_keys_;
    std::unique_ptr<seal::Encryptor> encryptor_;
    std::unique_ptr<seal::Decryptor> decryptor_;
};
