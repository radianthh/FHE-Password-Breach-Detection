#pragma once
#include "seal/seal.h"
#include <cstdint>
#include <memory>
#include <vector>

// 클라이언트: 비밀번호 해시를 암호화해서 서버에 넘기고, 서버 결과를 복호화해 판별
// 비밀키는 클라이언트만 보유 → 서버는 평문을 볼 수 없음
class Client {
public:
    // poly_modulus_degree: 다항식 차수 (클수록 슬롯·보안 증가, 연산 느려짐)
    // 방법1 → 4096, 방법2(SIMD) → 32768
    explicit Client(size_t poly_modulus_degree = 32768);

    // 방법 1용: 단일 값 암·복호화 (DB 항목 수만큼 개별 암호문 생성)
    seal::Ciphertext encrypt(uint64_t val);
    uint64_t decrypt(const seal::Ciphertext& ct);

    // 방법 2용: SIMD 배칭 - 모든 슬롯에 val을 복제해 한 번에 암호화 / 복호화
    // poly_modulus_degree=32768 → 슬롯 수 16384개
    seal::Ciphertext encryptBatch(uint64_t val);
    std::vector<uint64_t> decryptBatch(const seal::Ciphertext& ct);

    size_t slotCount() const;

    const seal::PublicKey& publicKey() const { return public_key_; }
    // relinKeys: 암호문끼리 곱셈 후 크기가 커지는 것을 원래대로 줄이는 키 (재선형화)
    const seal::RelinKeys& relinKeys() const { return relin_keys_; }
    seal::SEALContext& context() { return context_; }

private:
    seal::SEALContext context_;   // BFV 파라미터 묶음
    seal::SecretKey secret_key_;  // 복호화 전용, 클라이언트만 보관
    seal::PublicKey public_key_;  // 암호화 전용, 서버에 공유 가능
    seal::RelinKeys relin_keys_;  // 곱셈 후 재선형화용, 서버에 전달
    std::unique_ptr<seal::Encryptor> encryptor_;
    std::unique_ptr<seal::Decryptor> decryptor_;
    std::unique_ptr<seal::BatchEncoder> encoder_; // SIMD 슬롯 인코딩/디코딩
};
