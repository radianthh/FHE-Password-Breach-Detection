#pragma once
#include "seal/seal.h"
#include <string>
#include <vector>

// 서버: DB 관리 및 FHE 연산 담당 (비밀번호 평문 없이 암호화 상태로 비교)
class Server {
public:
    explicit Server(seal::SEALContext& context);

    void loadDB(const std::string& filepath);

    // 방법 1: Enc(hash_user - db[i]) 반환
    std::vector<seal::Ciphertext> computeDiffs(
        const seal::Ciphertext& enc_user,
        seal::Evaluator& evaluator);

    // 방법 2: Enc((hash_user - db[i])^(p-1)) 반환
    std::vector<seal::Ciphertext> computeFermat(
        const seal::Ciphertext& enc_user,
        seal::Evaluator& evaluator,
        const seal::RelinKeys& relin_keys);

private:
    seal::SEALContext& context_;
    std::vector<uint64_t> db_; // 유출 DB의 해시값 목록
};
