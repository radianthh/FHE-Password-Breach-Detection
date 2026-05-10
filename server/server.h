#pragma once
#include "seal/seal.h"
#include <string>
#include <vector>

// 서버: 유출 DB를 해시 목록으로 보관하고, FHE 연산만 수행
// 클라이언트의 비밀번호 평문·해시값을 직접 볼 수 없음
class Server {
public:
    explicit Server(seal::SEALContext& context); // 생성자

    // DB 파일을 줄 단위로 읽어 각 항목을 hashPassword()로 변환해 저장
    void loadDB(const std::string& filepath);

    // 방법 1: DB 항목마다 Enc(hash_user - hash_db[i]) 를 계산해 벡터로 반환
    // 클라이언트가 복호화 후 0 여부로 일치 확인
    std::vector<seal::Ciphertext> computeDiffs(
        const seal::Ciphertext& enc_user,
        seal::Evaluator& evaluator);

    // 방법 2: 페르마 소정리 기반 SIMD 배칭
    // DB 전체를 슬롯에 묶고 diff^65536 을 계산 → 슬롯값이 0이면 일치
    seal::Ciphertext computeFermat(
        const seal::Ciphertext& enc_user_batch,
        seal::Evaluator& evaluator,
        const seal::RelinKeys& relin_keys);

    size_t dbSize() const { return db_.size(); }

private:
    seal::SEALContext& context_; // FHE 파라미터 정보를 담은 객체, 레퍼런스로 받아서 복사 X, Client가 만든 것 공유
    std::vector<uint64_t> db_; // 유출 DB의 해시값 목록 (mod 65537)
};
