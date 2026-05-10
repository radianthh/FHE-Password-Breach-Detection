#include "server.h"
#include "../utils/utils.h"
#include <fstream>
#include <iostream>

using namespace seal;
using namespace std;

Server::Server(SEALContext& context) : context_(context) {}

// 유출 DB 파일을 줄 단위로 읽어 각 비밀번호를 hashPassword()로 변환해 저장
// 서버는 해시값만 보관하고 평문 비밀번호는 메모리에 남기지 않음
void Server::loadDB(const string& filepath) {
    ifstream file(filepath);
    string password;
    while (getline(file, password)) {
        if (!password.empty())
            db_.push_back(hashPassword(password));
    }
    cout << "[Server] DB 로드 완료: " << db_.size() << "개" << endl;
}

// 방법 1: 각 DB 항목에 대해 Enc(hash_user - hash_db[i]) 계산
// 서버는 암호화된 상태로만 연산 → 비교 결과(0 여부)를 직접 알 수 없음
vector<Ciphertext> Server::computeDiffs(const Ciphertext& enc_user, Evaluator& evaluator) {
    vector<Ciphertext> diffs;
    diffs.reserve(db_.size()); // 벡터 공간 확보
    for (uint64_t hash_db : db_) {
        Ciphertext diff = enc_user;                    // 암호문 복사
        Plaintext plain_db(toHex(hash_db));
        evaluator.sub_plain_inplace(diff, plain_db);   // FHE 상태에서 평문 뺄셈
        diffs.push_back(std::move(diff));              // 복사 비용 제거
    }
    return diffs;
}

// 방법 2: 페르마 소정리 기반 SIMD 배치 비교
// 원리: 소수 p=65537에서 x^(p-1) mod p → x=0이면 0, x≠0이면 1 (페르마 소정리)
// SIMD로 DB 전체를 슬롯에 묶어 단 하나의 암호문으로 일괄 처리
Ciphertext Server::computeFermat(const Ciphertext& enc_user_batch, Evaluator& evaluator, 
    const RelinKeys& relin_keys) {
    BatchEncoder encoder(context_);
    size_t slot_count = encoder.slot_count();

    // DB 해시를 슬롯에 순서대로 채움 (DB < slot_count이면 나머지는 0으로 패딩)
    vector<uint64_t> db_slots(slot_count, 0);
    for (size_t i = 0; i < db_.size() && i < slot_count; i++)
        db_slots[i] = db_[i];

    Plaintext plain_db;
    encoder.encode(db_slots, plain_db);

    // 각 슬롯: diff_i = hash_user - db[i] (FHE 상태, 전 슬롯 동시 연산)
    Ciphertext result = enc_user_batch;
    evaluator.sub_plain_inplace(result, plain_db);

    // diff^65536 = diff^(2^16): 16번 제곱으로 계산
    // 매 제곱 후 재선형화(relinearize)해 암호문 크기(noise)를 줄임
    for (int i = 0; i < 16; i++) {
        evaluator.square_inplace(result); // 암호문을 자기 자신과 곱해서 제곱하는 함수
        evaluator.relinearize_inplace(result, relin_keys); // 곱셈 후 암호문 크기를 다시 줄이는 역할
    }
    return result;
}
