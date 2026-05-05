#include "server.h"
#include "../utils/utils.h"
#include <fstream>
#include <iostream>

using namespace seal;
using namespace std;

Server::Server(SEALContext& context) : context_(context) {}

// 유출 DB 파일을 읽어 각 비밀번호를 해시값으로 변환해 저장
void Server::loadDB(const string& filepath) {
    ifstream file(filepath);
    string password;
    while (getline(file, password)) {
        if (!password.empty())
            db_.push_back(hashPassword(password));
    }
    cout << "[Server] DB 로드 완료: " << db_.size() << "개" << endl;
}

// 방법 1: 암호화된 상태로 Enc(hash_user - db[i]) 를 각 항목마다 계산
vector<Ciphertext> Server::computeDiffs(
    const Ciphertext& enc_user,
    Evaluator& evaluator)
{
    vector<Ciphertext> diffs;
    // db_ size만큼 벡터 공간 미리 확보
    diffs.reserve(db_.size());
    for (uint64_t hash_db : db_) {
        Ciphertext diff = enc_user;
        Plaintext plain_db(toHex(hash_db));
        evaluator.sub_plain_inplace(diff, plain_db); // FHE 상태에서 평문 뺄셈
        diffs.push_back(std::move(diff)); // diff 복사 대신 이동 move 사용해서 불필요한 복사 비용 제거
    }
    return diffs;
}

// 방법 2: diff^(p-1) 계산. diff=0이면 0, 아니면 1 (페르마 소정리, p=65537)
vector<Ciphertext> Server::computeFermat(
    const Ciphertext& enc_user,
    Evaluator& evaluator,
    const RelinKeys& relin_keys)
{
    vector<Ciphertext> results;
    results.reserve(db_.size());
    for (uint64_t hash_db : db_) {
        // diff = Enc(hash_user - db[i])
        Ciphertext result = enc_user;
        Plaintext plain_db(toHex(hash_db));
        evaluator.sub_plain_inplace(result, plain_db);

        // diff^65536 = diff^(2^16): 16번 제곱 반복
        // diff=0 → 0^65536=0 (유출), diff≠0 → diff^65536=1 mod 65537 (페르마 소정리)
        for (int i = 0; i < 16; i++) {
            evaluator.square_inplace(result);
            evaluator.relinearize_inplace(result, relin_keys); // 암호문 크기 복원
        }
        results.push_back(std::move(result));
    }
    return results;
}
