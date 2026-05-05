#include "fermat.h"
#include <iostream>
#include <vector>

using namespace seal;
using namespace std;

// 페르마 소정리 기반 유출 탐지: diff^(p-1) mod p 결과가 0이면 유출 (p=65537)
int runFermat(Client& client, Server& server, uint64_t hash_user) {
    Evaluator evaluator(client.context());

    Ciphertext enc_user = client.encrypt(hash_user);
    cout << "[방법2][Client] 암호화 완료" << endl;

    cout << "[방법2][Server] 페르마 소정리 연산 중 (16회 제곱)..." << endl;
    vector<Ciphertext> results = server.computeFermat(enc_user, evaluator, client.relinKeys());

    // 복호화 결과 0 → diff=0 (유출), 1 → diff≠0 (안전)
    cout << "[방법2][Client] 복호화 및 판별 중..." << endl;
    for (int i = 0; i < (int)results.size(); i++) {
        if (client.decrypt(results[i]) == 0)
            return i;
    }
    return -1;
}
