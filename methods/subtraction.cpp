#include "subtraction.h"
#include <iostream>
#include <vector>

using namespace seal;
using namespace std;

// 방법 1: 뺄셈 기반 유출 탐지
// DB 항목 수만큼 암호문을 개별 처리
int runSubtraction(Client& client, Server& server, uint64_t hash_user) {
    Evaluator evaluator(client.context());

    // 클라이언트: 해시값을 단일 암호문으로 암호화
    Ciphertext enc_user = client.encrypt(hash_user);
    cout << "[방법1][Client] 암호화 완료" << endl;

    // 서버: 각 DB 항목에 대해 Enc(hash_user - db[i]) 계산
    cout << "[방법1][Server] 뺄셈 연산 중" << endl;
    vector<Ciphertext> diffs = server.computeDiffs(enc_user, evaluator);

    // 3. 클라이언트: 각 암호문 복호화 -> 0이면 hash_user == db[i] -> 유출
    cout << "[방법1][Client] 복호화 및 판별 중" << endl;
    for (int i = 0; i < (int)diffs.size(); i++) {
        if (client.decrypt(diffs[i]) == 0)
            return i;
    }
    return -1;
}
