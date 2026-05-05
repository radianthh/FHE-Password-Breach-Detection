#include "subtraction.h"
#include <iostream>
#include <vector>

using namespace seal;
using namespace std;

// 뺄셈 기반 유출 탐지: 서버가 Enc(hash_user - db[i])를 계산하고 클라이언트가 복호화해 0 여부 확인
int runSubtraction(Client& client, Server& server, uint64_t hash_user) {
    Evaluator evaluator(client.context());

    Ciphertext enc_user = client.encrypt(hash_user);
    cout << "[방법1][Client] 암호화 완료" << endl;

    cout << "[방법1][Server] 뺄셈 연산 중..." << endl;
    vector<Ciphertext> diffs = server.computeDiffs(enc_user, evaluator);

    // 복호화 결과가 0이면 hash_user == db[i], 즉 유출된 비밀번호
    cout << "[방법1][Client] 복호화 및 판별 중..." << endl;
    for (int i = 0; i < (int)diffs.size(); i++) {
        if (client.decrypt(diffs[i]) == 0)
            return i;
    }
    return -1;
}
