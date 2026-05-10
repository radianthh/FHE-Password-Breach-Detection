#include "fermat.h"
#include <iostream>
#include <vector>

using namespace seal;
using namespace std;

// 방법 2: 페르마 소정리 + SIMD 배칭 기반 유출 탐지
// 흐름: 클라이언트가 모든 슬롯에 hash_user 복제 → 서버가 diff^65536 일괄 계산
//        → 클라이언트가 복호화 후 슬롯[i]=0이면 db[i]와 일치
// 장점: 단 하나의 암호문 연산으로 DB 전체를 동시에 비교 (방법1보다 스케일링에 유리)
int runFermat(Client& client, Server& server, uint64_t hash_user) {
    Evaluator evaluator(client.context());

    // 1. 클라이언트: 모든 슬롯에 hash_user를 채워 배치 암호화
    //    슬롯 i에 hash_user가 들어 있어 서버의 db[i]와 슬롯 단위로 비교됨
    Ciphertext enc_user = client.encryptBatch(hash_user);
    cout << "[방법2][Client] 배치 암호화 완료 (슬롯 수: " << client.slotCount() << ")" << endl;

    // 2. 서버: diff_i = hash_user - db[i] 계산 후 diff^65536 적용 (전 슬롯 동시)
    cout << "[방법2][Server] 페르마 소정리 배치 연산 중 (16회 제곱)..." << endl;
    Ciphertext result = server.computeFermat(enc_user, evaluator, client.relinKeys());

    // 3. 클라이언트: 배치 복호화 후 DB 크기만큼 슬롯 확인
    //    slots[i] == 0이면 diff_i == 0, 즉 hash_user == db[i] → 유출
    cout << "[방법2][Client] 배치 복호화 및 판별 중..." << endl;
    vector<uint64_t> slots = client.decryptBatch(result);
    for (int i = 0; i < (int)server.dbSize(); i++) {
        if (slots[i] == 0)
            return i; // i번째 DB 항목과 일치
    }
    return -1; // DB에 없으면 안전
}
