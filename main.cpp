#include "client/client.h"
#include "server/server.h"
#include "utils/utils.h"
#include "methods/subtraction.h"
#include "methods/fermat.h"
#include <iostream>
#include <chrono>
#include <string>

using namespace std;
using namespace chrono;

static void runInteractive(const string& password) {
    uint64_t hash_user = hashPassword(password);

    // ── 방법 1: 뺄셈 기반 (poly_modulus_degree=4096) ──────────────────
    cout << "\n=== 방법 1: 뺄셈 기반 (poly_modulus_degree=4096) ===" << endl;
    Client client1(4096);
    Server server1(client1.context());
    server1.loadDB(DB_PATH);

    auto t1_start = high_resolution_clock::now();
    int result1 = runSubtraction(client1, server1, hash_user);
    auto t1_end   = high_resolution_clock::now();
    double ms1 = duration_cast<microseconds>(t1_end - t1_start).count() / 1000.0;

    // ── 방법 2: 페르마 소정리 기반 (poly_modulus_degree=8192) ──────────
    cout << "\n=== 방법 2: 페르마 소정리 기반 (poly_modulus_degree=8192) ===" << endl;
    Client client2(8192, true); // deep_mult=true: 16회 제곱용 custom coeff_modulus
    Server server2(client2.context());
    server2.loadDB(DB_PATH);

    auto t2_start = high_resolution_clock::now();
    int result2 = runFermat(client2, server2, hash_user);
    auto t2_end   = high_resolution_clock::now();
    double ms2 = duration_cast<microseconds>(t2_end - t2_start).count() / 1000.0;

    // ── 결과 비교 출력 ──────────────────────────────────────────────────
    cout << "\n========== 결과 비교 ==========" << endl;

    cout << "[방법1] ";
    if (result1 >= 0) cout << "유출된 비밀번호! (DB " << result1 + 1 << "번째 항목)" << endl;
    else cout << "안전합니다." << endl;
    cout << "[방법1] 소요 시간: " << ms1 << " ms" << endl;

    cout << "[방법2] ";
    if (result2 >= 0) cout << "유출된 비밀번호! (DB " << result2 + 1 << "번째 항목)" << endl;
    else cout << "안전합니다." << endl;
    cout << "[방법2] 소요 시간: " << ms2 << " ms" << endl;

    cout << "\n[검증] 두 방법 결과 ";
    if (result1 == result2) cout << "일치" << endl;
    else cout << "불일치!" << endl;
}

// CLI 인자로 비밀번호를 받으면 JSON 출력 (FastAPI 연동용)
// 인자 없으면 대화형 모드
int main(int argc, char* argv[]) {
    if (argc >= 2) {
        string password = argv[1];
        uint64_t hash_user = hashPassword(password);

        Client client1(4096);
        Server server1(client1.context());
        server1.loadDB(DB_PATH);
        auto t1s = high_resolution_clock::now();
        int r1 = runSubtraction(client1, server1, hash_user);
        double ms1 = duration_cast<microseconds>(high_resolution_clock::now() - t1s).count() / 1000.0;

        Client client2(8192, true);
        Server server2(client2.context());
        server2.loadDB(DB_PATH);
        auto t2s = high_resolution_clock::now();
        int r2 = runFermat(client2, server2, hash_user);
        double ms2 = duration_cast<microseconds>(high_resolution_clock::now() - t2s).count() / 1000.0;

        // FastAPI가 파싱할 JSON (stderr 로그와 분리되도록 stdout에만 출력)
        cout << "{"
             << "\"sub_result\":"     << r1   << ","
             << "\"sub_ms\":"         << ms1  << ","
             << "\"fermat_result\":"  << r2   << ","
             << "\"fermat_ms\":"      << ms2
             << "}" << endl;
        return 0;
    }

    // 대화형 모드
    string password;
    cout << "비밀번호를 입력하세요: ";
    cin >> password;
    runInteractive(password);
    return 0;
}
