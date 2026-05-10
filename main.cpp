#include "client/client.h"
#include "server/server.h"
#include "utils/utils.h"
#include "methods/subtraction.h"
#include "methods/fermat.h"
#include <iostream>
#include <chrono>
#include <string>
#include <sstream>
#include <iomanip>

using namespace std;
using namespace chrono;

static string fmtDuration(double ms) {
    ostringstream oss;
    oss << fixed << setprecision(2);
    if (ms >= 1000.0) oss << ms / 1000.0 << " s";
    else oss << ms << " ms";
    return oss.str();
}

// 대화형 모드: 두 방법을 순서대로 실행하고 결과·시간을 비교 출력
static void runInteractive(const string& password) {
    uint64_t hash_user = hashPassword(password);

    // ── 방법 1: 뺄셈 기반 ─────────────────────────────────────────────
    // poly_modulus_degree=4096: 슬롯 불필요, noise budget이 작아도 단순 뺄셈에 충분
    cout << "\n=== 방법 1: 뺄셈 기반 (poly_modulus_degree=4096) ===" << endl;
    Client client1(4096);
    Server server1(client1.context());
    server1.loadDB(DB_PATH);

    auto t1_start = high_resolution_clock::now();
    int result1 = runSubtraction(client1, server1, hash_user);
    auto t1_end   = high_resolution_clock::now();
    double ms1 = duration_cast<microseconds>(t1_end - t1_start).count() / 1000.0;

    // ── 방법 2: 페르마 소정리 기반 ────────────────────────────────────
    // poly_modulus_degree=32768: BFVDefault(32768)≈881 bits → 16회 제곱 후 약 425 bits 잔존
    cout << "\n=== 방법 2: 페르마 소정리 기반 (poly_modulus_degree=32768, SIMD) ===" << endl;
    Client client2(32768);
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
    cout << "[방법1] 소요 시간: " << fmtDuration(ms1) << endl;

    cout << "[방법2] ";
    if (result2 >= 0) cout << "유출된 비밀번호! (DB " << result2 + 1 << "번째 항목)" << endl;
    else cout << "안전합니다." << endl;
    cout << "[방법2] 소요 시간: " << fmtDuration(ms2) << endl;

    cout << "\n[검증] 두 방법 결과 ";
    if (result1 == result2) cout << "일치" << endl;
    else cout << "불일치!" << endl;
}

int main() {
    string password;
    cout << "비밀번호를 입력하세요: ";
    cin >> password;
    runInteractive(password);
    return 0;
}
