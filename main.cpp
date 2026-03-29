#include "seal/seal.h"
#include "utils.h"
#include "server.h"
#include <iostream>
using namespace std;
using namespace seal;

int main() {
    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(4096);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(4096));
    parms.set_plain_modulus(65537);

    SEALContext context(parms);
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);

    // 서버 DB 로드
    Server server(context);
    server.loadDB("/Users/sinhohyeon/Documents/FHE-Password-Breach-Detection/data/breach_db.txt");

    // 사용자 비밀번호 입력
    string password;
    cout << "비밀번호를 입력하세요: ";
    cin >> password;

    // 클라이언트: 해시 + 암호화
    uint64_t hash_user = hashPassword(password);
    Plaintext plain_user(toHex(hash_user));
    Ciphertext enc_user;
    encryptor.encrypt(plain_user, enc_user);
    cout << "[Client] 암호화 완료" << endl;

    // 서버: DB와 비교
    cout << "[Server] DB와 비교 중..." << endl;
    int idx = server.compare(enc_user, decryptor, evaluator);

    // 결과 출력
    if (idx >= 0) cout << "유출된 비밀번호입니다! (DB " << idx + 1 << "번째 항목)" << endl;
    else cout << "안전합니다." << endl;

    return 0;

}