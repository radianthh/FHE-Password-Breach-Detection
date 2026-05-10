#include "client.h"
#include "../utils/utils.h"
#include <memory>
#include <vector>

using namespace seal;

// BFV 스킴 파라미터 생성
// - plain_modulus=65537: 소수이면서 65537 ≡ 1 (mod 2*poly_modulus_degree) 조건 만족
//   → BatchEncoder로 SIMD 슬롯 사용 가능, 페르마 소정리(x^65536 mod 65537) 적용 가능
// - BFVDefault: 해당 차수에 맞는 표준 보안 계수 모듈러스 자동 선택
static SEALContext makeContext(size_t poly_modulus_degree) {
    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(65537);
    return SEALContext(parms);
}

// 생성 시 키 3종 생성: 공개키(암호화), 비밀키(복호화), 재선형화키(곱셈 후 암호문 크기 축소)
Client::Client(size_t poly_modulus_degree)
    : context_(makeContext(poly_modulus_degree))
{
    KeyGenerator keygen(context_);
    secret_key_ = keygen.secret_key();
    keygen.create_public_key(public_key_);
    keygen.create_relin_keys(relin_keys_);
    encryptor_ = std::make_unique<Encryptor>(context_, public_key_);
    decryptor_ = std::make_unique<Decryptor>(context_, secret_key_);
    encoder_   = std::make_unique<BatchEncoder>(context_);
}

// 단일 값 암호화 (방법 1용)
// SEAL Plaintext는 16진수 문자열 형식으로 값을 받음
Ciphertext Client::encrypt(uint64_t val) {
    Plaintext pt(toHex(val));
    Ciphertext ct;
    encryptor_->encrypt(pt, ct);
    return ct;
}

// 단일 암호문 복호화 → uint64_t 반환 (방법 1용)
uint64_t Client::decrypt(const Ciphertext& ct) {
    Plaintext pt;
    decryptor_->decrypt(ct, pt);
    std::string s = pt.to_string();
    if (s == "0") return 0;
    return std::stoull(s, nullptr, 16); // 16진수 문자열 → 정수(unsigned long long)
}

// SIMD 배치 암호화 (방법 2용)
// slot_count개의 슬롯 전부에 같은 val을 채워 하나의 암호문으로 만듦
// → 서버가 단일 연산으로 DB 전체(슬롯마다 항목 1개)와 동시에 비교 가능
Ciphertext Client::encryptBatch(uint64_t val) {
    std::vector<uint64_t> slots(encoder_->slot_count(), val);
    Plaintext pt;
    encoder_->encode(slots, pt);
    Ciphertext ct;
    encryptor_->encrypt(pt, ct);
    return ct;
}

// SIMD 배치 복호화 → 슬롯 벡터 반환 (방법 2용)
// i번째 슬롯 값이 0이면 db[i]와 해시가 일치 → 유출
std::vector<uint64_t> Client::decryptBatch(const Ciphertext& ct) {
    Plaintext pt;
    decryptor_->decrypt(ct, pt);
    std::vector<uint64_t> slots;
    encoder_->decode(pt, slots);
    return slots;
}

size_t Client::slotCount() const {
    return encoder_->slot_count();
}
