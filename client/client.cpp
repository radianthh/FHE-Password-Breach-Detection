#include "client.h"
#include "../utils/utils.h"
#include <memory>
#include <vector>

using namespace seal;

// BFV 암호화 파라미터를 설정하고 SEALContext를 생성
static SEALContext makeContext(size_t poly_modulus_degree, bool deep_mult) {
    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    if (deep_mult) {
        // BFVDefault(8192)은 약 5-6레벨만 지원. 16회 제곱을 위해 custom coeff_modulus 사용.
        // 10 × 60비트 = 600비트: noise budget ≈ 583비트, 16레벨 후 약 100비트 여유.
        parms.set_coeff_modulus(CoeffModulus::Create(
            poly_modulus_degree, {60, 60, 60, 60, 60, 60, 60, 60, 60, 60}));
        parms.set_plain_modulus(65537);
        // 보안 레벨 검사 비활성화 (데모 전용)
        return SEALContext(parms, true, sec_level_type::none);
    }
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(65537);
    return SEALContext(parms);
}

// 키 생성 및 암·복호화 객체 초기화
Client::Client(size_t poly_modulus_degree, bool deep_mult)
    : context_(makeContext(poly_modulus_degree, deep_mult))
{
    KeyGenerator keygen(context_);
    secret_key_ = keygen.secret_key();
    keygen.create_public_key(public_key_);
    keygen.create_relin_keys(relin_keys_); // 재선형화 키 (제곱 후 암호문 크기 줄이기용)
    encryptor_ = std::make_unique<Encryptor>(context_, public_key_);
    decryptor_ = std::make_unique<Decryptor>(context_, secret_key_);
}

// 해시값을 16진수 평문으로 변환 후 암호화
Ciphertext Client::encrypt(uint64_t val) {
    Plaintext pt(toHex(val));
    Ciphertext ct;
    encryptor_->encrypt(pt, ct);
    return ct;
}

// 암호문을 복호화해 uint64_t로 반환
uint64_t Client::decrypt(const Ciphertext& ct) {
    Plaintext pt;
    decryptor_->decrypt(ct, pt);
    std::string s = pt.to_string();
    if (s == "0") return 0;
    return std::stoull(s, nullptr, 16);
}
