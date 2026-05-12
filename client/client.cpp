#include "client.h"
#include "../utils/utils.h"
#include <memory>
#include <vector>

using namespace seal;

// BFV 스킴 파라미터 생성(plain_modulus=65537)
static SEALContext makeContext(size_t poly_modulus_degree) {
    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(65537);
    return SEALContext(parms);
}

// Public key, Secret key, Relinearization key 생성
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

// 단일 값 암호화
Ciphertext Client::encrypt(uint64_t val) {
    Plaintext pt(toHex(val));
    Ciphertext ct;
    encryptor_->encrypt(pt, ct);
    return ct;
}

// 단일 암호문 복호화 -> uint64_t 반환
uint64_t Client::decrypt(const Ciphertext& ct) {
    Plaintext pt;
    decryptor_->decrypt(ct, pt);
    std::string s = pt.to_string();
    if (s == "0") return 0;
    return std::stoull(s, nullptr, 16); // 16진수 문자열 -> 정수(unsigned long long)
}

// SIMD Computation
// slot_count개의 슬롯 전부에 같은 val을 채워 하나의 암호문으로 만듦
Ciphertext Client::encryptBatch(uint64_t val) {
    std::vector<uint64_t> slots(encoder_->slot_count(), val);
    Plaintext pt;
    encoder_->encode(slots, pt);
    Ciphertext ct;
    encryptor_->encrypt(pt, ct);
    return ct;
}

// SIMD Computation -> 슬롯 벡터 반환
// i번째 슬롯 값이 0이면 db[i]와 해시가 일치 -> 유출
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
