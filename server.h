#pragma once
#include "seal/seal.h"
#include <string>
#include <vector>
using namespace std;
using namespace seal;

class Server {
public:
    Server(SEALContext& context);
    void loadDB(const string& filepath);
    int compare(Ciphertext& enc_user, Decryptor& decryptor, Evaluator& evaluator);
private:
    SEALContext& context_;
    vector<uint64_t> db_;
};