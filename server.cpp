#include "server.h"
#include "utils.h"
#include <fstream>
#include <iostream>

Server::Server(SEALContext& context) : context_(context) {}

void Server::loadDB(const string& filepath) {
    ifstream file(filepath);
    string password;
    while (getline(file, password)) {
        if (!password.empty()) {
            db_.push_back(hashPassword(password));
        }
    }
    cout << "[Server] DB 로드 완료: " << db_.size() << "개" << endl;
}

int Server::compare(Ciphertext& enc_user, Decryptor& decryptor, Evaluator& evaluator) {
    for (int i = 0; i < (int)db_.size(); i++) {
        Ciphertext enc_copy = enc_user;
        Plaintext plain_db(toHex(db_[i]));
        evaluator.sub_plain_inplace(enc_copy, plain_db);

        Plaintext result;
        decryptor.decrypt(enc_copy, result);

        int diff = stoi(result.to_string(), nullptr, 16);
        if (diff == 0) return i;
    }
    return -1;
}