#pragma once
#include <string>
using namespace std;

uint64_t hashPassword(const string& password);
string toHex(uint64_t val);