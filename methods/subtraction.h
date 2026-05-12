#pragma once
#include "../client/client.h"
#include "../server/server.h"
#include <cstdint>

// 방법 1: 뺄셈 기반, 일치하는 DB 인덱스 반환, 없으면 -1
int runSubtraction(Client& client, Server& server, uint64_t hash_user);
