#pragma once
#include "../client/client.h"
#include "../server/server.h"
#include <cstdint>

// 방법 2: 페르마 소정리 기반. 일치하는 DB 인덱스 반환, 없으면 -1
int runFermat(Client& client, Server& server, uint64_t hash_user);
