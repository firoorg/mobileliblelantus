#ifndef MOBILELIBLELANTUS_LELANTUS_H
#define MOBILELIBLELANTUS_LELANTUS_H

#include "../src/coin.h"

lelantus::PrivateCoin CreateMintScript(uint64_t value, unsigned char* keydata, int32_t index, uint160 seedID, std::vector<unsigned char>& script);

#endif //MOBILELIBLELANTUS_LELANTUS_H
