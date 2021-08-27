#ifndef MOBILELIBLELANTUS_LELANTUS_H
#define MOBILELIBLELANTUS_LELANTUS_H

#include "../src/coin.h"
#include <list>

lelantus::PrivateCoin CreateMintScript(uint64_t value, unsigned char* keydata, int32_t index, uint160 seedID, std::vector<unsigned char>& script);

uint64_t EstimateJoinSplitFee(uint64_t spendAmound, bool subtractFeeFromAmount, std::list<lelantus::CLelantusEntry> coinsl, std::vector<lelantus::CLelantusEntry>& coinsToBeSpent, uint64_t& changeToMint);

lelantus::PrivateCoin CreateMintPrivateCoin(uint64_t value, unsigned char* keydata, int32_t index, uint32_t& keyPathOut);

lelantus::PrivateCoin CreateJMintScriptFromPrivateCoin(lelantus::PrivateCoin coin, uint64_t value, uint160 seedID, unsigned char* AESkeydata, std::vector<unsigned char>& script);

void CreateJoinSplit(
        const uint256& txHash,
        const lelantus::PrivateCoin& Cout,
        const uint64_t& Vout,
        const uint64_t& fee,
        const std::vector<lelantus::CLelantusEntry>& coinsToBeSpent,
        const std::map<uint32_t, std::vector<lelantus::PublicCoin>>& anonymity_sets,
        const std::vector<std::vector<unsigned char>>& anonymity_set_hashes,
        const std::map<uint32_t, uint256>& groupBlockHashes,
        std::vector<uint8_t>& script);

#endif //MOBILELIBLELANTUS_LELANTUS_H
