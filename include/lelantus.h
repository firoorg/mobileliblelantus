#ifndef MOBILELIBLELANTUS_LELANTUS_H
#define MOBILELIBLELANTUS_LELANTUS_H

#include "../src/coin.h"
#include <list>

void SetTestnet(bool isTestnet_);

lelantus::PrivateCoin CreateMintScript(uint64_t value, unsigned char* keydata, int32_t index, uint160 seedID, std::vector<unsigned char>& script, bool isTestnet_ = false);

uint256 CreateMintTag(unsigned char* keydata, int32_t index, uint160 seedID, bool isTestnet_ = false);

uint64_t EstimateJoinSplitFee(uint64_t spendAmound, bool subtractFeeFromAmount, std::list<lelantus::CLelantusEntry> coinsl, std::vector<lelantus::CLelantusEntry>& coinsToBeSpent, uint64_t& changeToMint);

lelantus::PrivateCoin CreateMintPrivateCoin(uint64_t value, unsigned char* keydata, int32_t index, uint32_t& keyPathOut, bool isTestnet_ = false);

uint32_t GenerateAESKeyPath(const std::string& serializedCoin);

lelantus::PrivateCoin CreateJMintScriptFromPrivateCoin(lelantus::PrivateCoin coin, uint64_t value, uint160 seedID, unsigned char* AESkeydata, std::vector<unsigned char>& script, bool isTestnet_ = false);

void CreateJoinSplit(
        const uint256& txHash,
        const lelantus::PrivateCoin& Cout,
        const uint64_t& Vout,
        const uint64_t& fee,
        const std::vector<lelantus::CLelantusEntry>& coinsToBeSpent,
        const std::map<uint32_t, std::vector<lelantus::PublicCoin>>& anonymity_sets,
        const std::vector<std::vector<unsigned char>>& anonymity_set_hashes,
        const std::map<uint32_t, uint256>& groupBlockHashes,
        std::vector<uint8_t>& script, bool isTestnet_ = false);

void DecryptMintAmount(unsigned char* keydata, const std::vector<unsigned char>& encryptedValue, uint64_t& amount);

#endif //MOBILELIBLELANTUS_LELANTUS_H
