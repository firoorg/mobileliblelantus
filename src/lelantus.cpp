#include "coin.h"
#include "schnorr_prover.h"
#include "challenge_generator_impl.h"
#include "joinsplit.h"
#include "../bitcoin/streams.h"
#include "../bitcoin/hash.h"
#include "../bitcoin/amount.h"
#include "../bitcoin/crypto/hmac_sha512.h"
#include "../bitcoin/crypto/aes.h"
#include "../bitcoin/utilstrencodings.h"

#include <list>

#define LELANTUS_TX_TPAYLOAD                47
#define OP_LELANTUSMINT                     0xc5
#define OP_LELANTUSJMINT                    0xc6
#define DEFAULT_TX_CONFIRM_TARGET           6
#define LELANTUS_INPUT_LIMIT_PER_TRANSACTION            50
#define LELANTUS_VALUE_SPEND_LIMIT_PER_TRANSACTION     (5001 * COIN)

static const CAmount DEFAULT_FALLBACK_FEE = 20000;
static const int PROTOCOL_VERSION = 90030;

using namespace lelantus;

void SetTestnet(bool isTestnet_) {
    isTestnet = isTestnet_;
    lelantus::Params::get_default();
}

void GenerateMintSchnorrProof(const lelantus::PrivateCoin& coin, CDataStream&  serializedSchnorrProof)
{
    auto params = lelantus::Params::get_default();

    SchnorrProof schnorrProof;

    SchnorrProver schnorrProver(params->get_g(), params->get_h0(), true);
    Scalar v = coin.getVScalar();
    secp_primitives::GroupElement commit = coin.getPublicCoin().getValue();
    secp_primitives::GroupElement comm = commit + (params->get_h1() * v.negate());

    unique_ptr<ChallengeGenerator> challengeGenerator = std::make_unique<ChallengeGeneratorImpl<CHash256>>(1);

    // commit (G^s*H1^v*H2^r), comm (G^s*H2^r), and H1^v are used in challenge generation if nLelantusFixesStartBlock is passed
    schnorrProver.proof(coin.getSerialNumber(), coin.getRandomness(), comm, commit, (params->get_h1() * v), challengeGenerator, schnorrProof);

    serializedSchnorrProof << schnorrProof;
}

PrivateCoin CreateMintScript(uint64_t value, unsigned char* keydata, int32_t index, uint160 seedID, std::vector<unsigned char>& script) {
    auto* params = Params::get_default();
    PrivateCoin coin(params, value, BIP44MintData(keydata, index), LELANTUS_TX_TPAYLOAD);

    // Get a copy of the 'public' portion of the coin. You should
    // embed this into a Lelantus 'MINT' transaction along with a series of currency inputs
    auto &pubCoin = coin.getPublicCoin();

    if (!pubCoin.validate()) {
        throw std::runtime_error("Unable to mint a lelantus coin.");
    }


    script.push_back((unsigned char)OP_LELANTUSMINT);

    // and this one will write the size in different byte lengths depending on the length of vector. If vector size is <0.4c, which is 76, will write the size of vector in just 1 byte. In our case the size is always 34, so must write that 34 in 1 byte.
    std::vector<unsigned char> vch = pubCoin.getValue().getvch();
    script.insert(script.end(), vch.begin(), vch.end()); //this uses 34 byte

    // generating schnorr proof
    CDataStream serializedSchnorrProof(SER_NETWORK, PROTOCOL_VERSION);
    GenerateMintSchnorrProof(coin, serializedSchnorrProof);
    script.insert(script.end(), serializedSchnorrProof.begin(), serializedSchnorrProof.end()); //this uses 98 byte

    auto pubcoin = pubCoin.getValue() + lelantus::Params::get_default()->get_h1() * Scalar(value).negate();
    uint256 hashPub = primitives::GetPubCoinValueHash(pubcoin);
    CDataStream ss(SER_GETHASH, 0);
    ss << hashPub;
    ss << seedID;
    uint256 hashForRecover = Hash(ss.begin(), ss.end());

    CDataStream serializedHash(SER_NETWORK, 0);
    serializedHash << hashForRecover;

    script.insert(script.end(), serializedHash.begin(), serializedHash.end());

    return coin;
}

uint256 CreateMintTag(unsigned char* keydata, int32_t index, uint160 seedID) {
    auto* params = Params::get_default();
    PrivateCoin coin(params, 0, BIP44MintData(keydata, index), LELANTUS_TX_TPAYLOAD);

    uint256 hashPub = primitives::GetPubCoinValueHash(coin.getPublicCoin().getValue());
    CDataStream ss(SER_GETHASH, 0);
    ss << hashPub;
    ss << seedID;
    return Hash(ss.begin(), ss.end());
}

template<typename Iterator>
static uint64_t CalculateLelantusCoinsBalance(Iterator begin, Iterator end) {
    uint64_t balance(0);
    for (auto start = begin; start != end; start++) {
        balance += start->amount;
    }
    return balance;
}

bool GetCoinsToJoinSplit(
        uint64_t required,
        std::vector<lelantus::CLelantusEntry>& coinsToSpend_out,
        uint64_t& changeToMint,
        std::list<lelantus::CLelantusEntry> coins)
{
    if (required > LELANTUS_VALUE_SPEND_LIMIT_PER_TRANSACTION) {
        return false;
    }

    uint64_t availableBalance = CalculateLelantusCoinsBalance(coins.begin(), coins.end());

    if (required > availableBalance) {
        return false;
    }

    // sort by biggest amount. if it is same amount we will prefer the older block
    auto comparer = [](const lelantus::CLelantusEntry& a, const lelantus::CLelantusEntry& b) -> bool {
        return a.amount != b.amount ? a.amount > b.amount : a.nHeight < b.nHeight;
    };
    coins.sort(comparer);

    uint64_t spend_val(0);

    std::list<lelantus::CLelantusEntry> coinsToSpend;

    while (spend_val < required) {
        if(coins.empty())
            break;

        lelantus::CLelantusEntry choosen;
        uint64_t need = required - spend_val;

        auto itr = coins.begin();
        if(need >= itr->amount) {
            choosen = *itr;
            coins.erase(itr);
        } else {
            for (auto coinIt = coins.rbegin(); coinIt != coins.rend(); coinIt++) {
                auto nextItr = coinIt;
                nextItr++;

                if (coinIt->amount >= need && (nextItr == coins.rend() || nextItr->amount != coinIt->amount)) {
                    choosen = *coinIt;
                    coins.erase(std::next(coinIt).base());
                    break;
                }
            }
        }

        spend_val += choosen.amount;
        coinsToSpend.push_back(choosen);
    }

    // sort by group id ay ascending order. it is mandatory for creting proper joinsplit
    auto idComparer = [](const lelantus::CLelantusEntry& a, const lelantus::CLelantusEntry& b) -> bool {
        return a.id < b.id;
    };
    coinsToSpend.sort(idComparer);

    changeToMint = spend_val - required;
    coinsToSpend_out.insert(coinsToSpend_out.begin(), coinsToSpend.begin(), coinsToSpend.end());

    return true;
}

uint64_t EstimateJoinSplitFee(uint64_t spendAmount, bool subtractFeeFromAmount, std::list<lelantus::CLelantusEntry> coins, std::vector<lelantus::CLelantusEntry>& coinsToBeSpent, uint64_t& changeToMint) {
    uint64_t fee;
    unsigned size;

    for (fee = 0;;) {
        uint64_t currentRequired = spendAmount;

        if (!subtractFeeFromAmount)
            currentRequired += fee;

        coinsToBeSpent.clear();
        changeToMint = 0;

        if (!GetCoinsToJoinSplit(currentRequired, coinsToBeSpent, changeToMint, coins)) {
            return 0;
        }

        // 1054 is constant part, mainly Schnorr and Range proofs, 2560 is for each sigma/aux data
        // 179 other parts of tx, assuming 1 utxo and 1 jmint
        size = 1054 + 2560 * coinsToBeSpent.size() + 180;
        //        uint64_t feeNeeded = GetMinimumFee(size, DEFAULT_TX_CONFIRM_TARGET);
        uint64_t feeNeeded = size; //TODO(Levon) temporary, use real estimation methods here

        if (fee >= feeNeeded) {
            break;
        }

        fee = feeNeeded;

        if(subtractFeeFromAmount)
            break;
    }

    return fee;
}

std::vector<unsigned char> EncryptMintAmount(unsigned char* keydata, uint64_t amount, const secp_primitives::GroupElement& pubcoin) {
    std::vector<unsigned char> key(CHMAC_SHA512::OUTPUT_SIZE);
    CHMAC_SHA512(keydata, 32).Finalize(&key[0]);
    AES256Encrypt enc(key.data());
    std::vector<unsigned char> ciphertext(16);
    std::vector<unsigned char> plaintext(16);
    memcpy(plaintext.data(), &amount, 8);
    enc.Encrypt(ciphertext.data(), plaintext.data());
    return ciphertext;
}

void DecryptMintAmount(unsigned char* keydata, const std::vector<unsigned char>& encryptedValue, uint64_t& amount) {
    std::vector<unsigned char> key(CHMAC_SHA512::OUTPUT_SIZE);
    CHMAC_SHA512(keydata, 32).Finalize(&key[0]);

    AES256Decrypt dec(key.data());
    std::vector<unsigned char> plaintext(16);
    dec.Decrypt(plaintext.data(), encryptedValue.data());
    memcpy(&amount, plaintext.data(), 8);
}

lelantus::PrivateCoin CreateMintPrivateCoin(uint64_t value, unsigned char* keydata, int32_t index, uint32_t& keyPathOut) {

    auto params = lelantus::Params::get_default();
    PrivateCoin coin(params, value, BIP44MintData(keydata, index), LELANTUS_TX_TPAYLOAD);

    auto &pubCoin = coin.getPublicCoin();

    if (!pubCoin.validate()) {
        throw std::runtime_error("Unable to mint a lelantus coin.");
    }

    CDataStream ss(SER_GETHASH, 0);
    ss << pubCoin.getValue();
    keyPathOut = Hash(ss.begin(), ss.end()).GetFirstUint32();

    return coin;
}

uint32_t GenerateAESKeyPath(const std::string& serializedCoin) {
    GroupElement coin;
    coin.deserialize(ParseHex(serializedCoin).data());

    CDataStream ss(SER_GETHASH, 0);
    ss << coin;
    return Hash(ss.begin(), ss.end()).GetFirstUint32();
}

lelantus::PrivateCoin CreateJMintScriptFromPrivateCoin(
        lelantus::PrivateCoin coin,
        uint64_t value,
        uint160 seedID,
        unsigned char* AESkeydata,
        std::vector<unsigned char>& script) {

    auto &pubCoin = coin.getPublicCoin();
    script.push_back((unsigned char)OP_LELANTUSJMINT);

    std::vector<unsigned char> vch = pubCoin.getValue().getvch();
    script.insert(script.end(), vch.begin(), vch.end());

    std::vector<unsigned char> encryptedValue = EncryptMintAmount(AESkeydata, value, pubCoin.getValue());
    script.insert(script.end(), encryptedValue.begin(), encryptedValue.end());

    auto pubcoin = pubCoin.getValue() +
                   lelantus::Params::get_default()->get_h1() * Scalar(value).negate();
    uint256 hashPub = primitives::GetPubCoinValueHash(pubcoin);
    CDataStream ss(SER_GETHASH, 0);
    ss << hashPub;
    ss << seedID;
    uint256 hashForRecover = Hash(ss.begin(), ss.end());

    CDataStream serializedHash(SER_NETWORK, 0);
    serializedHash << hashForRecover;
    script.insert(script.end(), serializedHash.begin(), serializedHash.end());

    return coin;
}

struct CoinCompare
{
    bool operator()( const std::pair<lelantus::PrivateCoin, uint32_t>& left, const std::pair<lelantus::PrivateCoin, uint32_t>& right ) const {
        return left.second < right.second;
    }
};

void CreateJoinSplit(
        const uint256& txHash,
        const lelantus::PrivateCoin& Cout,
        const uint64_t& Vout,
        const uint64_t& fee,
        const std::vector<lelantus::CLelantusEntry>& coinsToBeSpent,
        const std::map<uint32_t, std::vector<lelantus::PublicCoin>>& anonymity_sets,
        const std::vector<std::vector<unsigned char>>& anonymity_set_hashes,
        const std::map<uint32_t, uint256>& groupBlockHashes,
        std::vector<uint8_t>& script) {

    auto params = lelantus::Params::get_default();

    std::vector<std::pair<lelantus::PrivateCoin, uint32_t>> coins;
    coins.reserve(coinsToBeSpent.size());
    int version = LELANTUS_TX_TPAYLOAD;

    for (const auto &spend : coinsToBeSpent) {
        // construct public part of the mint
        lelantus::PublicCoin pub(spend.value);
        // construct private part of the mint
        lelantus::PrivateCoin priv(params, spend.amount);
        priv.setVersion(version);
        priv.setSerialNumber(spend.serialNumber);
        priv.setRandomness(spend.randomness);
        priv.setEcdsaSeckey(spend.ecdsaSecretKey);
        priv.setPublicCoin(pub);

        // get coin group
        uint32_t groupId = spend.id;
        coins.emplace_back(std::make_pair(priv, groupId));
    }

    std::sort(coins.begin(), coins.end(), CoinCompare());

    lelantus::JoinSplit joinSplit(params, coins, anonymity_sets, anonymity_set_hashes, Vout, {Cout}, fee, groupBlockHashes, txHash, version);

    std::vector<lelantus::PublicCoin>  pCout;
    pCout.emplace_back(Cout.getPublicCoin());

    if (!joinSplit.Verify(anonymity_sets, anonymity_set_hashes, pCout, Vout, txHash)) {
        throw std::runtime_error(("The joinsplit transaction failed to verify"));
    }

    // construct spend script
    CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
    serialized << joinSplit;

    script.insert(script.end(), serialized.begin(), serialized.end());
}
