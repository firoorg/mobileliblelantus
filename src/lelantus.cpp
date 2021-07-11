#include "coin.h"
#include "schnorr_prover.h"
#include "challenge_generator_impl.h"
#include "../bitcoin/streams.h"
#include "../bitcoin/hash.h"

#define LELANTUS_TX_VERSION_4_5             45
#define OP_LELANTUSMINT                     0xc5

static const int PROTOCOL_VERSION = 90030;

using namespace lelantus;

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
    PrivateCoin coin(params, value, BIP44MintData(keydata, index), LELANTUS_TX_VERSION_4_5);

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
