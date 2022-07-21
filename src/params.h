#ifndef FIRO_LIBLELANTUS_PARAMS_H
#define FIRO_LIBLELANTUS_PARAMS_H

#include "../secp256k1/include/Scalar.h"
#include "../secp256k1/include/GroupElement.h"
#include "../bitcoin/serialize.h"
#include "../bitcoin/amount.h"

using namespace secp_primitives;

namespace lelantus {
static bool isTestnet;

class Params {
public:
    static Params const* get_default();
    const GroupElement& get_g() const;
    const GroupElement& get_h0() const;
    const GroupElement& get_h1() const;
    const std::vector<GroupElement>& get_sigma_h() const;
    const std::vector<GroupElement>& get_bulletproofs_g() const;
    const std::vector<GroupElement>& get_bulletproofs_h() const;
    int get_sigma_n() const;
    int get_sigma_m() const;
    int get_bulletproofs_n() const;
    int get_bulletproofs_max_m() const;
    const Scalar& get_limit_range() const;
    const GroupElement& get_h1_limit_range() const;

    uint64_t nMaxValueLelantusSpendPerTransaction = 5001 * COIN;
    uint64_t nMaxValueLelantusMint = 5001 * COIN;

private:
    Params(const GroupElement& g_sigma_, int n, int m, int n_rangeProof_, int max_m_rangeProof_);

private:
    static std::unique_ptr<Params> instance;
    bool isForTestnet;

    //sigma params
    GroupElement g;
    std::vector<GroupElement> h_sigma;
    int n_sigma;
    int m_sigma;

    //bulletproof params
    int n_rangeProof;
    int max_m_rangeProof;
    std::vector<GroupElement> g_rangeProof;
    std::vector<GroupElement> h_rangeProof;
    Scalar limit_range;
    GroupElement h1_limit_range;
};

} // namespace lelantus

#endif // FIRO_LIBLELANTUS_PARAMS_H
