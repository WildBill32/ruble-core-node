// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/chainparams.h>

#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <hash.h>
#include <kernel/messagestartchars.h>
#include <logging.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/strencodings.h>
#include <versionbits.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <type_traits>

using namespace util::hex_literals;

namespace {

constexpr int RUBLE_HALVING_INTERVAL{500000};
constexpr CAmount RUBLE_MAINNET_GENESIS_SUBSIDY{50 * COIN};
constexpr CAmount RUBLE_INITIAL_SUBSIDY{100 * COIN};
constexpr int RUBLE_PREMINE_HEIGHT{1};
constexpr CAmount RUBLE_PREMINE_AMOUNT{5000000 * COIN};
constexpr CAmount RUBLE_TAIL_SUBSIDY{COIN / 10};
constexpr int64_t RUBLE_COMBINED_SPACING{180};
constexpr int64_t RUBLE_ORDINARY_SPACING{270};
constexpr int64_t RUBLE_AUXPOW_SPACING{540};
constexpr int64_t RUBLE_ASERT_HALF_LIFE{2 * 60 * 60};
constexpr int32_t RUBLE_AUXPOW_CHAIN_ID{0x5255};
// First mainnet height at which either native PoW or AuxPoW may extend the
// chain. Native PoW remains valid at every height, and the first AuxPoW
// submission remains operationally gated until every production node and
// public wallet has upgraded.
constexpr int RUBLE_MAINNET_AUXPOW_ACTIVATION_HEIGHT{7'000};
constexpr int RUBLE_MAINNET_FINALITY_DEPTH{20};
constexpr uint32_t RUBLE_MAINNET_LAUNCH_TIME{1786213343};
// Calibrated for a minimum combined launch hash rate of 100 TH/s:
// 100e12 hashes/s * 180 seconds / 2^32 ~= difficulty 4,190,899.
constexpr uint32_t RUBLE_MAINNET_INITIAL_BITS{0x1a0400d1};
constexpr int RUBLE_TESTDUMMY_VERSION_BIT{7};

// The two independent mining channels must combine to one expected block
// every 180 seconds: 1/270 + 1/540 = 1/180.
static_assert(
    RUBLE_ORDINARY_SPACING * RUBLE_AUXPOW_SPACING ==
    RUBLE_COMBINED_SPACING * (RUBLE_ORDINARY_SPACING + RUBLE_AUXPOW_SPACING));
static_assert(RUBLE_AUXPOW_SPACING == 2 * RUBLE_ORDINARY_SPACING);
static_assert(IsAuxpowCompatibleVersionBit(RUBLE_TESTDUMMY_VERSION_BIT));

void AssertRubleDeploymentBits(const Consensus::Params& params)
{
    for (const auto& deployment : params.vDeployments) {
        // Keep every configured deployment in the bit range shared by both
        // mining channels. This also protects ALWAYS_ACTIVE deployments from
        // becoming impossible if their activation mode changes later.
        assert(IsAuxpowCompatibleVersionBit(deployment.bit));
    }
}

} // namespace

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.version = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/** Build a zero-allocation genesis block for Ruble's non-main networks. */
static CBlock CreateRubleGenesisBlock(const char* pszTimestamp, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion)
{
    return CreateGenesisBlock(pszTimestamp, CScript() << OP_RETURN, nTime, nNonce, nBits, nVersion, 0);
}

/**
 * Build the finalized Ruble mainnet genesis block. Its 50-RUB output is part
 * of the immutable genesis transaction but, like Bitcoin's genesis output,
 * is not inserted into the spendable UTXO set. The height-1 premine remains a
 * separate consensus-locked allocation.
 */
static CBlock CreateRubleMainnetGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion)
{
    // Spell the em dash as explicit UTF-8 bytes so source/execution charset
    // settings cannot change the immutable genesis transaction.
    const char* pszTimestamp = "Ruble (RUB) Genesis Block " "\xE2\x80\x94" " Built by the community, secured by Bitcoin.";
    const CScript genesisOutputScript = CScript()
        << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"_hex
        << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, RUBLE_MAINNET_GENESIS_SUBSIDY);
}

/**
 * Main network on which people trade goods and services.
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        m_chain_type = ChainType::MAIN;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        // The owner-approved, independently verified native block 1 is the
        // consensus-pinned ASERT launch origin. Mainnet accepts no other
        // direct child of genesis.
        consensus.fRequireLaunchBlock = true;
        consensus.hashLaunchBlock = uint256{
            "00000000000003e4b7526e931b9ba1f5154b9ab13dfd9820fefef03bd1aee192"};
        consensus.nLaunchBlockTime = RUBLE_MAINNET_LAUNCH_TIME;
        consensus.nGenesisSubsidy = RUBLE_MAINNET_GENESIS_SUBSIDY;
        consensus.nSubsidyHalvingInterval = RUBLE_HALVING_INTERVAL;
        consensus.nInitialSubsidy = RUBLE_INITIAL_SUBSIDY;
        consensus.nPremineHeight = RUBLE_PREMINE_HEIGHT;
        consensus.nPremineAmount = RUBLE_PREMINE_AMOUNT;
        // Height 1 is consensus-locked to the owner's finalized public
        // P2WPKH script. Private key material never enters the source tree.
        consensus.vPremineScript = "0014d66945ac0db4a7caf4dc7cb94c0fb0d74bab4098"_hex_v_u8;
        consensus.fRequirePremineScript = true;
        consensus.nTailSubsidy = RUBLE_TAIL_SUBSIDY;

        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 1;
        consensus.MinBIP9WarningHeight = 0; // segwit activation height + miner confirmation window
        // Keep 32 leading zero bits for the fixed-width ASERT arithmetic.
        // The finalized, hard-coded genesis header predates the live ASERT
        // schedule and intentionally uses its own easier 0x1e0ffff0 target.
        consensus.powLimit = uint256{"00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 24 * 60 * 60; // one day
        consensus.nPowTargetSpacing = RUBLE_COMBINED_SPACING;
        consensus.nPowTargetSpacingLegacy = RUBLE_ORDINARY_SPACING;
        consensus.nPowTargetSpacingAuxPow = RUBLE_AUXPOW_SPACING;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.enforce_BIP94 = false;
        consensus.fPowNoRetargeting = false;
        // No AuxPoW block existed before this rule was introduced.  Let the
        // first one establish the independent AuxPoW ASERT clock so dormant
        // wall time cannot trigger a minimum-difficulty catch-up storm.
        consensus.fAuxpowFirstBlockASERTAnchor = true;
        // AuxPoW is consensus-valid only at and after the pinned mainnet
        // boundary. Native PoW remains valid before, at, and after it.
        consensus.nAuxpowActivationHeight = RUBLE_MAINNET_AUXPOW_ACTIVATION_HEIGHT;
        consensus.nRuleChangeActivationThreshold = 432; // 90% of 480
        consensus.nMinerConfirmationWindow = 480; // nPowTargetTimespan / nPowTargetSpacing

        // The half life for the ASERT DAA. For every (nASERTHalfLife) seconds behind schedule the blockchain gets,
        // difficulty is cut in half. Doubled if blocks are ahead of schedule.
        // Two hours gives a new network timely recovery from large hash-rate
        // changes while avoiding a timestamp-driven emergency reset.
        consensus.nASERTHalfLife = RUBLE_ASERT_HALF_LIFE;

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = RUBLE_TESTDUMMY_VERSION_BIT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0;

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        // Permit ordinary short forks while making the launch block and every
        // block buried by 20 successors irreversible for automatic fork
        // choice. The fixed height-1 floor is safe because block 1 is already
        // an exact consensus commitment on mainnet.
        consensus.nFinalityDepth = RUBLE_MAINNET_FINALITY_DEPTH;
        consensus.nFinalityFloorHeight = RUBLE_PREMINE_HEIGHT;

        consensus.nAuxpowChainId = RUBLE_AUXPOW_CHAIN_ID;
        consensus.fStrictChainId = true;

        // The live initial targets are separate consensus parameters, not
        // fields committed by the genesis header. The exact native block 1
        // pinned above establishes the native schedule origin. The first
        // accepted AuxPoW block establishes the AuxPoW schedule origin.
        consensus.asertAnchorParams = Consensus::Params::ASERTAnchor{
            0,                            // genesis
            RUBLE_MAINNET_INITIAL_BITS,   // initial ordinary PoW nBits
            RUBLE_MAINNET_INITIAL_BITS,   // initial AuxPoW nBits
            1784710520,                   // genesis timestamp
        };

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xc1;
        pchMessageStart[1] = 0xc7;
        pchMessageStart[2] = 0x18;
        pchMessageStart[3] = 0x65;
        nDefaultPort = 33888;
        nPruneAfterHeight = 10000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        genesis = CreateRubleMainnetGenesisBlock(1784710520, 582296, 0x1e0ffff0, 1);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"00000c2a6ff6021e6d10fe9a28cf5a652df4a354775e216af2c864de53230b5a"});
        assert(genesis.hashMerkleRoot == uint256{"4c422303101396cf081fc7919c91a6e714f974985ed617d6c53622f4a7a85bca"});

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as an addrfetch if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        // Public Ruble Core bootstrap node. DNS resolves to the independently
        // operated mainnet node listening on the default P2P port (33888).
        vSeeds.emplace_back("pool.rublecore.org");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 60);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 122);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 163);
        // Ruble mainnet uses distinct extended-key versions. These bytes
        // encode as rpub/rprv and prevent accidental Bitcoin-mainnet imports.
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x0b, 0xf2, 0xa6};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x0b, 0xee, 0x6c};

        bech32_hrp = "rub";

        vFixedSeeds.clear();

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                {0, uint256{"00000c2a6ff6021e6d10fe9a28cf5a652df4a354775e216af2c864de53230b5a"}},
            }
        };

        m_assumeutxo_data = {
        };

        chainTxData = ChainTxData{
            .nTime = 0,
            .tx_count = 0,
            .dTxRate = 0,
        };
    }
};

/**
 * Testnet (v3): public test network which is reset from time to time.
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        m_chain_type = ChainType::TESTNET;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = RUBLE_HALVING_INTERVAL;
        consensus.nInitialSubsidy = RUBLE_INITIAL_SUBSIDY;
        consensus.nPremineHeight = -1;
        consensus.nPremineAmount = 0;
        consensus.nTailSubsidy = RUBLE_TAIL_SUBSIDY;

        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 1;
        consensus.MinBIP9WarningHeight = 0; // segwit activation height + miner confirmation window
        consensus.powLimit = uint256{"00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 24 * 60 * 60; // one day
        consensus.nPowTargetSpacing = RUBLE_COMBINED_SPACING;
        consensus.nPowTargetSpacingLegacy = RUBLE_ORDINARY_SPACING;
        consensus.nPowTargetSpacingAuxPow = RUBLE_AUXPOW_SPACING;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.enforce_BIP94 = false;
        consensus.fPowNoRetargeting = false;
        consensus.fAuxpowFirstBlockASERTAnchor = true;
        consensus.nAuxpowActivationHeight = 1;
        consensus.nRuleChangeActivationThreshold = 360; // 75% for testchains
        consensus.nMinerConfirmationWindow = 480; // nPowTargetTimespan / nPowTargetSpacing

        // The half life for the ASERT DAA. For every (nASERTHalfLife) seconds behind schedule the blockchain gets,
        // difficulty is cut in half. Doubled if blocks are ahead of schedule.
        consensus.nASERTHalfLife = RUBLE_ASERT_HALF_LIFE;

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = RUBLE_TESTDUMMY_VERSION_BIT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0;

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        consensus.nAuxpowChainId = RUBLE_AUXPOW_CHAIN_ID;
        consensus.fStrictChainId = true;

        // The live initial targets are separate consensus parameters; block 1
        // starts the live schedule.
        consensus.asertAnchorParams = Consensus::Params::ASERTAnchor{
            0,            // genesis
            0x1d00ffff,   // initial ordinary PoW nBits
            0x1d00ffff,   // initial AuxPoW nBits
            1785196861,   // genesis timestamp
        };

        pchMessageStart[0] = 0x88;
        pchMessageStart[1] = 0x44;
        pchMessageStart[2] = 0x0a;
        pchMessageStart[3] = 0x8a;
        nDefaultPort = 43888;
        nPruneAfterHeight = 10000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        genesis = CreateRubleGenesisBlock(
            "28/Jul/2026 Ruble testnet genesis - community development",
            1785196861, 1452779023, 0x1d00ffff, 1);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"000000002cf445f5ca3e4d4ee118517f86f48b39ae2ddd0239a8e5318acfbf03"});
        assert(genesis.hashMerkleRoot == uint256{"83a3906ec09047cdd26ee860b2f1b2d15625f2697a15ebf9f1e237002176b163"});

        vFixedSeeds.clear();
        vSeeds.clear();

        // Keep standard test-key encodings so upstream Core test vectors and
        // hardware tooling remain usable. Network magic and genesis still
        // make this an entirely separate chain.
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 196);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xcf};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tb";

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                {0, uint256{"000000002cf445f5ca3e4d4ee118517f86f48b39ae2ddd0239a8e5318acfbf03"}},
            }
        };

        m_assumeutxo_data = {
        };

        chainTxData = ChainTxData{
            .nTime = 0,
            .tx_count = 0,
            .dTxRate = 0,
        };
    }
};

/**
 * Testnet (v4): public test network which is reset from time to time.
 */
class CTestNet4Params : public CChainParams {
public:
    CTestNet4Params() {
        m_chain_type = ChainType::TESTNET4;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = RUBLE_HALVING_INTERVAL;
        consensus.nInitialSubsidy = RUBLE_INITIAL_SUBSIDY;
        consensus.nPremineHeight = -1;
        consensus.nPremineAmount = 0;
        consensus.nTailSubsidy = RUBLE_TAIL_SUBSIDY;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 1;
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256{"00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 24 * 60 * 60; // one day
        consensus.nPowTargetSpacing = RUBLE_COMBINED_SPACING;
        consensus.nPowTargetSpacingLegacy = RUBLE_ORDINARY_SPACING;
        consensus.nPowTargetSpacingAuxPow = RUBLE_AUXPOW_SPACING;
        // Match mainnet DAA behavior; Ruble has no timestamp-triggered
        // emergency difficulty reset.
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.enforce_BIP94 = false;
        consensus.fPowNoRetargeting = false;
        consensus.fAuxpowFirstBlockASERTAnchor = true;
        consensus.nAuxpowActivationHeight = 1;
        consensus.nRuleChangeActivationThreshold = 360; // 75% for testchains
        consensus.nMinerConfirmationWindow = 480; // nPowTargetTimespan / nPowTargetSpacing
        consensus.nASERTHalfLife = RUBLE_ASERT_HALF_LIFE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = RUBLE_TESTDUMMY_VERSION_BIT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};
        consensus.nAuxpowChainId = RUBLE_AUXPOW_CHAIN_ID;
        consensus.fStrictChainId = true;
        consensus.asertAnchorParams = Consensus::Params::ASERTAnchor{
            0,
            0x1d00ffff,
            0x1d00ffff,
            1785196891,
        };

        pchMessageStart[0] = 0xd2;
        pchMessageStart[1] = 0x6b;
        pchMessageStart[2] = 0x52;
        pchMessageStart[3] = 0x34;
        nDefaultPort = 43898;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        genesis = CreateRubleGenesisBlock(
            "28/Jul/2026 Ruble testnet4 genesis - protocol testing",
            1785196891, 3677704107, 0x1d00ffff, 1);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"00000000c18d0967b53a961f55fe209f51cd79af12857f7c527808e1f3dcd3ec"});
        assert(genesis.hashMerkleRoot == uint256{"942ca0f1be95880554dd69f02291764002e5360078848a2c9b5bdff28419e8af"});

        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 196);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xcf};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tb";

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                {0, uint256{"00000000c18d0967b53a961f55fe209f51cd79af12857f7c527808e1f3dcd3ec"}},
            }
        };

        m_assumeutxo_data = {
        };

        chainTxData = ChainTxData{
            .nTime = 0,
            .tx_count = 0,
            .dTxRate = 0,
        };
    }
};

/**
 * Signet: test network with an additional consensus parameter (see BIP325).
 */
class SigNetParams : public CChainParams {
public:
    explicit SigNetParams(const SigNetOptions& options)
    {
        std::vector<uint8_t> bin;
        vFixedSeeds.clear();
        vSeeds.clear();

        if (!options.challenge) {
            // Publicly solvable Ruble signet challenge:
            // <Ruble network commitment> OP_DROP OP_TRUE.
            bin = "2084ada4a264ded2b6f94cc3666ee843986bd700b1d48f69c50eaeb242b2182b8e7551"_hex_v_u8;

            consensus.nMinimumChainWork = uint256{};
            consensus.defaultAssumeValid = uint256{};
            m_assumed_blockchain_size = 0;
            m_assumed_chain_state_size = 0;
            chainTxData = ChainTxData{
                .nTime = 0,
                .tx_count = 0,
                .dTxRate = 0,
            };
        } else {
            bin = *options.challenge;
            consensus.nMinimumChainWork = uint256{};
            consensus.defaultAssumeValid = uint256{};
            m_assumed_blockchain_size = 0;
            m_assumed_chain_state_size = 0;
            chainTxData = ChainTxData{
                0,
                0,
                0,
            };
            LogPrintf("Signet with challenge %s\n", HexStr(bin));
        }

        if (options.seeds) {
            vSeeds = *options.seeds;
        }

        m_chain_type = ChainType::SIGNET;
        consensus.signet_blocks = true;
        consensus.signet_challenge.assign(bin.begin(), bin.end());
        consensus.nSubsidyHalvingInterval = RUBLE_HALVING_INTERVAL;
        consensus.nInitialSubsidy = RUBLE_INITIAL_SUBSIDY;
        consensus.nPremineHeight = -1;
        consensus.nPremineAmount = 0;
        consensus.nTailSubsidy = RUBLE_TAIL_SUBSIDY;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 1;
        consensus.nPowTargetTimespan = 24 * 60 * 60; // one day
        consensus.nPowTargetSpacing = RUBLE_COMBINED_SPACING;
        consensus.nPowTargetSpacingLegacy = RUBLE_ORDINARY_SPACING;
        consensus.nPowTargetSpacingAuxPow = RUBLE_AUXPOW_SPACING;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.enforce_BIP94 = false;
        // Signet is a private/public test network. Keep its work fixed at an
        // intentionally easy target so operators can exercise signed blocks
        // and multi-node behavior on ordinary development hardware.
        consensus.fPowNoRetargeting = true;
        consensus.fAuxpowFirstBlockASERTAnchor = true;
        consensus.nAuxpowActivationHeight = 1;
        consensus.nRuleChangeActivationThreshold = 360; // 75% for testchains
        consensus.nMinerConfirmationWindow = 480; // nPowTargetTimespan / nPowTargetSpacing
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256{"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nASERTHalfLife = RUBLE_ASERT_HALF_LIFE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = RUBLE_TESTDUMMY_VERSION_BIT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Activation of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        consensus.nAuxpowChainId = RUBLE_AUXPOW_CHAIN_ID;
        consensus.fStrictChainId = true;
        consensus.asertAnchorParams = Consensus::Params::ASERTAnchor{
            0,
            0x207fffff,
            0x207fffff,
            1785196921,
        };

        // message start is defined as the first 4 bytes of the sha256d of the block script
        HashWriter h{};
        h << consensus.signet_challenge;
        uint256 hash = h.GetHash();
        std::copy_n(hash.begin(), 4, pchMessageStart.begin());

        nDefaultPort = 44888;
        nPruneAfterHeight = 1000;

        genesis = CreateRubleGenesisBlock(
            "28/Jul/2026 Ruble signet genesis - community development",
            1785196921, 0, 0x207fffff, 1);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"4810234406518a4cb293c64d79b7be54106f000f1e0e2587a93c620cbe63102f"});
        assert(genesis.hashMerkleRoot == uint256{"787b9756415d59f4f7024b65e2aab8d3e4d4ed0b01afd623d955a0b43517e405"});

        m_assumeutxo_data = {
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 196);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xcf};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tb";

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                {0, uint256{"4810234406518a4cb293c64d79b7be54106f000f1e0e2587a93c620cbe63102f"}},
            }
        };
    }
};

/**
 * Regression test: intended for private networks only. Has minimal difficulty to ensure that
 * blocks can be found instantly.
 */
class CRegTestParams : public CChainParams
{
public:
    explicit CRegTestParams(const RegTestOptions& opts)
    {
        m_chain_type = ChainType::REGTEST;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nInitialSubsidy = RUBLE_INITIAL_SUBSIDY;
        // Generic Core regression tests use a regular first subsidy. The
        // mainnet-equivalent premine path is enabled explicitly with
        // -test=premine and covered by feature_ruble_tokenomics.py.
        consensus.nPremineHeight = opts.enable_premine ? RUBLE_PREMINE_HEIGHT : -1;
        consensus.nPremineAmount = opts.enable_premine ? RUBLE_PREMINE_AMOUNT : 0;
        if (opts.enable_premine) {
            consensus.vPremineScript = {static_cast<unsigned char>(OP_TRUE)};
            consensus.fRequirePremineScript = true;
        }
        consensus.nTailSubsidy = RUBLE_TAIL_SUBSIDY;
        consensus.BIP34Height = 1; // Always active unless overridden
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1;  // Always active unless overridden
        consensus.BIP66Height = 1;  // Always active unless overridden
        consensus.CSVHeight = 1;    // Always active unless overridden
        consensus.SegwitHeight = 0; // Always active unless overridden
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256{"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 24 * 60 * 60; // one day
        consensus.nPowTargetSpacing = RUBLE_COMBINED_SPACING;
        consensus.nPowTargetSpacingLegacy = RUBLE_ORDINARY_SPACING;
        consensus.nPowTargetSpacingAuxPow = RUBLE_AUXPOW_SPACING;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.enforce_BIP94 = opts.enforce_bip94;
        consensus.fPowNoRetargeting = true;
        consensus.fAuxpowFirstBlockASERTAnchor = true;
        consensus.nAuxpowActivationHeight = opts.auxpow_activation_height;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2880)

        // The half life for the ASERT DAA. For every (nASERTHalfLife) seconds behind schedule the blockchain gets,
        // difficulty is cut in half. Doubled if blocks are ahead of schedule.
        consensus.nASERTHalfLife = RUBLE_ASERT_HALF_LIFE;

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = RUBLE_TESTDUMMY_VERSION_BIT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        // Disabled by default so the upstream regression suite can exercise
        // arbitrarily deep reorganizations. -test=finality enables the exact
        // mainnet depth for dedicated attack tests.
        consensus.nFinalityDepth = opts.enable_finality ? RUBLE_MAINNET_FINALITY_DEPTH : 0;
        consensus.nFinalityFloorHeight = 0;

        consensus.nAuxpowChainId = RUBLE_AUXPOW_CHAIN_ID;
        consensus.fStrictChainId = true;

        // RegTest has no hard-coded anchor block
        // consensus.asertAnchorParams.reset();

        pchMessageStart[0] = 0xa4;
        pchMessageStart[1] = 0xb2;
        pchMessageStart[2] = 0x7a;
        pchMessageStart[3] = 0xdd;
        nDefaultPort = 45888;
        nPruneAfterHeight = opts.fastprune ? 100 : 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        for (const auto& [dep, height] : opts.activation_heights) {
            switch (dep) {
            case Consensus::BuriedDeployment::DEPLOYMENT_SEGWIT:
                consensus.SegwitHeight = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_HEIGHTINCB:
                consensus.BIP34Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_DERSIG:
                consensus.BIP66Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CLTV:
                consensus.BIP65Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CSV:
                consensus.CSVHeight = int{height};
                break;
            }
        }

        for (const auto& [deployment_pos, version_bits_params] : opts.version_bits_parameters) {
            consensus.vDeployments[deployment_pos].nStartTime = version_bits_params.start_time;
            consensus.vDeployments[deployment_pos].nTimeout = version_bits_params.timeout;
            consensus.vDeployments[deployment_pos].min_activation_height = version_bits_params.min_activation_height;
        }

        genesis = CreateRubleGenesisBlock(
            "Ruble regtest genesis - deterministic local testing",
            1296688602, 0, 0x207fffff, 1);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"5a3f68d82df274d2e892b6b50de381059f9541402bf99082fe54fd29b0c85724"});
        assert(genesis.hashMerkleRoot == uint256{"8a29e646a4b2de9a2c531e8e20dcc8b4cc90ba3eff85998fe8e5eb68d1977f17"});

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        m_is_mockable_chain = true;

        checkpointData = {
            {
                {0, uint256{"5a3f68d82df274d2e892b6b50de381059f9541402bf99082fe54fd29b0c85724"}},
            }
        };

        m_assumeutxo_data = {
            {   // Deterministic Ruble regtest snapshot for unit tests
                .height = 110,
                .hash_serialized = AssumeutxoHash{uint256{"a3a3048216fc4cb181f63436f327957254ebc8012a2efe7a062ddc22c2d8968f"}},
                .m_chain_tx_count = 111,
                .blockhash = uint256{"716d21ae6b37b560aa6fceab86fad5eefbfb325844c17f5adcd8b547f3f78063"},
            },
            {   // Deterministic Ruble regtest snapshot for the UTXO snapshot fuzz target
                .height = 200,
                .hash_serialized = AssumeutxoHash{uint256{"b6707f88f5a63c991b1d59d38113bbbd6b64f8467b58093e16ba2b93992e383f"}},
                .m_chain_tx_count = 201,
                .blockhash = uint256{"783cd0e987920491c7396d0d69d1d801b72d524b92ec78bcf9597076b9d5a7f6"},
            },
            {   // Deterministic Ruble regtest snapshot for feature_assumeutxo.py
                .height = 299,
                .hash_serialized = AssumeutxoHash{uint256{"2133463f63ac56752a2e4c48b24525683a3eee69eb8b9d1d491b515090d24cd0"}},
                .m_chain_tx_count = 334,
                .blockhash = uint256{"76cbbcd720aa87e7d75f5c2b31ad2d4da41c4b10dc8fe8203c8158ed616f6657"},
            },
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 196);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xcf};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "bcrt";
    }
};

std::unique_ptr<const CChainParams> CChainParams::SigNet(const SigNetOptions& options)
{
    auto params = std::make_unique<const SigNetParams>(options);
    AssertRubleDeploymentBits(params->GetConsensus());
    return params;
}

std::unique_ptr<const CChainParams> CChainParams::RegTest(const RegTestOptions& options)
{
    auto params = std::make_unique<const CRegTestParams>(options);
    AssertRubleDeploymentBits(params->GetConsensus());
    return params;
}

std::unique_ptr<const CChainParams> CChainParams::Main()
{
    auto params = std::make_unique<const CMainParams>();
    AssertRubleDeploymentBits(params->GetConsensus());
    return params;
}

std::unique_ptr<const CChainParams> CChainParams::TestNet()
{
    auto params = std::make_unique<const CTestNetParams>();
    AssertRubleDeploymentBits(params->GetConsensus());
    return params;
}

std::unique_ptr<const CChainParams> CChainParams::TestNet4()
{
    auto params = std::make_unique<const CTestNet4Params>();
    AssertRubleDeploymentBits(params->GetConsensus());
    return params;
}

std::vector<int> CChainParams::GetAvailableSnapshotHeights() const
{
    std::vector<int> heights;
    heights.reserve(m_assumeutxo_data.size());

    for (const auto& data : m_assumeutxo_data) {
        heights.emplace_back(data.height);
    }
    return heights;
}

std::optional<ChainType> GetNetworkForMagic(const MessageStartChars& message)
{
    const auto mainnet_msg = CChainParams::Main()->MessageStart();
    const auto testnet_msg = CChainParams::TestNet()->MessageStart();
    const auto testnet4_msg = CChainParams::TestNet4()->MessageStart();
    const auto regtest_msg = CChainParams::RegTest({})->MessageStart();
    const auto signet_msg = CChainParams::SigNet({})->MessageStart();

    if (std::ranges::equal(message, mainnet_msg)) {
        return ChainType::MAIN;
    } else if (std::ranges::equal(message, testnet_msg)) {
        return ChainType::TESTNET;
    } else if (std::ranges::equal(message, testnet4_msg)) {
        return ChainType::TESTNET4;
    } else if (std::ranges::equal(message, regtest_msg)) {
        return ChainType::REGTEST;
    } else if (std::ranges::equal(message, signet_msg)) {
        return ChainType::SIGNET;
    }
    return std::nullopt;
}
