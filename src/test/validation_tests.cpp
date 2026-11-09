// Copyright (c) 2014-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <core_io.h>
#include <hash.h>
#include <net.h>
#include <policy/policy.h>
#include <pow.h>
#include <serialize.h>
#include <signet.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/strencodings.h>
#include <validation.h>
#include <versionbits.h>

#include <algorithm>
#include <limits>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(validation_tests, TestingSetup)

static void TestBlockSubsidyHalvings(const Consensus::Params& consensusParams)
{
    CAmount previous_subsidy = consensusParams.nInitialSubsidy;
    for (int halvings = 1; halvings < 64; ++halvings) {
        const int height = halvings * consensusParams.nSubsidyHalvingInterval;
        const CAmount subsidy = GetBlockSubsidy(height, consensusParams);
        const CAmount expected = std::max(previous_subsidy / 2, consensusParams.nTailSubsidy);
        BOOST_CHECK_EQUAL(subsidy, expected);
        previous_subsidy = subsidy;
    }
    BOOST_CHECK_EQUAL(previous_subsidy, consensusParams.nTailSubsidy);
}

static void TestBlockSubsidyHalvings(int nSubsidyHalvingInterval)
{
    Consensus::Params consensusParams{};
    consensusParams.nSubsidyHalvingInterval = nSubsidyHalvingInterval;
    consensusParams.nInitialSubsidy = 100 * COIN;
    consensusParams.nTailSubsidy = COIN / 10;
    TestBlockSubsidyHalvings(consensusParams);
}

BOOST_AUTO_TEST_CASE(block_subsidy_test)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus = chainParams->GetConsensus();

    for (const auto chain : {ChainType::MAIN, ChainType::TESTNET, ChainType::TESTNET4, ChainType::SIGNET, ChainType::REGTEST}) {
        const auto params = CreateChainParams(*m_node.args, chain);
        const auto& network_consensus = params->GetConsensus();
        BOOST_CHECK_EQUAL(network_consensus.nInitialSubsidy, 100 * COIN);
        BOOST_CHECK_EQUAL(network_consensus.nGenesisSubsidy, chain == ChainType::MAIN ? 50 * COIN : 0);
        BOOST_CHECK_EQUAL(GetBlockSubsidy(0, network_consensus), network_consensus.nGenesisSubsidy);
        if (chain != ChainType::MAIN) {
            BOOST_CHECK_EQUAL(network_consensus.nPremineHeight, -1);
            BOOST_CHECK_EQUAL(network_consensus.nPremineAmount, 0);
        } else {
            BOOST_CHECK_EQUAL(network_consensus.nPremineHeight, 1);
            BOOST_CHECK_EQUAL(network_consensus.nPremineAmount, 5000000 * COIN);
        }
        if (chain == ChainType::MAIN) {
            BOOST_CHECK(network_consensus.fRequirePremineScript);
            BOOST_CHECK_EQUAL(HexStr(network_consensus.vPremineScript), "0014d66945ac0db4a7caf4dc7cb94c0fb0d74bab4098");
            BOOST_CHECK_EQUAL(network_consensus.asertAnchorParams.nBitsLegacy, 0x1a0400d1U);
            BOOST_CHECK_EQUAL(network_consensus.asertAnchorParams.nBitsAuxPow, 0x1a0400d1U);
            BOOST_CHECK_EQUAL(network_consensus.nFinalityDepth, 20);
            BOOST_CHECK_EQUAL(network_consensus.nFinalityFloorHeight, 1);
        } else {
            BOOST_CHECK(!network_consensus.fRequirePremineScript);
            BOOST_CHECK_EQUAL(network_consensus.nFinalityDepth, 0);
            BOOST_CHECK_EQUAL(network_consensus.nFinalityFloorHeight, 0);
        }
        BOOST_CHECK_EQUAL(network_consensus.nTailSubsidy, COIN / 10);
        BOOST_CHECK_EQUAL(network_consensus.nPowTargetSpacing, 180);
        BOOST_CHECK_EQUAL(network_consensus.nPowTargetSpacingLegacy, 270);
        BOOST_CHECK_EQUAL(network_consensus.nPowTargetSpacingAuxPow, 540);
        BOOST_CHECK_EQUAL(network_consensus.nASERTHalfLife, 2 * 60 * 60);
        BOOST_CHECK_EQUAL(network_consensus.nAuxpowChainId, 0x5255);
        BOOST_CHECK(network_consensus.fStrictChainId);
        BOOST_CHECK(network_consensus.fAuxpowFirstBlockASERTAnchor);
        if (chain == ChainType::MAIN) {
            constexpr int activation_height{7'000};
            BOOST_CHECK_EQUAL(network_consensus.nAuxpowActivationHeight, activation_height);
            BOOST_CHECK(!network_consensus.IsAuxpowEnabled(activation_height - 1));
            BOOST_CHECK(network_consensus.IsAuxpowEnabled(activation_height));
            BOOST_CHECK(network_consensus.IsAuxpowEnabled(activation_height + 1));
        } else {
            BOOST_CHECK_EQUAL(network_consensus.nAuxpowActivationHeight, 1);
            BOOST_CHECK(!network_consensus.IsAuxpowEnabled(0));
            BOOST_CHECK(network_consensus.IsAuxpowEnabled(1));
        }
        for (const auto& deployment : network_consensus.vDeployments) {
            BOOST_CHECK(IsAuxpowCompatibleVersionBit(deployment.bit));
        }
        if (chain != ChainType::REGTEST) {
            BOOST_CHECK_EQUAL(network_consensus.asertAnchorParams.nHeight, 0);
            BOOST_CHECK(!network_consensus.fPowAllowMinDifficultyBlocks);
        }
        if (chain == ChainType::SIGNET) {
            BOOST_CHECK(network_consensus.fPowNoRetargeting);
            BOOST_CHECK_EQUAL(params->GenesisBlock().nBits, 0x207fffffU);
            BOOST_CHECK_EQUAL(network_consensus.asertAnchorParams.nBitsLegacy, 0x207fffffU);
            BOOST_CHECK_EQUAL(network_consensus.asertAnchorParams.nBitsAuxPow, 0x207fffffU);
        } else if (chain != ChainType::REGTEST) {
            BOOST_CHECK(!network_consensus.fPowNoRetargeting);
        }
    }
    BOOST_CHECK_EQUAL(consensus.nSubsidyHalvingInterval, 500000);

    BOOST_CHECK_EQUAL(GetBlockSubsidy(0, consensus), 50 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1, consensus), 5000000 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(2, consensus), 100 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(499999, consensus), 100 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(500000, consensus), 50 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1000000, consensus), 25 * COIN);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(4500000, consensus), 19531250);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(4999999, consensus), 19531250);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(5000000, consensus), COIN / 10);
    BOOST_CHECK_EQUAL(GetBlockSubsidy(std::numeric_limits<int>::max(), consensus), COIN / 10);

    ArgsManager premine_args;
    premine_args.ForceSetArg("-test", "premine");
    const auto premine_regtest = CreateChainParams(premine_args, ChainType::REGTEST);
    BOOST_CHECK_EQUAL(premine_regtest->GetConsensus().nPremineHeight, 1);
    BOOST_CHECK_EQUAL(premine_regtest->GetConsensus().nPremineAmount, 5000000 * COIN);
    BOOST_CHECK(premine_regtest->GetConsensus().fRequirePremineScript);
    BOOST_CHECK(premine_regtest->GetConsensus().vPremineScript == std::vector<unsigned char>{static_cast<unsigned char>(OP_TRUE)});
    BOOST_CHECK_EQUAL(GetBlockSubsidy(1, premine_regtest->GetConsensus()), 5000000 * COIN);

    ArgsManager finality_args;
    finality_args.ForceSetArg("-test", "finality");
    const auto finality_regtest = CreateChainParams(finality_args, ChainType::REGTEST);
    BOOST_CHECK_EQUAL(finality_regtest->GetConsensus().nFinalityDepth, 20);
    BOOST_CHECK_EQUAL(finality_regtest->GetConsensus().nFinalityFloorHeight, 0);

    TestBlockSubsidyHalvings(consensus);
    TestBlockSubsidyHalvings(150); // As in regtest
    TestBlockSubsidyHalvings(1000); // Just another interval
}

BOOST_AUTO_TEST_CASE(ruble_rolling_finality_boundary_test)
{
    Consensus::Params consensus{
        CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus()};

    std::vector<CBlockIndex> active(31);
    for (int height{0}; height < static_cast<int>(active.size()); ++height) {
        active[height].nHeight = height;
        active[height].pprev = height == 0 ? nullptr : &active[height - 1];
        active[height].BuildSkip();
    }

    CChain chain;
    chain.SetTip(active[21]);
    BOOST_REQUIRE(GetFinalityCandidate(chain, consensus) != nullptr);
    BOOST_CHECK_EQUAL(GetFinalityCandidate(chain, consensus)->nHeight, 1);

    chain.SetTip(active[22]);
    const CBlockIndex* finalized{GetFinalityCandidate(chain, consensus)};
    BOOST_REQUIRE(finalized != nullptr);
    BOOST_CHECK_EQUAL(finalized->nHeight, 2);

    // A competing tip branching at the finalized block may replace exactly
    // 20 active blocks.
    std::vector<CBlockIndex> allowed_branch(21);
    for (int offset{0}; offset < static_cast<int>(allowed_branch.size()); ++offset) {
        allowed_branch[offset].nHeight = 3 + offset;
        allowed_branch[offset].pprev = offset == 0 ? &active[2] : &allowed_branch[offset - 1];
        allowed_branch[offset].BuildSkip();
    }
    BOOST_CHECK(IsFinalityCompatible(&allowed_branch.back(), finalized));

    // A branch one block earlier would disconnect 21 active blocks and is
    // rejected no matter how much proof of work it later accumulates.
    std::vector<CBlockIndex> blocked_branch(22);
    for (int offset{0}; offset < static_cast<int>(blocked_branch.size()); ++offset) {
        blocked_branch[offset].nHeight = 2 + offset;
        blocked_branch[offset].pprev = offset == 0 ? &active[1] : &blocked_branch[offset - 1];
        blocked_branch[offset].BuildSkip();
    }
    BOOST_CHECK(!IsFinalityCompatible(&blocked_branch.back(), finalized));
    BOOST_CHECK(IsFinalityCompatible(&active[1], finalized));
    BOOST_CHECK(!IsFinalityCompatible(&blocked_branch.front(), finalized));

    consensus.nFinalityDepth = 0;
    BOOST_CHECK(GetFinalityCandidate(chain, consensus) == nullptr);
    BOOST_CHECK(IsFinalityCompatible(&blocked_branch.back(), nullptr));
}

BOOST_AUTO_TEST_CASE(subsidy_limit_test)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    CAmount spendable_before_tail{0};
    for (int height = 1; height < 5000000; ++height) {
        spendable_before_tail += GetBlockSubsidy(height, chainParams->GetConsensus());
    }
    BOOST_CHECK(MoneyRange(spendable_before_tail));
    BOOST_CHECK_EQUAL(spendable_before_tail, CAmount{10490214375000000});
}

BOOST_AUTO_TEST_CASE(ruble_network_identity_test)
{
    std::vector<std::unique_ptr<const CChainParams>> networks;
    networks.emplace_back(CreateChainParams(*m_node.args, ChainType::MAIN));
    networks.emplace_back(CreateChainParams(*m_node.args, ChainType::TESTNET));
    networks.emplace_back(CreateChainParams(*m_node.args, ChainType::TESTNET4));
    networks.emplace_back(CreateChainParams(*m_node.args, ChainType::SIGNET));
    networks.emplace_back(CreateChainParams(*m_node.args, ChainType::REGTEST));

    const std::vector<std::string> genesis_hashes{
        "00000c2a6ff6021e6d10fe9a28cf5a652df4a354775e216af2c864de53230b5a",
        "000000002cf445f5ca3e4d4ee118517f86f48b39ae2ddd0239a8e5318acfbf03",
        "00000000c18d0967b53a961f55fe209f51cd79af12857f7c527808e1f3dcd3ec",
        "4810234406518a4cb293c64d79b7be54106f000f1e0e2587a93c620cbe63102f",
        "5a3f68d82df274d2e892b6b50de381059f9541402bf99082fe54fd29b0c85724",
    };
    const std::vector<std::string> message_starts{
        "c1c71865",
        "88440a8a",
        "d26b5234",
        "bb89469d",
        "a4b27add",
    };
    const std::vector<uint16_t> ports{33888, 43888, 43898, 44888, 45888};

    std::set<std::string> unique_genesis;
    std::set<std::string> unique_magic;
    std::set<uint16_t> unique_ports;
    for (size_t i{0}; i < networks.size(); ++i) {
        const auto& params{*networks[i]};
        const auto& genesis{params.GenesisBlock()};

        BOOST_CHECK_EQUAL(genesis.GetHash().ToString(), genesis_hashes[i]);
        BOOST_CHECK(genesis.hashPrevBlock.IsNull());
        BOOST_REQUIRE_EQUAL(genesis.vtx.size(), 1U);
        BOOST_REQUIRE_EQUAL(genesis.vtx[0]->vout.size(), 1U);
        if (i == 0) {
            BOOST_CHECK_EQUAL(genesis.nTime, 1784710520U);
            BOOST_CHECK_EQUAL(genesis.nNonce, 582296U);
            BOOST_CHECK_EQUAL(genesis.nBits, 0x1e0ffff0U);
            BOOST_CHECK_EQUAL(genesis.hashMerkleRoot.ToString(), "4c422303101396cf081fc7919c91a6e714f974985ed617d6c53622f4a7a85bca");
            BOOST_CHECK_EQUAL(genesis.vtx[0]->vout[0].nValue, 50 * COIN);
            BOOST_CHECK_EQUAL(
                HexStr(genesis.vtx[0]->vin[0].scriptSig),
                "04ffff001d0104495275626c652028525542292047656e6573697320426c6f636b20e28094204275696c742062792074686520636f6d6d756e6974792c207365637572656420627920426974636f696e2e");
            BOOST_CHECK_EQUAL(
                HexStr(genesis.vtx[0]->vout[0].scriptPubKey),
                "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac");

            // The exact hard-coded genesis is valid even though its historical
            // target is easier than the live ASERT powLimit. The exception must
            // not apply to any other header.
            BOOST_CHECK(CheckProofOfWork(genesis, params.GetConsensus()));
            BOOST_CHECK(!CheckProofOfWork(genesis.GetHash(), genesis.nBits, params.GetConsensus()));
            CBlock inconsistent_auxpow{genesis};
            inconsistent_auxpow.auxpow = std::make_shared<CAuxPow>();
            BOOST_CHECK(!CheckProofOfWork(inconsistent_auxpow, params.GetConsensus()));
            BlockValidationState genesis_state;
            BOOST_CHECK(CheckBlock(genesis, genesis_state, params.GetConsensus()));
            CBlock non_genesis{genesis};
            non_genesis.fChecked = false;
            ++non_genesis.nNonce;
            BOOST_CHECK(!CheckProofOfWork(non_genesis, params.GetConsensus()));
            BlockValidationState non_genesis_state;
            BOOST_CHECK(!CheckBlock(non_genesis, non_genesis_state, params.GetConsensus()));
            BOOST_CHECK_EQUAL(non_genesis_state.GetRejectReason(), "high-hash");
        } else {
            BOOST_CHECK_EQUAL(genesis.vtx[0]->vout[0].nValue, 0);
            BOOST_CHECK(genesis.vtx[0]->vout[0].scriptPubKey == (CScript{} << OP_RETURN));
        }
        BOOST_CHECK_EQUAL(params.Checkpoints().mapCheckpoints.size(), 1U);
        BOOST_CHECK_EQUAL(params.Checkpoints().mapCheckpoints.at(0), genesis.GetHash());
        if (i == networks.size() - 1) {
            BOOST_CHECK(params.GetAvailableSnapshotHeights() == (std::vector<int>{110, 200, 299}));
        } else {
            BOOST_CHECK(params.GetAvailableSnapshotHeights().empty());
        }

        const std::string magic{HexStr(params.MessageStart())};
        BOOST_CHECK_EQUAL(magic, message_starts[i]);
        BOOST_CHECK_EQUAL(params.GetDefaultPort(), ports[i]);
        unique_genesis.emplace(genesis.GetHash().ToString());
        unique_magic.emplace(magic);
        unique_ports.emplace(params.GetDefaultPort());
    }
    BOOST_CHECK_EQUAL(unique_genesis.size(), networks.size());
    BOOST_CHECK_EQUAL(unique_magic.size(), networks.size());
    BOOST_CHECK_EQUAL(unique_ports.size(), networks.size());

    const auto& main{*networks.front()};
    BOOST_CHECK(main.GetConsensus().nMinimumChainWork.IsNull());
    BOOST_CHECK(main.GetConsensus().defaultAssumeValid.IsNull());
    BOOST_CHECK(main.GetConsensus().BIP34Hash.IsNull());
    BOOST_CHECK_EQUAL(main.GetConsensus().asertAnchorParams.nBlockTime, main.GenesisBlock().GetBlockTime());
    BOOST_CHECK(main.GetConsensus().fRequireLaunchBlock);
    BOOST_CHECK(main.GetConsensus().hashLaunchBlock == uint256{
        "00000000000003e4b7526e931b9ba1f5154b9ab13dfd9820fefef03bd1aee192"});
    BOOST_CHECK_EQUAL(main.GetConsensus().nLaunchBlockTime, 1786213343U);
    BOOST_CHECK_EQUAL(main.Bech32HRP(), "rub");
    BOOST_REQUIRE_EQUAL(main.Base58Prefix(CChainParams::PUBKEY_ADDRESS).size(), 1U);
    BOOST_REQUIRE_EQUAL(main.Base58Prefix(CChainParams::SCRIPT_ADDRESS).size(), 1U);
    BOOST_REQUIRE_EQUAL(main.Base58Prefix(CChainParams::SECRET_KEY).size(), 1U);
    BOOST_CHECK_EQUAL(main.Base58Prefix(CChainParams::PUBKEY_ADDRESS).front(), 60);
    BOOST_CHECK_EQUAL(main.Base58Prefix(CChainParams::SCRIPT_ADDRESS).front(), 122);
    BOOST_CHECK_EQUAL(main.Base58Prefix(CChainParams::SECRET_KEY).front(), 163);
    BOOST_CHECK(main.Base58Prefix(CChainParams::EXT_PUBLIC_KEY) ==
                std::vector<unsigned char>({0x04, 0x0b, 0xf2, 0xa6}));
    BOOST_CHECK(main.Base58Prefix(CChainParams::EXT_SECRET_KEY) ==
                std::vector<unsigned char>({0x04, 0x0b, 0xee, 0x6c}));

    for (size_t i{1}; i < networks.size(); ++i) {
        const auto& params{*networks[i]};
        BOOST_REQUIRE_EQUAL(params.Base58Prefix(CChainParams::PUBKEY_ADDRESS).size(), 1U);
        BOOST_REQUIRE_EQUAL(params.Base58Prefix(CChainParams::SCRIPT_ADDRESS).size(), 1U);
        BOOST_REQUIRE_EQUAL(params.Base58Prefix(CChainParams::SECRET_KEY).size(), 1U);
        BOOST_CHECK_EQUAL(params.Base58Prefix(CChainParams::PUBKEY_ADDRESS).front(), 111);
        BOOST_CHECK_EQUAL(params.Base58Prefix(CChainParams::SCRIPT_ADDRESS).front(), 196);
        BOOST_CHECK_EQUAL(params.Base58Prefix(CChainParams::SECRET_KEY).front(), 239);
        BOOST_CHECK_EQUAL(params.Bech32HRP(), i == networks.size() - 1 ? "bcrt" : "tb");
    }
}

BOOST_AUTO_TEST_CASE(ruble_launch_block_fail_closed_test)
{
    const auto chain_params{CreateChainParams(*m_node.args, ChainType::MAIN)};
    const auto& consensus{chain_params->GetConsensus()};

    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript{} << 1 << OP_0;
    coinbase.vout.emplace_back(
        consensus.nPremineAmount,
        CScript{consensus.vPremineScript.begin(), consensus.vPremineScript.end()});

    CBlock launch;
    launch.nVersion = 4;
    launch.hashPrevBlock = consensus.hashGenesisBlock;
    launch.nTime = chain_params->GenesisBlock().nTime + 1;
    launch.nBits = consensus.asertAnchorParams.nBitsLegacy;
    launch.nNonce = 1;
    launch.vtx.emplace_back(MakeTransactionRef(std::move(coinbase)));
    launch.hashMerkleRoot = BlockMerkleRoot(launch);

    // The finalized mainnet parameters reject every child of genesis except
    // the exact pinned launch block, including paths that skip PoW.
    BlockValidationState pinned_state;
    BOOST_CHECK(!CheckBlock(
        launch, pinned_state, consensus,
        /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/true));
    BOOST_CHECK_EQUAL(pinned_state.GetRejectReason(), "bad-launch-block");
    BOOST_CHECK(!CheckProofOfWork(launch, consensus));

    // An incompletely configured copy remains fail-closed.
    Consensus::Params locked{consensus};
    locked.hashLaunchBlock.SetNull();
    locked.nLaunchBlockTime = 0;
    BlockValidationState locked_state;
    BOOST_CHECK(!CheckBlock(
        launch, locked_state, locked,
        /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/true));
    BOOST_CHECK_EQUAL(locked_state.GetRejectReason(), "launch-block-unset");

    // A synthetic configured commitment proves the positive path without
    // pretending this CPU test mined the real 0x1a0400d1 launch proof.
    Consensus::Params configured{consensus};
    configured.nLaunchBlockTime = launch.nTime;
    configured.hashLaunchBlock = launch.GetHash();
    BlockValidationState exact_state;
    BOOST_CHECK(CheckBlock(
        launch, exact_state, configured,
        /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/true));

    using BlockMutator = void (*)(CBlock&);
    for (const BlockMutator mutate : {
             +[](CBlock& block) { ++block.nTime; },
             +[](CBlock& block) { ++block.nNonce; },
             +[](CBlock& block) { ++block.nVersion; },
             +[](CBlock& block) { ++block.nBits; },
             +[](CBlock& block) { block.hashMerkleRoot = ArithToUint256(2); },
         }) {
        CBlock changed{launch};
        changed.fChecked = false;
        mutate(changed);
        BlockValidationState changed_state;
        BOOST_CHECK(!CheckBlock(
            changed, changed_state, configured,
            /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/false));
        BOOST_CHECK_EQUAL(changed_state.GetRejectReason(), "bad-launch-block");
    }
}

BOOST_AUTO_TEST_CASE(ruble_finalized_launch_block_vector)
{
    // Exact 180-byte native mainnet block 1 recovered from the independently
    // checksummed RC5 mining evidence archive. Keep the complete block here,
    // rather than only its header hash, so the premine transaction, owner
    // script, Merkle root, and proof of work are immutable test data.
    constexpr const char* launch_block_hex{
        "0060cf285a0b2353de64c8f26a215e7754a3f42d655acf289afe106d1e02f66f2a0c000098faffb5"
        "a8b57fba928e7196b022fce7bb449c8b1569feb537ab207c154bc724df73776ad100041a0d80136f"
        "0102000000010000000000000000000000000000000000000000000000000000000000000000ffff"
        "ffff1151002f5275626c652f454090ddd6000000ffffffff0100406352bfc60100160014d66945ac"
        "0db4a7caf4dc7cb94c0fb0d74bab409800000000"};

    const auto chain_params{CreateChainParams(*m_node.args, ChainType::MAIN)};
    const auto& consensus{chain_params->GetConsensus()};
    CBlock launch;
    BOOST_REQUIRE(DecodeHexBlk(launch, launch_block_hex));

    BOOST_CHECK_EQUAL(GetSerializeSize(TX_WITH_WITNESS(launch)), 180U);
    BOOST_CHECK_EQUAL(
        launch.GetHash().ToString(),
        "00000000000003e4b7526e931b9ba1f5154b9ab13dfd9820fefef03bd1aee192");
    BOOST_CHECK_EQUAL(launch.nVersion, 0x28cf6000);
    BOOST_CHECK(!launch.IsAuxpow());
    BOOST_CHECK_EQUAL(launch.hashPrevBlock, consensus.hashGenesisBlock);
    BOOST_CHECK_EQUAL(
        launch.hashMerkleRoot.ToString(),
        "24c74b157c20ab37b5fe69158b9c44bbe7fc22b096718e92ba7fb5a8b5fffa98");
    BOOST_CHECK_EQUAL(launch.nTime, 1786213343U);
    BOOST_CHECK_EQUAL(launch.nBits, 0x1a0400d1U);
    BOOST_CHECK_EQUAL(launch.nNonce, 1863548941U);
    BOOST_CHECK(CheckLaunchBlockCommitment(launch, consensus));
    BOOST_CHECK(CheckProofOfWork(launch, consensus));

    BOOST_REQUIRE_EQUAL(launch.vtx.size(), 1U);
    const CTransaction& coinbase{*launch.vtx.front()};
    BOOST_CHECK(coinbase.IsCoinBase());
    BOOST_CHECK_EQUAL(
        coinbase.GetHash().ToString(),
        "24c74b157c20ab37b5fe69158b9c44bbe7fc22b096718e92ba7fb5a8b5fffa98");
    BOOST_REQUIRE_EQUAL(coinbase.vin.size(), 1U);
    BOOST_CHECK_EQUAL(
        HexStr(coinbase.vin.front().scriptSig),
        "51002f5275626c652f454090ddd6000000");
    BOOST_REQUIRE_EQUAL(coinbase.vout.size(), 1U);
    BOOST_CHECK_EQUAL(coinbase.vout.front().nValue, 5000000 * COIN);
    BOOST_CHECK_EQUAL(
        HexStr(coinbase.vout.front().scriptPubKey),
        "0014d66945ac0db4a7caf4dc7cb94c0fb0d74bab4098");

    BlockValidationState state;
    BOOST_CHECK(CheckBlock(
        launch, state, consensus,
        /*fCheckPOW=*/true, /*fCheckMerkleRoot=*/true));
}

BOOST_AUTO_TEST_CASE(ruble_resource_limits_test)
{
    BOOST_CHECK_EQUAL(MAX_BLOCK_SERIALIZED_SIZE, 48'000'000U);
    BOOST_CHECK_EQUAL(MAX_BLOCK_WEIGHT, 48'000'000U);
    BOOST_CHECK_EQUAL(MAX_BLOCK_SIGOPS_COST, 960'000);
    BOOST_CHECK_EQUAL(MAX_PROTOCOL_MESSAGE_LENGTH, MAX_BLOCK_SERIALIZED_SIZE);
    BOOST_CHECK_EQUAL(BIP324Cipher::LENGTH_LEN, 4U);

    // Generic deserialization must hold a maximum block, while raw-block and
    // P2P paths remain capped at exactly 48 MB. HTTP has a separate larger
    // body limit for the block's hexadecimal RPC representation.
    BOOST_CHECK(MAX_SIZE >= MAX_BLOCK_SERIALIZED_SIZE);

    // Increasing block capacity must not increase one standard transaction's
    // share of relay and mining validation work.
    BOOST_CHECK_EQUAL(MAX_STANDARD_TX_SIGOPS_COST, 16'000U);
}

BOOST_AUTO_TEST_CASE(signet_parse_tests)
{
    ArgsManager signet_argsman;
    signet_argsman.ForceSetArg("-signetchallenge", "51"); // set challenge to OP_TRUE
    const auto signet_params = CreateChainParams(signet_argsman, ChainType::SIGNET);
    CBlock block;
    BOOST_CHECK(signet_params->GetConsensus().signet_challenge == std::vector<uint8_t>{OP_TRUE});
    CScript challenge{OP_TRUE};

    // empty block is invalid
    BOOST_CHECK(!SignetTxs::Create(block, challenge));
    BOOST_CHECK(!CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // no witness commitment
    CMutableTransaction cb;
    cb.vout.emplace_back(0, CScript{});
    block.vtx.push_back(MakeTransactionRef(cb));
    block.vtx.push_back(MakeTransactionRef(cb)); // Add dummy tx to exercise merkle root code
    BOOST_CHECK(!SignetTxs::Create(block, challenge));
    BOOST_CHECK(!CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // no header is treated valid
    std::vector<uint8_t> witness_commitment_section_141{0xaa, 0x21, 0xa9, 0xed};
    for (int i = 0; i < 32; ++i) {
        witness_commitment_section_141.push_back(0xff);
    }
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(SignetTxs::Create(block, challenge));
    BOOST_CHECK(CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // no data after header, valid
    std::vector<uint8_t> witness_commitment_section_325{0xec, 0xc7, 0xda, 0xa2};
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141 << witness_commitment_section_325;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(SignetTxs::Create(block, challenge));
    BOOST_CHECK(CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // Premature end of data, invalid
    witness_commitment_section_325.push_back(0x01);
    witness_commitment_section_325.push_back(0x51);
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141 << witness_commitment_section_325;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(!SignetTxs::Create(block, challenge));
    BOOST_CHECK(!CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // has data, valid
    witness_commitment_section_325.push_back(0x00);
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141 << witness_commitment_section_325;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(SignetTxs::Create(block, challenge));
    BOOST_CHECK(CheckSignetBlockSolution(block, signet_params->GetConsensus()));

    // Extraneous data, invalid
    witness_commitment_section_325.push_back(0x00);
    cb.vout.at(0).scriptPubKey = CScript{} << OP_RETURN << witness_commitment_section_141 << witness_commitment_section_325;
    block.vtx.at(0) = MakeTransactionRef(cb);
    BOOST_CHECK(!SignetTxs::Create(block, challenge));
    BOOST_CHECK(!CheckSignetBlockSolution(block, signet_params->GetConsensus()));
}

//! Ruble launch networks deliberately ship without assumeutxo snapshots.
//! Regtest keeps deterministic snapshot vectors for unit, fuzz, and functional tests.
BOOST_AUTO_TEST_CASE(test_assumeutxo)
{
    for (const auto chain : {ChainType::MAIN, ChainType::TESTNET, ChainType::TESTNET4, ChainType::SIGNET}) {
        const auto params = CreateChainParams(*m_node.args, chain);
        for (const int height : {0, 1, 100, 110, 5000000}) {
            BOOST_CHECK(!params->AssumeutxoForHeight(height));
        }
        BOOST_CHECK(!params->AssumeutxoForBlockhash(params->GenesisBlock().GetHash()));
    }

    const auto regtest = CreateChainParams(*m_node.args, ChainType::REGTEST);
    const auto snapshot = regtest->AssumeutxoForHeight(110);
    BOOST_REQUIRE(snapshot);
    BOOST_CHECK(snapshot->hash_serialized == AssumeutxoHash{uint256{"a3a3048216fc4cb181f63436f327957254ebc8012a2efe7a062ddc22c2d8968f"}});
    BOOST_CHECK_EQUAL(snapshot->m_chain_tx_count, 111);
    BOOST_CHECK(snapshot->blockhash == uint256{"716d21ae6b37b560aa6fceab86fad5eefbfb325844c17f5adcd8b547f3f78063"});
    BOOST_CHECK(regtest->AssumeutxoForBlockhash(snapshot->blockhash));

    const auto fuzz_snapshot = regtest->AssumeutxoForHeight(200);
    BOOST_REQUIRE(fuzz_snapshot);
    BOOST_CHECK(fuzz_snapshot->hash_serialized == AssumeutxoHash{uint256{"b6707f88f5a63c991b1d59d38113bbbd6b64f8467b58093e16ba2b93992e383f"}});
    BOOST_CHECK_EQUAL(fuzz_snapshot->m_chain_tx_count, 201);
    BOOST_CHECK(fuzz_snapshot->blockhash == uint256{"783cd0e987920491c7396d0d69d1d801b72d524b92ec78bcf9597076b9d5a7f6"});
    BOOST_CHECK(regtest->AssumeutxoForBlockhash(fuzz_snapshot->blockhash));

    const auto functional_snapshot = regtest->AssumeutxoForHeight(299);
    BOOST_REQUIRE(functional_snapshot);
    BOOST_CHECK(functional_snapshot->hash_serialized == AssumeutxoHash{uint256{"2133463f63ac56752a2e4c48b24525683a3eee69eb8b9d1d491b515090d24cd0"}});
    BOOST_CHECK_EQUAL(functional_snapshot->m_chain_tx_count, 334);
    BOOST_CHECK(functional_snapshot->blockhash == uint256{"76cbbcd720aa87e7d75f5c2b31ad2d4da41c4b10dc8fe8203c8158ed616f6657"});
    BOOST_CHECK(regtest->AssumeutxoForBlockhash(functional_snapshot->blockhash));

    for (const int height : {0, 1, 100, 109, 111, 199, 201, 298, 300, 5000000}) {
        BOOST_CHECK(!regtest->AssumeutxoForHeight(height));
    }
}

BOOST_AUTO_TEST_CASE(block_malleation)
{
    // Test utilities that calls `IsBlockMutated` and then clears the validity
    // cache flags on `CBlock`.
    auto is_mutated = [](CBlock& block, bool check_witness_root) {
        bool mutated{IsBlockMutated(block, check_witness_root)};
        block.fChecked = false;
        block.m_checked_witness_commitment = false;
        block.m_checked_merkle_root = false;
        return mutated;
    };
    auto is_not_mutated = [&is_mutated](CBlock& block, bool check_witness_root) {
        return !is_mutated(block, check_witness_root);
    };

    // Test utilities to create coinbase transactions and insert witness
    // commitments.
    //
    // Note: this will not include the witness stack by default to avoid
    // triggering the "no witnesses allowed for blocks that don't commit to
    // witnesses" rule when testing other malleation vectors.
    auto create_coinbase_tx = [](bool include_witness = false) {
        CMutableTransaction coinbase;
        coinbase.vin.resize(1);
        if (include_witness) {
            coinbase.vin[0].scriptWitness.stack.resize(1);
            coinbase.vin[0].scriptWitness.stack[0] = std::vector<unsigned char>(32, 0x00);
        }

        coinbase.vout.resize(1);
        coinbase.vout[0].scriptPubKey.resize(MINIMUM_WITNESS_COMMITMENT);
        coinbase.vout[0].scriptPubKey[0] = OP_RETURN;
        coinbase.vout[0].scriptPubKey[1] = 0x24;
        coinbase.vout[0].scriptPubKey[2] = 0xaa;
        coinbase.vout[0].scriptPubKey[3] = 0x21;
        coinbase.vout[0].scriptPubKey[4] = 0xa9;
        coinbase.vout[0].scriptPubKey[5] = 0xed;

        auto tx = MakeTransactionRef(coinbase);
        assert(tx->IsCoinBase());
        return tx;
    };
    auto insert_witness_commitment = [](CBlock& block, uint256 commitment) {
        assert(!block.vtx.empty() && block.vtx[0]->IsCoinBase() && !block.vtx[0]->vout.empty());

        CMutableTransaction mtx{*block.vtx[0]};
        CHash256().Write(commitment).Write(std::vector<unsigned char>(32, 0x00)).Finalize(commitment);
        memcpy(&mtx.vout[0].scriptPubKey[6], commitment.begin(), 32);
        block.vtx[0] = MakeTransactionRef(mtx);
    };

    {
        CBlock block;

        // Empty block is expected to have merkle root of 0x0.
        BOOST_CHECK(block.vtx.empty());
        block.hashMerkleRoot = uint256{1};
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        block.hashMerkleRoot = uint256{};
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Block with a single coinbase tx is mutated if the merkle root is not
        // equal to the coinbase tx's hash.
        block.vtx.push_back(create_coinbase_tx());
        BOOST_CHECK(block.vtx[0]->GetHash() != block.hashMerkleRoot);
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        block.hashMerkleRoot = block.vtx[0]->GetHash();
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Block with two transactions is mutated if the merkle root does not
        // match the double sha256 of the concatenation of the two transaction
        // hashes.
        block.vtx.push_back(MakeTransactionRef(CMutableTransaction{}));
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        HashWriter hasher;
        hasher.write(block.vtx[0]->GetHash());
        hasher.write(block.vtx[1]->GetHash());
        block.hashMerkleRoot = hasher.GetHash();
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Block with two transactions is mutated if any node is duplicate.
        {
            block.vtx[1] = block.vtx[0];
            HashWriter hasher;
            hasher.write(block.vtx[0]->GetHash());
            hasher.write(block.vtx[1]->GetHash());
            block.hashMerkleRoot = hasher.GetHash();
            BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        }

        // Blocks with 64-byte coinbase transactions are not considered mutated
        block.vtx.clear();
        {
            CMutableTransaction mtx;
            mtx.vin.resize(1);
            mtx.vout.resize(1);
            mtx.vout[0].scriptPubKey.resize(4);
            block.vtx.push_back(MakeTransactionRef(mtx));
            block.hashMerkleRoot = block.vtx.back()->GetHash();
            assert(block.vtx.back()->IsCoinBase());
            assert(GetSerializeSize(TX_NO_WITNESS(block.vtx.back())) == 64);
        }
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));
    }

    {
        // Test merkle root malleation

        // Pseudo code to mine transactions tx{1,2,3}:
        //
        // ```
        // loop {
        //   tx1 = random_tx()
        //   tx2 = random_tx()
        //   tx3 = deserialize_tx(txid(tx1) || txid(tx2));
        //   if serialized_size_without_witness(tx3) == 64 {
        //     print(hex(tx3))
        //     break
        //   }
        // }
        // ```
        //
        // The `random_tx` function used to mine the txs below simply created
        // empty transactions with a random version field.
        CMutableTransaction tx1;
        BOOST_CHECK(DecodeHexTx(tx1, "ff204bd0000000000000", /*try_no_witness=*/true, /*try_witness=*/false));
        CMutableTransaction tx2;
        BOOST_CHECK(DecodeHexTx(tx2, "8ae53c92000000000000", /*try_no_witness=*/true, /*try_witness=*/false));
        CMutableTransaction tx3;
        BOOST_CHECK(DecodeHexTx(tx3, "cdaf22d00002c6a7f848f8ae4d30054e61dcf3303d6fe01d282163341f06feecc10032b3160fcab87bdfe3ecfb769206ef2d991b92f8a268e423a6ef4d485f06", /*try_no_witness=*/true, /*try_witness=*/false));
        {
            // Verify that double_sha256(txid1||txid2) == txid3
            HashWriter hasher;
            hasher.write(tx1.GetHash());
            hasher.write(tx2.GetHash());
            assert(hasher.GetHash() == tx3.GetHash());
            // Verify that tx3 is 64 bytes in size (without witness).
            assert(GetSerializeSize(TX_NO_WITNESS(tx3)) == 64);
        }

        CBlock block;
        block.vtx.push_back(MakeTransactionRef(tx1));
        block.vtx.push_back(MakeTransactionRef(tx2));
        uint256 merkle_root = block.hashMerkleRoot = BlockMerkleRoot(block);
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/false));

        // Mutate the block by replacing the two transactions with one 64-byte
        // transaction that serializes into the concatenation of the txids of
        // the transactions in the unmutated block.
        block.vtx.clear();
        block.vtx.push_back(MakeTransactionRef(tx3));
        BOOST_CHECK(!block.vtx.back()->IsCoinBase());
        BOOST_CHECK(BlockMerkleRoot(block) == merkle_root);
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
    }

    {
        CBlock block;
        block.vtx.push_back(create_coinbase_tx(/*include_witness=*/true));
        {
            CMutableTransaction mtx;
            mtx.vin.resize(1);
            mtx.vin[0].scriptWitness.stack.resize(1);
            mtx.vin[0].scriptWitness.stack[0] = {0};
            block.vtx.push_back(MakeTransactionRef(mtx));
        }
        block.hashMerkleRoot = BlockMerkleRoot(block);
        // Block with witnesses is considered mutated if the witness commitment
        // is not validated.
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/false));
        // Block with invalid witness commitment is considered mutated.
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/true));

        // Block with valid commitment is not mutated
        {
            auto commitment{BlockWitnessMerkleRoot(block)};
            insert_witness_commitment(block, commitment);
            block.hashMerkleRoot = BlockMerkleRoot(block);
        }
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/true));

        // Malleating witnesses should be caught by `IsBlockMutated`.
        {
            CMutableTransaction mtx{*block.vtx[1]};
            assert(!mtx.vin[0].scriptWitness.stack[0].empty());
            ++mtx.vin[0].scriptWitness.stack[0][0];
            block.vtx[1] = MakeTransactionRef(mtx);
        }
        // Without also updating the witness commitment, the merkle root should
        // not change when changing one of the witnesses.
        BOOST_CHECK(block.hashMerkleRoot == BlockMerkleRoot(block));
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/true));
        {
            auto commitment{BlockWitnessMerkleRoot(block)};
            insert_witness_commitment(block, commitment);
            block.hashMerkleRoot = BlockMerkleRoot(block);
        }
        BOOST_CHECK(is_not_mutated(block, /*check_witness_root=*/true));

        // Test malleating the coinbase witness reserved value
        {
            CMutableTransaction mtx{*block.vtx[0]};
            mtx.vin[0].scriptWitness.stack.resize(0);
            block.vtx[0] = MakeTransactionRef(mtx);
            block.hashMerkleRoot = BlockMerkleRoot(block);
        }
        BOOST_CHECK(is_mutated(block, /*check_witness_root=*/true));
    }
}

BOOST_AUTO_TEST_SUITE_END()
