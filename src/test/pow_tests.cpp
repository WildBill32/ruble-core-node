// Copyright (c) 2015-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <pow.h>
#include <primitives/block.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <vector>

namespace {

Consensus::Params BitcoinRetargetParams(Consensus::Params params)
{
    arith_uint256 pow_limit;
    pow_limit.SetCompact(0x1d00ffff);
    params.powLimit = ArithToUint256(pow_limit);
    params.fPowAllowMinDifficultyBlocks = false;
    params.enforce_BIP94 = false;
    params.fPowNoRetargeting = false;
    params.nPowTargetSpacing = 10 * 60;
    params.nPowTargetTimespan = 14 * 24 * 60 * 60;
    return params;
}

void SetSyntheticIndex(CBlockIndex& index, CBlockIndex* parent, bool is_auxpow)
{
    index.pprev = parent;
    index.nHeight = parent == nullptr ? 0 : parent->nHeight + 1;
    index.nVersion = is_auxpow ? CPureBlockHeader::VERSION_AUXPOW : 1;
    index.nTime = parent == nullptr ? 1 : parent->nTime + 1;
    index.nAuxPow = parent == nullptr ? 0 : parent->nAuxPow;
    if (is_auxpow) ++index.nAuxPow;
    index.BuildSkip();
}

std::vector<CBlockIndex> BuildSyntheticChain(const std::vector<bool>& channels)
{
    std::vector<CBlockIndex> blocks(channels.size() + 1);
    SetSyntheticIndex(blocks[0], nullptr, /*is_auxpow=*/false);
    for (size_t i = 0; i < channels.size(); ++i) {
        SetSyntheticIndex(blocks[i + 1], &blocks[i], channels[i]);
    }
    return blocks;
}

std::vector<CBlockIndex> BuildSyntheticBranch(CBlockIndex& parent, const std::vector<bool>& channels)
{
    std::vector<CBlockIndex> blocks(channels.size());
    for (size_t i = 0; i < channels.size(); ++i) {
        SetSyntheticIndex(blocks[i], i == 0 ? &parent : &blocks[i - 1], channels[i]);
    }
    return blocks;
}

const CBlockIndex* LinearLastBlockInChannel(const CBlockIndex* tip, bool is_auxpow, int exclusive_anchor_height)
{
    for (const CBlockIndex* cursor{tip}; cursor->nHeight > exclusive_anchor_height; cursor = cursor->pprev) {
        if (cursor->IsAuxpow() == is_auxpow) return cursor;
    }
    return nullptr;
}

const CBlockIndex* LinearFirstBlockInChannel(const CBlockIndex* tip, bool is_auxpow, int exclusive_anchor_height)
{
    const CBlockIndex* result{nullptr};
    for (const CBlockIndex* cursor{tip}; cursor->nHeight > exclusive_anchor_height; cursor = cursor->pprev) {
        if (cursor->IsAuxpow() == is_auxpow) result = cursor;
    }
    return result;
}

void CheckChannelLookup(const CBlockIndex* tip, int exclusive_anchor_height = 0)
{
    for (const bool is_auxpow : {false, true}) {
        BOOST_CHECK_EQUAL(
            FindLastBlockInChannel(tip, is_auxpow, exclusive_anchor_height),
            LinearLastBlockInChannel(tip, is_auxpow, exclusive_anchor_height));
        BOOST_CHECK_EQUAL(
            FindFirstBlockInChannel(tip, is_auxpow, exclusive_anchor_height),
            LinearFirstBlockInChannel(tip, is_auxpow, exclusive_anchor_height));
    }
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pow_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(ruble_channel_lookup_matches_linear_oracle)
{
    // Exhaust every native/AuxPoW pattern through twelve post-genesis blocks.
    for (size_t length = 0; length <= 12; ++length) {
        const uint32_t pattern_count{uint32_t{1} << length};
        for (uint32_t pattern = 0; pattern < pattern_count; ++pattern) {
            std::vector<bool> channels(length);
            for (size_t i = 0; i < length; ++i) {
                channels[i] = (pattern & (uint32_t{1} << i)) != 0;
            }
            const auto chain{BuildSyntheticChain(channels)};
            CheckChannelLookup(&chain.back());
            CheckChannelLookup(&chain.back(), chain.back().nHeight / 2);
        }
    }

    // A long channel-starvation history previously forced a linear scan for
    // each candidate header. Check both starvation directions at 100k blocks.
    std::vector<bool> starvation(100'000, /*is_auxpow=*/true);
    starvation.front() = false;
    auto chain{BuildSyntheticChain(starvation)};
    CheckChannelLookup(&chain.back());
    const CBlockIndex* starved_native{FindLastBlockInChannel(&chain.back(), false, 0)};
    BOOST_REQUIRE(starved_native != nullptr);
    BOOST_CHECK_EQUAL(starved_native->nHeight, 1);

    starvation.assign(100'000, /*is_auxpow=*/false);
    starvation.front() = true;
    chain = BuildSyntheticChain(starvation);
    CheckChannelLookup(&chain.back());
    const CBlockIndex* starved_auxpow{FindLastBlockInChannel(&chain.back(), true, 0)};
    BOOST_REQUIRE(starved_auxpow != nullptr);
    BOOST_CHECK_EQUAL(starved_auxpow->nHeight, 1);

    // Deterministic mixed history and two branches from a common trunk prove
    // that the lookup follows the supplied tip rather than another branch.
    uint64_t state{0x9e3779b97f4a7c15ULL};
    std::vector<bool> trunk_channels(4096);
    for (size_t i = 0; i < trunk_channels.size(); ++i) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        trunk_channels[i] = (state >> 63) != 0;
    }
    auto trunk{BuildSyntheticChain(trunk_channels)};
    CheckChannelLookup(&trunk.back());

    std::vector<bool> branch_a_channels(2048);
    std::vector<bool> branch_b_channels(2048);
    for (size_t i = 0; i < branch_a_channels.size(); ++i) {
        branch_a_channels[i] = (i % 11) == 0;
        branch_b_channels[i] = (i % 7) != 0;
    }
    const auto branch_a{BuildSyntheticBranch(trunk.back(), branch_a_channels)};
    const auto branch_b{BuildSyntheticBranch(trunk.back(), branch_b_channels)};
    CheckChannelLookup(&branch_a.back());
    CheckChannelLookup(&branch_b.back());
}

BOOST_AUTO_TEST_CASE(ruble_launch_block_commitment)
{
    auto params{CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus()};
    BOOST_CHECK(params.fRequireLaunchBlock);
    BOOST_REQUIRE(IsLaunchBlockConfigured(params));
    BOOST_CHECK(params.hashLaunchBlock == uint256{
        "00000000000003e4b7526e931b9ba1f5154b9ab13dfd9820fefef03bd1aee192"});
    BOOST_CHECK_EQUAL(params.nLaunchBlockTime, 1786213343U);
    BOOST_CHECK(CheckProofOfWork(
        params.hashLaunchBlock,
        params.asertAnchorParams.nBitsLegacy,
        params));

    CBlockHeader launch;
    launch.nVersion = 4;
    launch.hashPrevBlock = params.hashGenesisBlock;
    launch.hashMerkleRoot = ArithToUint256(1);
    launch.nTime = params.asertAnchorParams.nBlockTime + 1;
    launch.nBits = params.asertAnchorParams.nBitsLegacy;
    launch.nNonce = 1;

    // Mainnet rejects every child of genesis except the externally mined,
    // consensus-pinned launch header.
    BOOST_CHECK(!CheckLaunchBlockCommitment(launch, params));

    // Preserve the fail-closed path for an incompletely configured build.
    auto locked{params};
    locked.hashLaunchBlock.SetNull();
    locked.nLaunchBlockTime = 0;
    BOOST_CHECK(!IsLaunchBlockConfigured(locked));
    BOOST_CHECK(!CheckLaunchBlockCommitment(launch, locked));

    // A synthetic commitment exercises the positive and mutation paths
    // without requiring the serialized production coinbase in this unit.
    auto synthetic{params};
    synthetic.nLaunchBlockTime = launch.nTime;
    synthetic.hashLaunchBlock = launch.GetHash();
    BOOST_CHECK(IsLaunchBlockConfigured(synthetic));
    BOOST_CHECK(CheckLaunchBlockCommitment(launch, synthetic));

    using HeaderMutator = void (*)(CBlockHeader&);
    for (const HeaderMutator mutate : {
             +[](CBlockHeader& block) { ++block.nTime; },
             +[](CBlockHeader& block) { ++block.nNonce; },
             +[](CBlockHeader& block) { ++block.nVersion; },
             +[](CBlockHeader& block) { ++block.nBits; },
             +[](CBlockHeader& block) { block.hashMerkleRoot = ArithToUint256(2); },
         }) {
        CBlockHeader changed{launch};
        mutate(changed);
        BOOST_CHECK(!CheckLaunchBlockCommitment(changed, synthetic));
    }

    // Even if someone configured the hash of an AuxPoW header, block 1 must
    // remain native so its identity cannot be separated from an AuxPoW payload.
    CBlockHeader auxpow_launch{launch};
    auxpow_launch.SetAuxpowVersion(true);
    synthetic.hashLaunchBlock = auxpow_launch.GetHash();
    BOOST_CHECK(!CheckLaunchBlockCommitment(auxpow_launch, synthetic));

    // The rule applies only to the direct child of genesis and only on a
    // network that explicitly requires the pinned launch block.
    CBlockHeader later{launch};
    later.hashPrevBlock = launch.GetHash();
    BOOST_CHECK(CheckLaunchBlockCommitment(later, synthetic));
    synthetic.fRequireLaunchBlock = false;
    BOOST_CHECK(CheckLaunchBlockCommitment(auxpow_launch, synthetic));
}

BOOST_AUTO_TEST_CASE(ruble_launch_work_calibration)
{
    const auto params{CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus()};
    CBlockIndex launch_index;
    launch_index.nBits = params.asertAnchorParams.nBitsLegacy;
    const arith_uint256 expected_hashes{GetBlockProof(launch_index)};

    BOOST_CHECK_EQUAL(params.nPowTargetSpacing, 180);
    BOOST_CHECK_EQUAL(params.nPowTargetSpacingLegacy, 270);
    BOOST_CHECK_EQUAL(params.nPowTargetSpacingAuxPow, 540);
    BOOST_CHECK_EQUAL(params.nPowTargetSpacingAuxPow,
                      2 * params.nPowTargetSpacingLegacy);
    BOOST_CHECK(params.fAuxpowFirstBlockASERTAnchor);
    BOOST_CHECK((expected_hashes >> 64) == 0);
    BOOST_CHECK_EQUAL(expected_hashes.GetLow64(), 18'000'047'580'434'167ULL);
}

BOOST_AUTO_TEST_CASE(ruble_asert_channel_response)
{
    auto params = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    const arith_uint256 pow_limit{UintToArith256(params.powLimit)};
    const arith_uint256 reference_target{pow_limit >> 4};
    const uint32_t reference_bits{reference_target.GetCompact()};
    const int64_t blocks{16};

    BOOST_CHECK_EQUAL(params.asertAnchorParams.nHeight, 0);
    BOOST_CHECK_EQUAL(params.nASERTHalfLife, 2 * 60 * 60);
    BOOST_CHECK_EQUAL(params.nPowTargetSpacingLegacy, 270);
    BOOST_CHECK_EQUAL(params.nPowTargetSpacingAuxPow, 540);
    BOOST_CHECK(!params.fPowAllowMinDifficultyBlocks);
    BOOST_CHECK_EQUAL(params.asertAnchorParams.nBitsLegacy, 0x1a0400d1U);
    BOOST_CHECK_EQUAL(params.asertAnchorParams.nBitsAuxPow, 0x1a0400d1U);

    for (const int64_t spacing : {params.nPowTargetSpacingLegacy, params.nPowTargetSpacingAuxPow}) {
        const int64_t ideal_time{spacing * blocks};
        const auto on_schedule{CalculateASERT(reference_target, spacing, ideal_time, blocks, pow_limit, params.nASERTHalfLife)};
        const auto one_half_life_late{CalculateASERT(reference_target, spacing, ideal_time + params.nASERTHalfLife, blocks, pow_limit, params.nASERTHalfLife)};
        const auto one_half_life_early{CalculateASERT(reference_target, spacing, ideal_time - params.nASERTHalfLife, blocks, pow_limit, params.nASERTHalfLife)};
        const auto twelve_minutes_late{CalculateASERT(reference_target, spacing, ideal_time + 12 * 60, blocks, pow_limit, params.nASERTHalfLife)};

        BOOST_CHECK(on_schedule == reference_target);
        BOOST_CHECK(one_half_life_late == (reference_target << 1));
        BOOST_CHECK(one_half_life_early == (reference_target >> 1));
        BOOST_CHECK(twelve_minutes_late > reference_target);
        BOOST_CHECK(twelve_minutes_late < (reference_target << 1));
    }

    // Exercise GetNextWorkRequired across an interleaved ordinary/AuxPoW
    // history with an honest-current block-1 timestamp. The adversarial
    // block-1 timestamp policy remains a mainnet launch gate.
    params.asertAnchorParams.nBitsLegacy = reference_bits;
    params.asertAnchorParams.nBitsAuxPow = reference_bits;

    CBlockHeader ordinary_candidate;
    ordinary_candidate.nVersion = 1;
    CBlockHeader auxpow_candidate;
    auxpow_candidate.SetBaseVersion(1, params.nAuxpowChainId);
    auxpow_candidate.SetAuxpowVersion(true);

    CBlockIndex genesis;
    genesis.nHeight = 0;
    genesis.nTime = params.asertAnchorParams.nBlockTime;
    genesis.nBits = reference_bits;
    genesis.nVersion = 1;
    uint256 genesis_hash{params.hashGenesisBlock};
    genesis.phashBlock = &genesis_hash;
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&genesis, &ordinary_candidate, params), reference_bits);
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&genesis, &auxpow_candidate, params), reference_bits);

    CBlockIndex ordinary_one;
    ordinary_one.pprev = &genesis;
    ordinary_one.nHeight = 1;
    ordinary_one.nTime = genesis.nTime + 7 * 24 * 60 * 60;
    ordinary_one.nBits = reference_bits;
    ordinary_one.nVersion = ordinary_candidate.nVersion;
    ordinary_one.nAuxPow = 0;
    uint256 ordinary_one_hash{ordinary_one.GetPureHeader().GetHash()};
    ordinary_one.phashBlock = &ordinary_one_hash;
    params.nLaunchBlockTime = ordinary_one.nTime;
    params.hashLaunchBlock = ordinary_one_hash;
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&ordinary_one, &ordinary_candidate, params), reference_bits);
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&ordinary_one, &auxpow_candidate, params), reference_bits);

    CBlockIndex ordinary_two;
    ordinary_two.pprev = &ordinary_one;
    ordinary_two.nHeight = 2;
    ordinary_two.nTime = ordinary_one.nTime + params.nPowTargetSpacingLegacy;
    ordinary_two.nBits = reference_bits;
    ordinary_two.nVersion = ordinary_candidate.nVersion;
    ordinary_two.nAuxPow = 0;

    CBlockIndex auxpow_one;
    auxpow_one.pprev = &ordinary_two;
    auxpow_one.nHeight = 3;
    auxpow_one.nTime = ordinary_one.nTime + params.nPowTargetSpacingAuxPow;
    auxpow_one.nBits = reference_bits;
    auxpow_one.nVersion = auxpow_candidate.nVersion;
    auxpow_one.nAuxPow = 1;

    BOOST_CHECK_EQUAL(GetNextWorkRequired(&auxpow_one, &ordinary_candidate, params), reference_bits);
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&auxpow_one, &auxpow_candidate, params), reference_bits);

    CBlockIndex ordinary_three_late;
    ordinary_three_late.pprev = &auxpow_one;
    ordinary_three_late.nHeight = 4;
    ordinary_three_late.nTime = ordinary_one.nTime + 2 * params.nPowTargetSpacingLegacy + params.nASERTHalfLife;
    ordinary_three_late.nBits = reference_bits;
    ordinary_three_late.nVersion = ordinary_candidate.nVersion;
    ordinary_three_late.nAuxPow = 1;

    const uint32_t expected_late_bits{
        CalculateASERT(
            arith_uint256{}.SetCompact(reference_bits),
            params.nPowTargetSpacingLegacy,
            2 * params.nPowTargetSpacingLegacy + params.nASERTHalfLife,
            2,
            pow_limit,
            params.nASERTHalfLife
        ).GetCompact()
    };
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&ordinary_three_late, &ordinary_candidate, params), expected_late_bits);
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&ordinary_three_late, &auxpow_candidate, params), reference_bits);
}

BOOST_AUTO_TEST_CASE(ruble_auxpow_cold_start_uses_first_block_anchor)
{
    auto params{CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus()};
    BOOST_REQUIRE(params.fAuxpowFirstBlockASERTAnchor);

    const uint32_t initial_bits{params.asertAnchorParams.nBitsAuxPow};
    const arith_uint256 pow_limit{UintToArith256(params.powLimit)};

    CBlockHeader auxpow_candidate;
    auxpow_candidate.SetBaseVersion(1, params.nAuxpowChainId);
    auxpow_candidate.SetAuxpowVersion(true);

    CBlockIndex genesis;
    genesis.nHeight = 0;
    genesis.nTime = params.asertAnchorParams.nBlockTime;
    genesis.nBits = initial_bits;
    genesis.nVersion = 1;
    uint256 genesis_hash{params.hashGenesisBlock};
    genesis.phashBlock = &genesis_hash;

    CBlockHeader launch_header;
    launch_header.nVersion = 4;
    launch_header.hashPrevBlock = genesis_hash;
    launch_header.hashMerkleRoot = ArithToUint256(1);
    launch_header.nTime = genesis.nTime + 1;
    launch_header.nBits = initial_bits;
    launch_header.nNonce = 1;
    params.nLaunchBlockTime = launch_header.nTime;
    params.hashLaunchBlock = launch_header.GetHash();

    CBlockIndex launch{launch_header};
    launch.pprev = &genesis;
    launch.nHeight = 1;
    launch.nAuxPow = 0;
    uint256 launch_hash{params.hashLaunchBlock};
    launch.phashBlock = &launch_hash;
    launch.BuildSkip();

    CBlockIndex late_native;
    late_native.pprev = &launch;
    late_native.nHeight = 2;
    late_native.nVersion = 4;
    late_native.nTime = launch.nTime + 4 * 24 * 60 * 60;
    late_native.nBits = initial_bits;
    late_native.nAuxPow = 0;
    late_native.BuildSkip();

    // Four days without an AuxPoW block must not make the first one easier.
    BOOST_CHECK_EQUAL(
        GetNextWorkRequired(&late_native, &auxpow_candidate, params),
        initial_bits);

    CBlockIndex first_auxpow;
    first_auxpow.pprev = &late_native;
    first_auxpow.nHeight = 3;
    first_auxpow.nVersion = auxpow_candidate.nVersion;
    first_auxpow.nTime = late_native.nTime + 1;
    first_auxpow.nBits = initial_bits;
    first_auxpow.nAuxPow = 1;
    first_auxpow.BuildSkip();

    // The first AuxPoW block establishes time zero; the second retains the
    // initial target instead of inheriting four days of native-channel lag.
    BOOST_CHECK_EQUAL(
        GetNextWorkRequired(&first_auxpow, &auxpow_candidate, params),
        initial_bits);

    CBlockIndex second_auxpow;
    second_auxpow.pprev = &first_auxpow;
    second_auxpow.nHeight = 4;
    second_auxpow.nVersion = auxpow_candidate.nVersion;
    second_auxpow.nTime = first_auxpow.nTime +
        params.nPowTargetSpacingAuxPow + params.nASERTHalfLife;
    second_auxpow.nBits = initial_bits;
    second_auxpow.nAuxPow = 2;
    second_auxpow.BuildSkip();

    const uint32_t one_half_life_late{
        CalculateASERT(
            arith_uint256{}.SetCompact(initial_bits),
            params.nPowTargetSpacingAuxPow,
            params.nPowTargetSpacingAuxPow + params.nASERTHalfLife,
            1,
            pow_limit,
            params.nASERTHalfLife
        ).GetCompact()};
    BOOST_CHECK_EQUAL(
        GetNextWorkRequired(&second_auxpow, &auxpow_candidate, params),
        one_half_life_late);

    // Document the fork rule explicitly: disabling the first-block anchor on
    // the same history reproduces the obsolete launch-time catch-up target.
    auto legacy_schedule{params};
    legacy_schedule.fAuxpowFirstBlockASERTAnchor = false;
    BOOST_CHECK_NE(
        GetNextWorkRequired(&first_auxpow, &auxpow_candidate, legacy_schedule),
        initial_bits);
}

/* Test calculation of next difficulty target with no constraints applying */
BOOST_AUTO_TEST_CASE(get_next_work)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto consensus = BitcoinRetargetParams(chainParams->GetConsensus());
    int64_t nLastRetargetTime = 1261130161; // Block #30240
    CBlockIndex pindexLast;
    pindexLast.nHeight = 32255;
    pindexLast.nTime = 1262152739;  // Block #32255
    pindexLast.nBits = 0x1d00ffff;

    // Here (and below): expected_nbits is calculated in
    // CalculateNextWorkRequired(); redoing the calculation here would be just
    // reimplementing the same code that is written in pow.cpp. Rather than
    // copy that code, we just hardcode the expected result.
    unsigned int expected_nbits = 0x1d00d86aU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, consensus), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(consensus, pindexLast.nHeight+1, pindexLast.nBits, expected_nbits));
}

/* Test the constraint on the upper bound for next work */
BOOST_AUTO_TEST_CASE(get_next_work_pow_limit)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto consensus = BitcoinRetargetParams(chainParams->GetConsensus());
    int64_t nLastRetargetTime = 1231006505; // Block #0
    CBlockIndex pindexLast;
    pindexLast.nHeight = 2015;
    pindexLast.nTime = 1233061996;  // Block #2015
    pindexLast.nBits = 0x1d00ffff;
    unsigned int expected_nbits = 0x1d00ffffU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, consensus), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(consensus, pindexLast.nHeight+1, pindexLast.nBits, expected_nbits));
}

/* Test the constraint on the lower bound for actual time taken */
BOOST_AUTO_TEST_CASE(get_next_work_lower_limit_actual)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto consensus = BitcoinRetargetParams(chainParams->GetConsensus());
    int64_t nLastRetargetTime = 1279008237; // Block #66528
    CBlockIndex pindexLast;
    pindexLast.nHeight = 68543;
    pindexLast.nTime = 1279297671;  // Block #68543
    pindexLast.nBits = 0x1c05a3f4;
    unsigned int expected_nbits = 0x1c0168fdU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, consensus), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(consensus, pindexLast.nHeight+1, pindexLast.nBits, expected_nbits));
    // Test that reducing nbits further would not be a PermittedDifficultyTransition.
    unsigned int invalid_nbits = expected_nbits-1;
    BOOST_CHECK(!PermittedDifficultyTransition(consensus, pindexLast.nHeight+1, pindexLast.nBits, invalid_nbits));
}

/* Test the constraint on the upper bound for actual time taken */
BOOST_AUTO_TEST_CASE(get_next_work_upper_limit_actual)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto consensus = BitcoinRetargetParams(chainParams->GetConsensus());
    int64_t nLastRetargetTime = 1263163443; // NOTE: Not an actual block time
    CBlockIndex pindexLast;
    pindexLast.nHeight = 46367;
    pindexLast.nTime = 1269211443;  // Block #46367
    pindexLast.nBits = 0x1c387f6f;
    unsigned int expected_nbits = 0x1d00e1fdU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, consensus), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(consensus, pindexLast.nHeight+1, pindexLast.nBits, expected_nbits));
    // Test that increasing nbits further would not be a PermittedDifficultyTransition.
    unsigned int invalid_nbits = expected_nbits+1;
    BOOST_CHECK(!PermittedDifficultyTransition(consensus, pindexLast.nHeight+1, pindexLast.nBits, invalid_nbits));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_negative_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    nBits = UintToArith256(consensus.powLimit).GetCompact(true);
    hash = uint256{1};
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_overflow_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits{~0x00800000U};
    hash = uint256{1};
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_too_easy_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 nBits_arith = UintToArith256(consensus.powLimit);
    nBits_arith *= 2;
    nBits = nBits_arith.GetCompact();
    hash = uint256{1};
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_biger_hash_than_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 hash_arith = UintToArith256(consensus.powLimit);
    nBits = hash_arith.GetCompact();
    hash_arith *= 2; // hash > nBits
    hash = ArithToUint256(hash_arith);
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_zero_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 hash_arith{0};
    nBits = hash_arith.GetCompact();
    hash = ArithToUint256(hash_arith);
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(GetBlockProofEquivalentTime_test)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    std::vector<CBlockIndex> blocks(10000);
    for (int i = 0; i < 10000; i++) {
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].nHeight = i;
        blocks[i].nTime = 1269211443 + i * chainParams->GetConsensus().nPowTargetSpacing;
        blocks[i].nBits = 0x207fffff; /* target 0x7fffff000... */
        blocks[i].nChainWork = i ? blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]) : arith_uint256(0);
    }

    for (int j = 0; j < 1000; j++) {
        CBlockIndex *p1 = &blocks[m_rng.randrange(10000)];
        CBlockIndex *p2 = &blocks[m_rng.randrange(10000)];
        CBlockIndex *p3 = &blocks[m_rng.randrange(10000)];

        int64_t tdiff = GetBlockProofEquivalentTime(*p1, *p2, *p3, chainParams->GetConsensus());
        BOOST_CHECK_EQUAL(tdiff, p1->GetBlockTime() - p2->GetBlockTime());
    }
}

void sanity_check_chainparams(const ArgsManager& args, ChainType chain_type)
{
    const auto chainParams = CreateChainParams(args, chain_type);
    const auto consensus = chainParams->GetConsensus();

    // hash genesis is correct
    BOOST_CHECK_EQUAL(consensus.hashGenesisBlock, chainParams->GenesisBlock().GetHash());

    // target timespan is an even multiple of spacing
    BOOST_CHECK_EQUAL(consensus.nPowTargetTimespan % consensus.nPowTargetSpacing, 0);

    // Genesis nBits is positive and does not overflow. Mainnet's finalized,
    // hard-coded genesis predates the live ASERT schedule and intentionally
    // uses an easier target than the ASERT-safe live powLimit.
    arith_uint256 pow_compact;
    bool neg, over;
    pow_compact.SetCompact(chainParams->GenesisBlock().nBits, &neg, &over);
    BOOST_CHECK(!neg && pow_compact != 0);
    BOOST_CHECK(!over);
    if (chain_type == ChainType::MAIN) {
        BOOST_CHECK(UintToArith256(consensus.powLimit) < pow_compact);
        BOOST_CHECK_EQUAL(chainParams->GenesisBlock().nBits, 0x1e0ffff0U);
    } else {
        BOOST_CHECK(UintToArith256(consensus.powLimit) >= pow_compact);
    }

    // check max target * 4*nPowTargetTimespan doesn't overflow -- see pow.cpp:CalculateNextWorkRequired()
    if (!consensus.fPowNoRetargeting) {
        // ASERT requires at least 32 leading zero bits for arithmetic headroom.
        BOOST_CHECK((UintToArith256(consensus.powLimit) >> 224) == 0);
        arith_uint256 targ_max{UintToArith256(uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"})};
        targ_max /= consensus.nPowTargetTimespan*4;
        BOOST_CHECK(UintToArith256(consensus.powLimit) < targ_max);
    }
}

BOOST_AUTO_TEST_CASE(ChainParams_MAIN_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::MAIN);
}

BOOST_AUTO_TEST_CASE(ChainParams_REGTEST_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::REGTEST);
}

BOOST_AUTO_TEST_CASE(ChainParams_TESTNET_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::TESTNET);
}

BOOST_AUTO_TEST_CASE(ChainParams_TESTNET4_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::TESTNET4);
}

BOOST_AUTO_TEST_CASE(ChainParams_SIGNET_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::SIGNET);
}

BOOST_AUTO_TEST_SUITE_END()
