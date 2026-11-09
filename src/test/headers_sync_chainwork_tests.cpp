// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <headerssync.h>
#include <pow.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <algorithm>
#include <vector>

#include <boost/test/unit_test.hpp>

struct HeadersGeneratorSetup : public RegTestingSetup {
    /** Search for a nonce to meet (regtest) proof of work */
    void FindProofOfWork(CBlockHeader& starting_header);
    /**
     * Generate headers in a chain that build off a given starting hash, using
     * the given nVersion, advancing time by 1 second from the starting
     * prev_time, and with a fixed merkle root hash.
     */
    void GenerateHeaders(std::vector<CBlockHeader>& headers, size_t count,
            const uint256& starting_hash, const int nVersion, int prev_time,
            const uint256& merkle_root, const uint32_t nBits);
};

void HeadersGeneratorSetup::FindProofOfWork(CBlockHeader& starting_header)
{
    while (!CheckProofOfWork(starting_header.GetHash(), starting_header.nBits, Params().GetConsensus())) {
        ++(starting_header.nNonce);
    }
}

void HeadersGeneratorSetup::GenerateHeaders(std::vector<CBlockHeader>& headers,
        size_t count, const uint256& starting_hash, const int nVersion, int prev_time,
        const uint256& merkle_root, const uint32_t nBits)
{
    uint256 prev_hash = starting_hash;

    while (headers.size() < count) {
        headers.emplace_back();
        CBlockHeader& next_header = headers.back();;
        next_header.nVersion = nVersion;
        next_header.hashPrevBlock = prev_hash;
        next_header.hashMerkleRoot = merkle_root;
        next_header.nTime = prev_time+1;
        next_header.nBits = nBits;

        FindProofOfWork(next_header);
        prev_hash = next_header.GetHash();
        prev_time = next_header.nTime;
    }
    return;
}

BOOST_FIXTURE_TEST_SUITE(headers_sync_chainwork_tests, HeadersGeneratorSetup)

// In this test, we construct two sets of headers from genesis, one with
// sufficient proof of work and one without.
// 1. We deliver the first set of headers and verify that the headers sync state
//    updates to the REDOWNLOAD phase successfully.
// 2. Then we deliver the second set of headers and verify that they fail
//    processing (presumably due to commitments not matching).
// 3. Finally, we verify that repeating with the first set of headers in both
//    phases is successful.
BOOST_AUTO_TEST_CASE(headers_sync_state)
{
    std::vector<CBlockHeader> first_chain;
    std::vector<CBlockHeader> second_chain;

    std::unique_ptr<HeadersSyncState> hss;

    const int target_blocks = 15000;
    arith_uint256 chain_work = target_blocks*2;

    // Generate headers for two different chains (using differing merkle roots
    // to ensure the headers are different).
    GenerateHeaders(first_chain, target_blocks-1, Params().GenesisBlock().GetHash(),
            Params().GenesisBlock().nVersion, Params().GenesisBlock().nTime,
            ArithToUint256(0), Params().GenesisBlock().nBits);

    GenerateHeaders(second_chain, target_blocks-2, Params().GenesisBlock().GetHash(),
            Params().GenesisBlock().nVersion, Params().GenesisBlock().nTime,
            ArithToUint256(1), Params().GenesisBlock().nBits);

    const CBlockIndex* chain_start = WITH_LOCK(::cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(Params().GenesisBlock().GetHash()));
    std::vector<CBlockHeader> headers_batch;

    // Feed the first chain to HeadersSyncState, by delivering 1 header
    // initially and then the rest.
    headers_batch.insert(headers_batch.end(), std::next(first_chain.begin()), first_chain.end());

    hss.reset(new HeadersSyncState(0, Params().GetConsensus(), chain_start, chain_work));
    (void)hss->ProcessNextHeaders({first_chain.front()}, true);
    // Pretend the first header is still "full", so we don't abort.
    auto result = hss->ProcessNextHeaders(headers_batch, true);

    // This chain should look valid, and we should have met the proof-of-work
    // requirement.
    BOOST_CHECK(result.success);
    BOOST_CHECK(result.request_more);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::REDOWNLOAD);

    // Try to sneakily feed back the second chain.
    result = hss->ProcessNextHeaders(second_chain, true);
    BOOST_CHECK(!result.success); // foiled!
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::FINAL);

    // Now try again, this time feeding the first chain twice.
    hss.reset(new HeadersSyncState(0, Params().GetConsensus(), chain_start, chain_work));
    (void)hss->ProcessNextHeaders(first_chain, true);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::REDOWNLOAD);

    result = hss->ProcessNextHeaders(first_chain, true);
    BOOST_CHECK(result.success);
    BOOST_CHECK(!result.request_more);
    // All headers should be ready for acceptance:
    BOOST_CHECK(result.pow_validated_headers.size() == first_chain.size());
    // Nothing left for the sync logic to do:
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::FINAL);

    // Finally, verify that just trying to process the second chain would not
    // succeed (too little work)
    hss.reset(new HeadersSyncState(0, Params().GetConsensus(), chain_start, chain_work));
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::PRESYNC);
     // Pretend just the first message is "full", so we don't abort.
    (void)hss->ProcessNextHeaders({second_chain.front()}, true);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::PRESYNC);

    headers_batch.clear();
    headers_batch.insert(headers_batch.end(), std::next(second_chain.begin(), 1), second_chain.end());
    // Tell the sync logic that the headers message was not full, implying no
    // more headers can be requested. For a low-work-chain, this should causes
    // the sync to end with no headers for acceptance.
    result = hss->ProcessNextHeaders(headers_batch, false);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::FINAL);
    BOOST_CHECK(result.pow_validated_headers.empty());
    BOOST_CHECK(!result.request_more);
    // Nevertheless, no validation errors should have been detected with the
    // chain:
    BOOST_CHECK(result.success);
}

BOOST_AUTO_TEST_CASE(headers_sync_ruble_asert_channels)
{
    Consensus::Params consensus{Params().GetConsensus()};
    consensus.fPowNoRetargeting = false;
    consensus.fPowAllowMinDifficultyBlocks = false;
    consensus.fAuxpowFirstBlockASERTAnchor = true;
    consensus.nPowTargetSpacingLegacy = 270;
    consensus.nPowTargetSpacingAuxPow = 540;
    consensus.nASERTHalfLife = 2 * 60 * 60;
    consensus.powLimit = uint256{
        "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    constexpr uint32_t anchor_nbits{0x1c0fffff};
    consensus.asertAnchorParams = Consensus::Params::ASERTAnchor{
        0,
        anchor_nbits,
        anchor_nbits,
        Params().GenesisBlock().GetBlockTime(),
    };

    const CBlockIndex* chain_start = WITH_LOCK(
        ::cs_main,
        return m_node.chainman->m_blockman.LookupBlockIndex(
            Params().GenesisBlock().GetHash()));
    BOOST_REQUIRE(chain_start != nullptr);

    std::vector<CBlockHeader> headers;
    auto append_header = [&](bool auxpow, uint32_t time, uint32_t nbits) {
        CBlockHeader header;
        header.nVersion = 4;
        header.SetAuxpowVersion(auxpow);
        header.hashPrevBlock = headers.empty()
            ? chain_start->GetBlockHash()
            : headers.back().GetHash();
        header.hashMerkleRoot = ArithToUint256(headers.size() + 1);
        header.nTime = time;
        header.nBits = nbits;
        header.nNonce = static_cast<uint32_t>(headers.size());
        headers.push_back(header);
    };

    const uint32_t launch_time{Params().GenesisBlock().nTime + 1};
    append_header(/*auxpow=*/false, launch_time, anchor_nbits);
    append_header(
        /*auxpow=*/false,
        launch_time + consensus.nPowTargetSpacingLegacy +
            consensus.nASERTHalfLife,
        anchor_nbits);
    append_header(
        /*auxpow=*/true,
        launch_time + consensus.nPowTargetSpacingAuxPow +
            consensus.nASERTHalfLife,
        anchor_nbits);

    const arith_uint256 pow_limit{UintToArith256(consensus.powLimit)};
    const uint32_t expected_legacy_nbits{
        CalculateASERT(
            arith_uint256{}.SetCompact(anchor_nbits),
            consensus.nPowTargetSpacingLegacy,
            headers[1].GetBlockTime() - launch_time,
            1,
            pow_limit,
            consensus.nASERTHalfLife
        ).GetCompact()};
    BOOST_REQUIRE(expected_legacy_nbits != anchor_nbits);

    append_header(
        /*auxpow=*/false,
        headers.back().nTime + 1,
        expected_legacy_nbits);

    // With an independent first-AuxPoW anchor, the second AuxPoW block still
    // uses the configured anchor target.  The third one is the first whose
    // target reflects elapsed time since the first AuxPoW block.
    append_header(
        /*auxpow=*/true,
        headers[2].nTime + consensus.nPowTargetSpacingAuxPow +
            consensus.nASERTHalfLife,
        anchor_nbits);
    const uint32_t expected_auxpow_nbits{
        CalculateASERT(
            arith_uint256{}.SetCompact(anchor_nbits),
            consensus.nPowTargetSpacingAuxPow,
            headers[4].GetBlockTime() - headers[2].GetBlockTime(),
            1,
            pow_limit,
            consensus.nASERTHalfLife
        ).GetCompact()};
    BOOST_REQUIRE(expected_auxpow_nbits != anchor_nbits);
    append_header(
        /*auxpow=*/true,
        headers.back().nTime + 1,
        expected_auxpow_nbits);

    arith_uint256 required_work{chain_start->nChainWork};
    for (const auto& header : headers) {
        required_work += GetBlockProof(CBlockIndex{header});
    }

    HeadersSyncState valid_sync{
        0, consensus, chain_start, required_work};
    auto result{valid_sync.ProcessNextHeaders(headers, true)};
    BOOST_CHECK(result.success);
    BOOST_CHECK(result.request_more);
    BOOST_CHECK(
        valid_sync.GetState() == HeadersSyncState::State::REDOWNLOAD);

    result = valid_sync.ProcessNextHeaders(headers, false);
    BOOST_CHECK(result.success);
    BOOST_CHECK(!result.request_more);
    BOOST_CHECK_EQUAL(result.pow_validated_headers.size(), headers.size());
    BOOST_CHECK(valid_sync.GetState() == HeadersSyncState::State::FINAL);

    std::vector<CBlockHeader> invalid_headers{headers};
    invalid_headers.back().nBits = anchor_nbits;

    HeadersSyncState invalid_sync{
        0, consensus, chain_start, required_work + 1};
    result = invalid_sync.ProcessNextHeaders(invalid_headers, true);
    BOOST_CHECK(!result.success);
    BOOST_CHECK(invalid_sync.GetState() == HeadersSyncState::State::FINAL);
}

BOOST_AUTO_TEST_CASE(headers_sync_ruble_auxpow_first_block_anchor)
{
    Consensus::Params consensus{Params().GetConsensus()};
    consensus.fPowNoRetargeting = false;
    consensus.fPowAllowMinDifficultyBlocks = false;
    consensus.fAuxpowFirstBlockASERTAnchor = true;
    consensus.nPowTargetSpacingLegacy = 270;
    consensus.nPowTargetSpacingAuxPow = 540;
    consensus.nASERTHalfLife = 2 * 60 * 60;
    consensus.powLimit = uint256{
        "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    constexpr uint32_t anchor_nbits{0x1c0fffff};
    consensus.asertAnchorParams = Consensus::Params::ASERTAnchor{
        0,
        anchor_nbits,
        anchor_nbits,
        Params().GenesisBlock().GetBlockTime(),
    };

    const CBlockIndex* chain_start = WITH_LOCK(
        ::cs_main,
        return m_node.chainman->m_blockman.LookupBlockIndex(
            Params().GenesisBlock().GetHash()));
    BOOST_REQUIRE(chain_start != nullptr);

    std::vector<CBlockHeader> headers;
    auto append_header = [&](bool auxpow, uint32_t time, uint32_t nbits) {
        CBlockHeader header;
        header.nVersion = 4;
        header.SetAuxpowVersion(auxpow);
        header.hashPrevBlock = headers.empty()
            ? chain_start->GetBlockHash()
            : headers.back().GetHash();
        header.hashMerkleRoot = ArithToUint256(headers.size() + 500);
        header.nTime = time;
        header.nBits = nbits;
        header.nNonce = static_cast<uint32_t>(headers.size());
        headers.push_back(header);
    };

    const uint32_t launch_time{Params().GenesisBlock().nTime + 1};
    append_header(/*auxpow=*/false, launch_time, anchor_nbits);
    append_header(
        /*auxpow=*/true,
        launch_time + 4 * 24 * 60 * 60,
        anchor_nbits);
    append_header(
        /*auxpow=*/true,
        headers.back().nTime + consensus.nPowTargetSpacingAuxPow,
        anchor_nbits);

    arith_uint256 required_work{chain_start->nChainWork};
    for (const auto& header : headers) {
        required_work += GetBlockProof(CBlockIndex{header});
    }

    HeadersSyncState valid_sync{0, consensus, chain_start, required_work};
    auto result{valid_sync.ProcessNextHeaders(headers, true)};
    BOOST_CHECK(result.success);
    BOOST_CHECK(result.request_more);

    const uint32_t obsolete_launch_time_bits{
        CalculateASERT(
            arith_uint256{}.SetCompact(anchor_nbits),
            consensus.nPowTargetSpacingAuxPow,
            headers[1].GetBlockTime() - launch_time,
            1,
            UintToArith256(consensus.powLimit),
            consensus.nASERTHalfLife
        ).GetCompact()};
    BOOST_REQUIRE(obsolete_launch_time_bits != anchor_nbits);

    std::vector<CBlockHeader> invalid_headers{headers};
    invalid_headers.back().nBits = obsolete_launch_time_bits;
    HeadersSyncState invalid_sync{0, consensus, chain_start, required_work + 1};
    result = invalid_sync.ProcessNextHeaders(invalid_headers, true);
    BOOST_CHECK(!result.success);
    BOOST_CHECK(invalid_sync.GetState() == HeadersSyncState::State::FINAL);
}

BOOST_AUTO_TEST_CASE(headers_sync_ruble_auxpow_activation_boundary)
{
    Consensus::Params consensus{Params().GetConsensus()};
    consensus.fPowNoRetargeting = true;
    consensus.nAuxpowActivationHeight = 3;

    BOOST_CHECK(!consensus.IsAuxpowEnabled(2));
    BOOST_CHECK(consensus.IsAuxpowEnabled(3));
    BOOST_CHECK(consensus.IsAuxpowEnabled(4));

    const CBlockIndex* chain_start = WITH_LOCK(
        ::cs_main,
        return m_node.chainman->m_blockman.LookupBlockIndex(
            Params().GenesisBlock().GetHash()));
    BOOST_REQUIRE(chain_start != nullptr);

    auto make_headers = [&](const std::vector<bool>& channels) {
        std::vector<CBlockHeader> headers;
        uint256 previous_hash{chain_start->GetBlockHash()};
        uint32_t previous_time{static_cast<uint32_t>(chain_start->GetBlockTime())};
        for (size_t i = 0; i < channels.size(); ++i) {
            CBlockHeader header;
            header.nVersion = 4;
            header.SetAuxpowVersion(channels[i]);
            header.hashPrevBlock = previous_hash;
            header.hashMerkleRoot = ArithToUint256(i + 10'000);
            header.nTime = ++previous_time;
            header.nBits = chain_start->nBits;
            header.nNonce = static_cast<uint32_t>(i);
            previous_hash = header.GetHash();
            headers.push_back(header);
        }
        return headers;
    };

    // An otherwise well-formed AuxPoW header at H-1 must fail during
    // presync and must not contribute to claimed chain work.
    const auto premature_headers{make_headers({false, true})};
    arith_uint256 premature_work{chain_start->nChainWork};
    for (const auto& header : premature_headers) {
        premature_work += GetBlockProof(CBlockIndex{header});
    }
    HeadersSyncState premature_sync{
        0, consensus, chain_start, premature_work};
    auto result{premature_sync.ProcessNextHeaders(premature_headers, true)};
    BOOST_CHECK(!result.success);
    BOOST_CHECK(premature_sync.GetState() == HeadersSyncState::State::FINAL);

    // Native H-1, AuxPoW H, and AuxPoW H+1 are all valid at the boundary.
    const auto boundary_headers{make_headers({false, false, true, true})};
    arith_uint256 boundary_work{chain_start->nChainWork};
    for (const auto& header : boundary_headers) {
        boundary_work += GetBlockProof(CBlockIndex{header});
    }
    HeadersSyncState boundary_sync{0, consensus, chain_start, boundary_work};
    result = boundary_sync.ProcessNextHeaders(boundary_headers, true);
    BOOST_CHECK(result.success);
    BOOST_CHECK(result.request_more);
    BOOST_CHECK(boundary_sync.GetState() == HeadersSyncState::State::REDOWNLOAD);
}

BOOST_AUTO_TEST_CASE(headers_sync_fixed_launch_block)
{
    Consensus::Params consensus{Params().GetConsensus()};
    consensus.fRequireLaunchBlock = true;
    consensus.hashLaunchBlock.SetNull();
    consensus.nLaunchBlockTime = 0;
    consensus.asertAnchorParams.nBitsLegacy = Params().GenesisBlock().nBits;

    const CBlockIndex* chain_start = WITH_LOCK(
        ::cs_main,
        return m_node.chainman->m_blockman.LookupBlockIndex(
            Params().GenesisBlock().GetHash()));
    BOOST_REQUIRE(chain_start != nullptr);

    std::vector<CBlockHeader> headers;
    GenerateHeaders(
        headers, 1, chain_start->GetBlockHash(), 4,
        chain_start->GetBlockTime(), ArithToUint256(1),
        Params().GenesisBlock().nBits);
    BOOST_REQUIRE_EQUAL(headers.size(), 1U);

    const arith_uint256 required_work{
        chain_start->nChainWork + GetBlockProof(CBlockIndex{headers.front()})};
    HeadersSyncState locked_sync{0, consensus, chain_start, required_work};
    auto result{locked_sync.ProcessNextHeaders(headers, true)};
    BOOST_CHECK(!result.success);
    BOOST_CHECK(locked_sync.GetState() == HeadersSyncState::State::FINAL);

    consensus.nLaunchBlockTime = headers.front().nTime;
    consensus.hashLaunchBlock = headers.front().GetHash();
    HeadersSyncState exact_sync{0, consensus, chain_start, required_work};
    result = exact_sync.ProcessNextHeaders(headers, true);
    BOOST_CHECK(result.success);
    BOOST_CHECK(result.request_more);
    BOOST_CHECK(exact_sync.GetState() == HeadersSyncState::State::REDOWNLOAD);

    // Starting presync from an old index that already contains a different
    // block 1 must fail on the next header. It must not create a partially
    // usable ASERT state merely because height 2 is not itself a genesis child.
    CBlockHeader invalid_launch{headers.front()};
    ++invalid_launch.nNonce;
    uint256 invalid_launch_hash{invalid_launch.GetHash()};
    CBlockIndex invalid_launch_index{invalid_launch};
    invalid_launch_index.phashBlock = &invalid_launch_hash;
    invalid_launch_index.pprev = const_cast<CBlockIndex*>(chain_start);
    invalid_launch_index.nHeight = 1;
    invalid_launch_index.nTimeMax = std::max(
        chain_start->nTimeMax, invalid_launch_index.nTime);
    invalid_launch_index.nChainWork =
        chain_start->nChainWork + GetBlockProof(invalid_launch_index);
    invalid_launch_index.nAuxPow = 0;
    invalid_launch_index.BuildSkip();

    std::vector<CBlockHeader> height_two;
    GenerateHeaders(
        height_two, 1, invalid_launch_hash, 4,
        invalid_launch.nTime, ArithToUint256(2),
        Params().GenesisBlock().nBits);
    BOOST_REQUIRE_EQUAL(height_two.size(), 1U);

    const arith_uint256 height_two_work{
        invalid_launch_index.nChainWork +
        GetBlockProof(CBlockIndex{height_two.front()})};
    HeadersSyncState invalid_fork_sync{
        0, consensus, &invalid_launch_index, height_two_work};
    result = invalid_fork_sync.ProcessNextHeaders(height_two, true);
    BOOST_CHECK(!result.success);
    BOOST_CHECK(invalid_fork_sync.GetState() == HeadersSyncState::State::FINAL);
}

BOOST_AUTO_TEST_CASE(headers_sync_ruble_non_genesis_channel_state)
{
    Consensus::Params consensus{Params().GetConsensus()};
    consensus.fPowNoRetargeting = false;
    consensus.fPowAllowMinDifficultyBlocks = false;
    consensus.fAuxpowFirstBlockASERTAnchor = true;
    consensus.nPowTargetSpacingLegacy = 270;
    consensus.nPowTargetSpacingAuxPow = 540;
    consensus.nASERTHalfLife = 2 * 60 * 60;
    consensus.powLimit = uint256{
        "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

    constexpr uint32_t anchor_nbits{0x1c0fffff};
    consensus.asertAnchorParams = Consensus::Params::ASERTAnchor{
        0,
        anchor_nbits,
        anchor_nbits,
        Params().GenesisBlock().GetBlockTime(),
    };

    // Build an indexed chain whose first two post-launch AuxPoW blocks are far
    // behind the chain start. This exercises MakeDifficultyState's skiplist
    // lookup for both the independent first-AuxPoW anchor and the channel tip,
    // not merely its genesis/no-channel path.
    constexpr int tip_height{1024};
    std::vector<CBlockIndex> blocks(tip_height + 1);
    std::vector<uint256> hashes(tip_height + 1);
    const uint32_t launch_time{Params().GenesisBlock().nTime + 1};

    for (int height = 0; height <= tip_height; ++height) {
        CBlockHeader header;
        if (height == 0) {
            const CBlock& genesis{Params().GenesisBlock()};
            header.nVersion = genesis.nVersion;
            header.hashPrevBlock = genesis.hashPrevBlock;
            header.hashMerkleRoot = genesis.hashMerkleRoot;
            header.nTime = genesis.nTime;
            header.nBits = genesis.nBits;
            header.nNonce = genesis.nNonce;
        } else {
            const bool is_auxpow{height == 2 || height == 3};
            header.nVersion = 4;
            header.SetAuxpowVersion(is_auxpow);
            header.hashPrevBlock = hashes[height - 1];
            header.hashMerkleRoot = ArithToUint256(height + 1000);
            if (height == 1) {
                header.nTime = launch_time;
            } else if (height == 2) {
                header.nTime = launch_time + consensus.nPowTargetSpacingAuxPow +
                    consensus.nASERTHalfLife;
            } else if (height == 3) {
                header.nTime = blocks[height - 1].nTime +
                    consensus.nPowTargetSpacingAuxPow +
                    consensus.nASERTHalfLife;
            } else {
                header.nTime = blocks[height - 1].nTime +
                    consensus.nPowTargetSpacingLegacy;
            }
            header.nBits = anchor_nbits;
            header.nNonce = height;
        }

        hashes[height] = header.GetHash();
        CBlockIndex& index{blocks[height]};
        index.phashBlock = &hashes[height];
        index.pprev = height == 0 ? nullptr : &blocks[height - 1];
        index.nHeight = height;
        index.nVersion = header.nVersion;
        index.hashMerkleRoot = header.hashMerkleRoot;
        index.nTime = header.nTime;
        index.nTimeMax = height == 0
            ? header.nTime
            : std::max(blocks[height - 1].nTimeMax, header.nTime);
        index.nBits = header.nBits;
        index.nNonce = header.nNonce;
        index.nAuxPow = height == 0 ? 0 : blocks[height - 1].nAuxPow;
        if (header.IsAuxpow()) ++index.nAuxPow;
        index.nChainWork = (height == 0 ? arith_uint256{} : blocks[height - 1].nChainWork) +
            GetBlockProof(index);
        index.BuildSkip();
    }

    const arith_uint256 pow_limit{UintToArith256(consensus.powLimit)};
    const uint32_t expected_auxpow_nbits{
        CalculateASERT(
            arith_uint256{}.SetCompact(anchor_nbits),
            consensus.nPowTargetSpacingAuxPow,
            blocks[3].GetBlockTime() - blocks[2].GetBlockTime(),
            1,
            pow_limit,
            consensus.nASERTHalfLife
        ).GetCompact()};
    BOOST_REQUIRE(expected_auxpow_nbits != anchor_nbits);

    CBlockHeader candidate;
    candidate.nVersion = 4;
    candidate.SetAuxpowVersion(true);
    candidate.hashPrevBlock = hashes.back();
    candidate.hashMerkleRoot = ArithToUint256(tip_height + 1001);
    candidate.nTime = blocks.back().nTime + 1;
    candidate.nBits = expected_auxpow_nbits;

    const arith_uint256 required_work{
        blocks.back().nChainWork + GetBlockProof(CBlockIndex{candidate})};
    HeadersSyncState sync{0, consensus, &blocks.back(), required_work};
    const auto result{sync.ProcessNextHeaders({candidate}, true)};
    BOOST_CHECK(result.success);
    BOOST_CHECK(result.request_more);
    BOOST_CHECK(sync.GetState() == HeadersSyncState::State::REDOWNLOAD);
}

BOOST_AUTO_TEST_SUITE_END()
