// Copyright (c) 2020-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <pow.h>
#include <primitives/block.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <util/chaintype.h>
#include <util/check.h>
#include <util/overflow.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

void initialize_pow()
{
    SelectParams(ChainType::MAIN);
}

FUZZ_TARGET(pow, .init = initialize_pow)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    const Consensus::Params& consensus_params = Params().GetConsensus();
    std::vector<std::unique_ptr<CBlockIndex>> blocks;
    const uint32_t fixed_time = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
    const uint32_t fixed_bits = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
    LIMITED_WHILE(fuzzed_data_provider.remaining_bytes() > 0, 10000) {
        const std::optional<CBlockHeader> block_header = ConsumeDeserializable<CBlockHeader>(fuzzed_data_provider);
        if (!block_header) {
            continue;
        }
        CBlockIndex& current_block{
            *blocks.emplace_back(std::make_unique<CBlockIndex>(*block_header))};
        {
            CBlockIndex* previous_block = blocks.empty() ? nullptr : PickValue(fuzzed_data_provider, blocks).get();
            const int current_height = (previous_block != nullptr && previous_block->nHeight != std::numeric_limits<int>::max()) ? previous_block->nHeight + 1 : 0;
            if (fuzzed_data_provider.ConsumeBool()) {
                current_block.pprev = previous_block;
            }
            if (fuzzed_data_provider.ConsumeBool()) {
                current_block.nHeight = current_height;
            }
            if (fuzzed_data_provider.ConsumeBool()) {
                const uint32_t seconds = current_height * consensus_params.nPowTargetSpacing;
                if (!AdditionOverflow(fixed_time, seconds)) {
                    current_block.nTime = fixed_time + seconds;
                }
            }
            if (fuzzed_data_provider.ConsumeBool()) {
                current_block.nBits = fixed_bits;
            }
            if (fuzzed_data_provider.ConsumeBool()) {
                current_block.nChainWork = previous_block != nullptr ? previous_block->nChainWork + GetBlockProof(*previous_block) : arith_uint256{0};
            } else {
                current_block.nChainWork = ConsumeArithUInt256(fuzzed_data_provider);
            }
        }
        {
            (void)GetBlockProof(current_block);
            (void)CalculateNextWorkRequired(&current_block, fuzzed_data_provider.ConsumeIntegralInRange<int64_t>(0, std::numeric_limits<int64_t>::max()), consensus_params);
            // GetNextWorkRequired requires a structurally consistent ancestry
            // with cumulative channel counts and skiplists. That contract is
            // covered by the dedicated pow_transition target below.
        }
        {
            const auto& to = PickValue(fuzzed_data_provider, blocks);
            const auto& from = PickValue(fuzzed_data_provider, blocks);
            const auto& tip = PickValue(fuzzed_data_provider, blocks);
            try {
                (void)GetBlockProofEquivalentTime(*to, *from, *tip, consensus_params);
            } catch (const uint_error&) {
            }
        }
        {
            const std::optional<uint256> hash = ConsumeDeserializable<uint256>(fuzzed_data_provider);
            if (hash) {
                (void)CheckProofOfWorkImpl(*hash, fuzzed_data_provider.ConsumeIntegral<unsigned int>(), consensus_params);
            }
        }
    }
}


FUZZ_TARGET(pow_transition, .init = initialize_pow)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    Consensus::Params consensus_params{Params().GetConsensus()};
    std::vector<std::unique_ptr<CBlockIndex>> blocks;

    const uint32_t old_time{fuzzed_data_provider.ConsumeIntegral<uint32_t>()};
    const uint32_t new_time{fuzzed_data_provider.ConsumeIntegral<uint32_t>()};
    const int max_chain_length{static_cast<int>(consensus_params.DifficultyAdjustmentInterval())};
    const int chain_length{fuzzed_data_provider.ConsumeIntegralInRange<int>(
        2, max_chain_length)};
    std::vector<uint256> block_hashes;
    block_hashes.reserve(chain_length);

    // Build a structurally consistent synthetic chain. GetNextWorkRequired()
    // relies on pprev, height, and the cumulative AuxPoW count when selecting
    // the independent ASERT schedule for the candidate's mining channel.
    for (int height = 0; height < chain_length; ++height) {
        // Mainnet requires a native block 1. Later blocks may use either
        // channel, so the target still explores both independent schedules.
        const bool is_auxpow{height > 1 && fuzzed_data_provider.ConsumeBool()};
        CBlockHeader header;
        header.nVersion = 4;
        if (is_auxpow) {
            header.SetBaseVersion(4, consensus_params.nAuxpowChainId);
            header.SetAuxpowVersion(true);
        }
        header.hashPrevBlock = block_hashes.empty()
            ? uint256{}
            : block_hashes.back();
        header.hashMerkleRoot = ArithToUint256(height + 1);
        header.nTime = height == chain_length - 1 ? new_time : old_time;
        if (height == 1 && header.nTime == 0) header.nTime = 1;
        header.nBits = is_auxpow
            ? consensus_params.asertAnchorParams.nBitsAuxPow
            : consensus_params.asertAnchorParams.nBitsLegacy;

        auto current_block{std::make_unique<CBlockIndex>(header)};
        current_block->pprev = blocks.empty() ? nullptr : blocks.back().get();
        block_hashes.emplace_back(
            height == 0 ? consensus_params.hashGenesisBlock : header.GetHash());
        current_block->phashBlock = &block_hashes.back();
        current_block->nHeight = height;
        current_block->nAuxPow = current_block->pprev != nullptr
            ? current_block->pprev->nAuxPow
            : 0;
        if (is_auxpow) ++current_block->nAuxPow;
        current_block->BuildSkip();

        if (height == 1) {
            consensus_params.nLaunchBlockTime = header.nTime;
            consensus_params.hashLaunchBlock = block_hashes.back();
        }
        blocks.emplace_back(std::move(current_block));
    }

    CBlockHeader candidate;
    candidate.nVersion = 4;
    if (fuzzed_data_provider.ConsumeBool()) {
        candidate.SetBaseVersion(4, consensus_params.nAuxpowChainId);
        candidate.SetAuxpowVersion(true);
    }
    candidate.nTime = fuzzed_data_provider.ConsumeIntegral<uint32_t>();

    const unsigned int required_nbits{
        GetNextWorkRequired(blocks.back().get(), &candidate, consensus_params)};

    for (const bool is_auxpow : {false, true}) {
        const CBlockIndex* linear{blocks.back().get()};
        while (linear->nHeight > 0 && linear->IsAuxpow() != is_auxpow) {
            linear = linear->pprev;
        }
        if (linear->nHeight == 0) linear = nullptr;
        Assert(FindLastBlockInChannel(blocks.back().get(), is_auxpow, 0) == linear);
    }
    const auto required_target{DeriveTarget(required_nbits, consensus_params.powLimit)};
    const arith_uint256 pow_limit{UintToArith256(consensus_params.powLimit)};

    // ASERT may adjust on every block, so the legacy periodic-transition
    // invariant does not apply. Its consensus output must instead always be a
    // canonical, positive target bounded by the configured proof-of-work limit.
    Assert(required_target.has_value());
    Assert(*required_target > 0 && *required_target <= pow_limit);
    Assert(required_target->GetCompact() == required_nbits);
}
