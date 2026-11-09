// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <logging.h>
#include <primitives/block.h>
#include <uint256.h>
#include <util/check.h>

namespace {

uint64_t ChannelCount(const CBlockIndex& index, bool is_auxpow) noexcept
{
    assert(index.nHeight >= 0);
    assert(index.nAuxPow <= static_cast<uint64_t>(index.nHeight) + 1);
    return is_auxpow
        ? index.nAuxPow
        : static_cast<uint64_t>(index.nHeight) + 1 - index.nAuxPow;
}

} // namespace

bool IsLaunchBlockConfigured(const Consensus::Params& params) noexcept
{
    return !params.hashLaunchBlock.IsNull() && params.nLaunchBlockTime != 0;
}

bool CheckLaunchBlockCommitment(const CPureBlockHeader& block, const Consensus::Params& params) noexcept
{
    if (!params.fRequireLaunchBlock || block.hashPrevBlock != params.hashGenesisBlock) {
        return true;
    }

    return IsLaunchBlockConfigured(params) &&
        !block.IsAuxpow() &&
        block.nTime == params.nLaunchBlockTime &&
        block.nBits == params.asertAnchorParams.nBitsLegacy &&
        block.GetHash() == params.hashLaunchBlock;
}

const CBlockIndex* FindLastBlockInChannel(const CBlockIndex* tip, bool is_auxpow, int exclusive_anchor_height) noexcept
{
    assert(tip != nullptr);
    assert(exclusive_anchor_height >= 0);
    assert(exclusive_anchor_height <= tip->nHeight);

    const CBlockIndex* anchor{tip->GetAncestor(exclusive_anchor_height)};
    assert(anchor != nullptr);

    const uint64_t anchor_count{ChannelCount(*anchor, is_auxpow)};
    const uint64_t target_count{ChannelCount(*tip, is_auxpow)};
    assert(target_count >= anchor_count);
    if (target_count == anchor_count) return nullptr;

    // A channel count is monotonic and increases by exactly one at a block in
    // that channel. The first height at which the tip's count is reached is
    // therefore the last block in that channel on this branch.
    int lower{exclusive_anchor_height + 1};
    int upper{tip->nHeight};
    while (lower < upper) {
        const int middle{lower + (upper - lower) / 2};
        const CBlockIndex* candidate{tip->GetAncestor(middle)};
        assert(candidate != nullptr);
        if (ChannelCount(*candidate, is_auxpow) < target_count) {
            lower = middle + 1;
        } else {
            upper = middle;
        }
    }

    const CBlockIndex* result{tip->GetAncestor(lower)};
    assert(result != nullptr);
    assert(ChannelCount(*result, is_auxpow) == target_count);
    assert(result->IsAuxpow() == is_auxpow);
    return result;
}

const CBlockIndex* FindFirstBlockInChannel(const CBlockIndex* tip, bool is_auxpow, int exclusive_anchor_height) noexcept
{
    assert(tip != nullptr);
    assert(exclusive_anchor_height >= 0);
    assert(exclusive_anchor_height <= tip->nHeight);

    const CBlockIndex* anchor{tip->GetAncestor(exclusive_anchor_height)};
    assert(anchor != nullptr);

    const uint64_t anchor_count{ChannelCount(*anchor, is_auxpow)};
    if (ChannelCount(*tip, is_auxpow) == anchor_count) return nullptr;

    // The first block in this channel is the earliest height whose cumulative
    // channel count is one greater than the count at the exclusive anchor.
    const uint64_t first_count{anchor_count + 1};
    int lower{exclusive_anchor_height + 1};
    int upper{tip->nHeight};
    while (lower < upper) {
        const int middle{lower + (upper - lower) / 2};
        const CBlockIndex* candidate{tip->GetAncestor(middle)};
        assert(candidate != nullptr);
        if (ChannelCount(*candidate, is_auxpow) < first_count) {
            lower = middle + 1;
        } else {
            upper = middle;
        }
    }

    const CBlockIndex* result{tip->GetAncestor(lower)};
    assert(result != nullptr);
    assert(ChannelCount(*result, is_auxpow) == first_count);
    assert(result->IsAuxpow() == is_auxpow);
    return result;
}

/**
 * Compute the next required proof of work using an absolutely scheduled
 * exponentially weighted target (ASERT).
 *
 * With ASERT, we define an ideal schedule for block issuance (e.g. 1 block every 600 seconds), and we calculate the
 * difficulty based on how far the most recent block's timestamp is ahead of or behind that schedule.
 * We set our targets (difficulty) exponentially. For every [nHalfLife] seconds ahead of or behind schedule we get, we
 * double or halve the difficulty.
 */
static uint32_t GetNextASERTWorkRequired(const CBlockIndex *pindexPrev,
                                         const CBlockHeader *pblock,
                                         const Consensus::Params &params) noexcept {
    // This cannot handle the genesis block and early blocks in general.
    assert(pindexPrev != nullptr);

    const Consensus::Params::ASERTAnchor &anchorParams = params.asertAnchorParams;

    // This ASERT implementation uses only a genesis anchor. A later anchor
    // needs explicit per-channel prefix counts and different reference-time
    // semantics.
    assert(anchorParams.nHeight == 0);
    assert(pindexPrev->nHeight > 0);

    const arith_uint256 powLimit = UintToArith256(params.powLimit);

    // The consensus-pinned native block 1 is the live schedule origin. Its
    // exact timestamp is selected before launch and committed by its hash.
    assert(pindexPrev->pprev != nullptr);

    uint32_t anchornBits = anchorParams.nBitsLegacy;
    int64_t nPowTargetSpacing = params.nPowTargetSpacingLegacy;
    if (pblock->IsAuxpow()) {
        anchornBits = anchorParams.nBitsAuxPow;
        nPowTargetSpacing = params.nPowTargetSpacingAuxPow;
    }
    const arith_uint256 refBlockTarget = arith_uint256().SetCompact(anchornBits);

    const CBlockIndex* launch_block{pindexPrev->GetAncestor(1)};
    assert(launch_block != nullptr);
    if (params.fRequireLaunchBlock) {
        assert(CheckLaunchBlockCommitment(launch_block->GetPureHeader(), params));
    }
    int64_t reference_time{
        params.fRequireLaunchBlock
            ? static_cast<int64_t>(params.nLaunchBlockTime)
            : launch_block->GetBlockTime()};

    // Count only same-channel blocks after the launch block. If block 1
    // belongs to this channel, it establishes time zero and is excluded.
    int64_t nHeightDiff;
    if (pblock->IsAuxpow() && params.fAuxpowFirstBlockASERTAnchor) {
        // The first AuxPoW block is both the initial-target block and the
        // independent AuxPoW time origin. The second block therefore keeps
        // the initial target; its timestamp completes the first interval used
        // when calculating the third block's target.
        const CBlockIndex* first_auxpow{FindFirstBlockInChannel(
            pindexPrev, /*is_auxpow=*/true, anchorParams.nHeight)};
        assert(first_auxpow != nullptr);
        assert(first_auxpow->nBits == anchorParams.nBitsAuxPow);
        reference_time = first_auxpow->GetBlockTime();
        nHeightDiff = static_cast<int64_t>(pindexPrev->nAuxPow) -
            static_cast<int64_t>(first_auxpow->nAuxPow);
    } else if (pblock->IsAuxpow()) {
        nHeightDiff = pindexPrev->nAuxPow - (launch_block->IsAuxpow() ? 1 : 0);
    } else {
        nHeightDiff = pindexPrev->nHeight - pindexPrev->nAuxPow - (launch_block->IsAuxpow() ? 0 : 1);
    }
    assert(nHeightDiff >= 0);
    if (nHeightDiff == 0) {
        return anchornBits;
    }
    const int64_t nTimeDiff = pindexPrev->GetBlockTime() - reference_time;

    // Do the actual target adaptation calculation in separate
    // CalculateASERT() function
    arith_uint256 nextTarget = CalculateASERT(refBlockTarget,
                                              nPowTargetSpacing,
                                              nTimeDiff,
                                              nHeightDiff,
                                              powLimit,
                                              params.nASERTHalfLife);

    // CalculateASERT() already clamps to powLimit.
    return nextTarget.GetCompact();
}

// ASERT calculation function.
// Clamps to powLimit.
arith_uint256 CalculateASERT(const arith_uint256 &refTarget,
                             const int64_t nPowTargetSpacing,
                             const int64_t nTimeDiff,
                             const int64_t nHeightDiff,
                             const arith_uint256 &powLimit,
                             const int64_t nHalfLife) noexcept {

    // Input target must never be zero nor exceed powLimit.
    assert(refTarget > 0 && refTarget <= powLimit);

    // We need some leading zero bits in powLimit in order to have room to handle
    // overflows easily. 32 leading zero bits is more than enough.
    assert((powLimit >> 224) == 0);

    // Height diff should NOT be negative.
    assert(nHeightDiff > 0);

    // It will be helpful when reading what follows, to remember that
    // nextTarget is adapted from anchor block target value.

    // Ultimately, we want to approximate the following ASERT formula, using only integer (fixed-point) math:
    //     new_target = old_target * 2^((blocks_time - IDEAL_BLOCK_TIME * (height_diff + 1)) / nHalfLife)

    // First, we'll calculate the exponent:
    assert( llabs(nTimeDiff - nPowTargetSpacing * nHeightDiff) < (1ll << (63 - 16)) );
    const int64_t exponent = ((nTimeDiff - nPowTargetSpacing * (nHeightDiff)) * 65536) / nHalfLife;

    // Next, we use the 2^x = 2 * 2^(x-1) identity to shift our exponent into the [0, 1) interval.
    // The truncated exponent tells us how many shifts we need to do
    // Note1: This needs to be a right shift. Right shift rounds downward (floored division),
    //        whereas integer division in C++ rounds towards zero (truncated division).
    // Note2: This algorithm uses arithmetic shifts of negative numbers. This
    //        is unpecified but very common behavior for C++ compilers before
    //        C++20, and standard with C++20. We must check this behavior e.g.
    //        using static_assert.
    static_assert(int64_t(-1) >> 1 == int64_t(-1),
                  "ASERT algorithm needs arithmetic shift support");

    // Now we compute an approximated target * 2^(exponent/65536.0)

    // First decompose exponent into 'integer' and 'fractional' parts:
    int64_t shifts = exponent >> 16;
    const auto frac = uint16_t(exponent);
    assert(exponent == (shifts * 65536) + frac);

    // multiply target by 65536 * 2^(fractional part)
    // 2^x ~= (1 + 0.695502049*x + 0.2262698*x**2 + 0.0782318*x**3) for 0 <= x < 1
    // Error versus actual 2^x is less than 0.013%.
    const uint32_t factor = 65536 + ((
        + 195766423245049ull * frac
        + 971821376ull * frac * frac
        + 5127ull * frac * frac * frac
        + (1ull << 47)
        ) >> 48);
    // this is always < 2^241 since refTarget < 2^224
    arith_uint256 nextTarget = refTarget * factor;

    // multiply by 2^(integer part) / 65536
    shifts -= 16;
    if (shifts <= 0) {
        nextTarget >>= -shifts;
    } else {
        // Detect overflow that would discard high bits
        const auto nextTargetShifted = nextTarget << shifts;
        if ((nextTargetShifted >> shifts) != nextTarget) {
            // If we had wider integers, the final value of nextTarget would
            // be >= 2^256 so it would have just ended up as powLimit anyway.
            nextTarget = powLimit;
        } else {
            // Shifting produced no overflow, can assign value
            nextTarget = nextTargetShifted;
        }
    }

    if (nextTarget == 0) {
        // 0 is not a valid target, but 1 is.
        nextTarget = arith_uint256(1);
    } else if (nextTarget > powLimit) {
        nextTarget = powLimit;
    }

    // we return from only 1 place for copy elision
    return nextTarget;
}


unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    assert(params.asertAnchorParams.nHeight == 0);

    // Special rule for regtest: we never retarget.
    if (params.fPowNoRetargeting) {
        return pindexLast->nBits;
    }

    if (pindexLast->nHeight <= params.asertAnchorParams.nHeight) {
        return pblock->IsAuxpow()
            ? params.asertAnchorParams.nBitsAuxPow
            : params.asertAnchorParams.nBitsLegacy;
    }

    // Special difficulty rule for testnet
    // If the new block's timestamp is more than 2 * 10 minutes then allow
    // mining of a min-difficulty block.
    if (params.fPowAllowMinDifficultyBlocks &&
        (pblock->GetBlockTime() >
         pindexLast->GetBlockTime() + 2 * params.nPowTargetSpacingAuxPow)) {
        return UintToArith256(params.powLimit).GetCompact();
    }

    const CBlockIndex* pindexPrev{FindLastBlockInChannel(
        pindexLast, pblock->IsAuxpow(), params.asertAnchorParams.nHeight)};
    if (pindexPrev == nullptr) {
        return pblock->IsAuxpow()
            ? params.asertAnchorParams.nBitsAuxPow
            : params.asertAnchorParams.nBitsLegacy;
    }

    return GetNextASERTWorkRequired(pindexPrev, pblock, params);
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;

    // Special difficulty rule for Testnet4
    if (params.enforce_BIP94) {
        // Here we use the first block of the difficulty period. This way
        // the real difficulty is always preserved in the first block as
        // it is not allowed to use the min-difficulty exception.
        int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
        const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
        bnNew.SetCompact(pindexFirst->nBits);
    } else {
        bnNew.SetCompact(pindexLast->nBits);
    }

    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

// Check that on difficulty adjustments, the new difficulty does not increase
// or decrease beyond the permitted limits.
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits)
{
    if (params.fPowAllowMinDifficultyBlocks) return true;

    if (height % params.DifficultyAdjustmentInterval() == 0) {
        int64_t smallest_timespan = params.nPowTargetTimespan/4;
        int64_t largest_timespan = params.nPowTargetTimespan*4;

        const arith_uint256 pow_limit = UintToArith256(params.powLimit);
        arith_uint256 observed_new_target;
        observed_new_target.SetCompact(new_nbits);

        // Calculate the largest difficulty value possible:
        arith_uint256 largest_difficulty_target;
        largest_difficulty_target.SetCompact(old_nbits);
        largest_difficulty_target *= largest_timespan;
        largest_difficulty_target /= params.nPowTargetTimespan;

        if (largest_difficulty_target > pow_limit) {
            largest_difficulty_target = pow_limit;
        }

        // Round and then compare this new calculated value to what is
        // observed.
        arith_uint256 maximum_new_target;
        maximum_new_target.SetCompact(largest_difficulty_target.GetCompact());
        if (maximum_new_target < observed_new_target) return false;

        // Calculate the smallest difficulty value possible:
        arith_uint256 smallest_difficulty_target;
        smallest_difficulty_target.SetCompact(old_nbits);
        smallest_difficulty_target *= smallest_timespan;
        smallest_difficulty_target /= params.nPowTargetTimespan;

        if (smallest_difficulty_target > pow_limit) {
            smallest_difficulty_target = pow_limit;
        }

        // Round and then compare this new calculated value to what is
        // observed.
        arith_uint256 minimum_new_target;
        minimum_new_target.SetCompact(smallest_difficulty_target.GetCompact());
        if (minimum_new_target > observed_new_target) return false;
    } else if (old_nbits != new_nbits) {
        return false;
    }
    return true;
}

// Bypasses the actual proof of work check during fuzz testing with a simplified validation checking whether
// the most significant bit of the last byte of the hash is set.
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    if constexpr (G_FUZZING) return (hash.data()[31] & 0x80) == 0;
    return CheckProofOfWorkImpl(hash, nBits, params);
}

std::optional<arith_uint256> DeriveTarget(unsigned int nBits, const uint256 pow_limit)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(pow_limit))
        return {};

    return bnTarget;
}

bool CheckProofOfWorkImpl(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    auto bnTarget{DeriveTarget(nBits, params.powLimit)};
    if (!bnTarget) return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
