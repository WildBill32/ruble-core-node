// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POW_H
#define BITCOIN_POW_H

#include <consensus/params.h>
#include <arith_uint256.h>

#include <stdint.h>

class CBlockHeader;
class CBlockIndex;
class CPureBlockHeader;
class uint256;
class arith_uint256;

/**
 * Convert nBits value to target.
 *
 * @param[in] nBits     compact representation of the target
 * @param[in] pow_limit PoW limit (consensus parameter)
 *
 * @return              the proof-of-work target or nullopt if the nBits value
 *                      is invalid (due to overflow or exceeding pow_limit)
 */
std::optional<arith_uint256> DeriveTarget(unsigned int nBits, const uint256 pow_limit);

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params&);
unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params&);

/**
 * Find the most recent block in the requested mining channel strictly after
 * exclusive_anchor_height. Uses the cumulative AuxPoW count and the block
 * index skiplist instead of a linear backward scan.
 */
const CBlockIndex* FindLastBlockInChannel(const CBlockIndex* tip, bool is_auxpow, int exclusive_anchor_height) noexcept;

/**
 * Find the first block in the requested mining channel strictly after
 * exclusive_anchor_height. Uses the cumulative channel count and skiplist.
 */
const CBlockIndex* FindFirstBlockInChannel(const CBlockIndex* tip, bool is_auxpow, int exclusive_anchor_height) noexcept;

/** Return whether all fields needed to unlock the pinned launch block exist. */
bool IsLaunchBlockConfigured(const Consensus::Params& params) noexcept;

/**
 * Enforce an unconditional native-PoW commitment for the child of genesis.
 * Other heights and networks without a required launch block are unaffected.
 */
bool CheckLaunchBlockCommitment(const CPureBlockHeader& block, const Consensus::Params& params) noexcept;

/** Check whether a block hash satisfies the proof-of-work requirement specified by nBits */
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params&);
bool CheckProofOfWorkImpl(uint256 hash, unsigned int nBits, const Consensus::Params&);

/**
 * Return false if the proof-of-work requirement specified by new_nbits at a
 * given height is not possible, given the proof-of-work on the prior block as
 * specified by old_nbits.
 *
 * This function only checks that the new value is within a factor of 4 of the
 * old value for blocks at the difficulty adjustment interval, and otherwise
 * requires the values to be the same.
 *
 * Always returns true on networks where min difficulty blocks are allowed,
 * such as regtest/testnet.
 */
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits);


arith_uint256 CalculateASERT(const arith_uint256 &refTarget,
                             const int64_t nPowTargetSpacing,
                             const int64_t nTimeDiff,
                             const int64_t nHeightDiff,
                             const arith_uint256 &powLimit,
                             const int64_t nHalfLife) noexcept;

#endif // BITCOIN_POW_H
