// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <headerssync.h>
#include <logging.h>
#include <pow.h>
#include <util/check.h>
#include <util/time.h>
#include <util/vector.h>

#include <algorithm>

// The two constants below are computed using the simulation script in
// contrib/devtools/headerssync-params.py.
//
// They are likely not ideal for auxpow, but we've kept them for now.

//! Store one header commitment per HEADER_COMMITMENT_PERIOD blocks.
constexpr size_t HEADER_COMMITMENT_PERIOD{624};

//! Only feed headers to validation once this many headers on top have been
//! received and validated against commitments.
constexpr size_t REDOWNLOAD_BUFFER_SIZE{14827}; // 14827/624 = ~23.8 commitments

HeadersSyncState::HeadersSyncState(NodeId id, const Consensus::Params& consensus_params,
        const CBlockIndex* chain_start, const arith_uint256& minimum_required_work) :
    m_commit_offset(FastRandomContext().randrange<unsigned>(HEADER_COMMITMENT_PERIOD)),
    m_id(id), m_consensus_params(consensus_params),
    m_chain_start(chain_start),
    m_minimum_required_work(minimum_required_work),
    m_current_chain_work(chain_start->nChainWork),
    m_last_header_received(m_chain_start->GetPureHeader()),
    m_current_height(chain_start->nHeight)
{
    Assert(m_consensus_params.asertAnchorParams.nHeight == 0);

    // Estimate the number of blocks that could possibly exist on the peer's
    // chain *right now* using 6 blocks/second (fastest blockrate given the MTP
    // rule) times the number of seconds from the last allowed block until
    // today. This serves as a memory bound on how many commitments we might
    // store from this peer, and we can safely give up syncing if the peer
    // exceeds this bound, because it's not possible for a consensus-valid
    // chain to be longer than this (at the current time -- in the future we
    // could try again, if necessary, to sync a longer chain).
    m_max_commitments = 6*(Ticks<std::chrono::seconds>(NodeClock::now() - NodeSeconds{std::chrono::seconds{chain_start->GetMedianTimePast()}}) + MAX_FUTURE_BLOCK_TIME) / HEADER_COMMITMENT_PERIOD;

    m_presync_difficulty_state = MakeDifficultyState(chain_start);
    m_redownload_difficulty_state = MakeDifficultyState(chain_start);

    LogDebug(BCLog::NET, "Initial headers sync started with peer=%d: height=%i, max_commitments=%i, min_work=%s\n", m_id, m_current_height, m_max_commitments, m_minimum_required_work.ToString());
}

HeadersSyncState::DifficultyState HeadersSyncState::MakeDifficultyState(const CBlockIndex* chain_start) const
{
    DifficultyState state;
    state.height = chain_start->nHeight;
    state.auxpow_count = chain_start->nAuxPow;
    state.last_nbits = chain_start->nBits;
    state.last_time = chain_start->GetBlockTime();

    std::vector<int64_t> reverse_times;
    reverse_times.reserve(CBlockIndex::nMedianTimeSpan);
    for (const CBlockIndex* cursor{chain_start};
         cursor != nullptr &&
             reverse_times.size() < CBlockIndex::nMedianTimeSpan;
         cursor = cursor->pprev) {
        reverse_times.push_back(cursor->GetBlockTime());
    }
    state.recent_times.assign(reverse_times.rbegin(), reverse_times.rend());

    constexpr int anchor_height{0};
    if (chain_start->nHeight >= 1) {
        const CBlockIndex* launch_block{chain_start->GetAncestor(1)};
        Assume(launch_block != nullptr);
        if (launch_block == nullptr) {
            state.valid = false;
            return state;
        }
        if (!CheckLaunchBlockCommitment(
                launch_block->GetPureHeader(), m_consensus_params)) {
            state.valid = false;
            return state;
        }
        state.launch_block_known = true;
        state.launch_block_auxpow = launch_block->IsAuxpow();
        state.launch_block_time = m_consensus_params.fRequireLaunchBlock
            ? m_consensus_params.nLaunchBlockTime
            : launch_block->GetBlockTime();
    }

    if (const CBlockIndex* auxpow_tip{FindLastBlockInChannel(
            chain_start, /*is_auxpow=*/true, anchor_height)}) {
        state.auxpow_tip_known = true;
        state.auxpow_tip_time = auxpow_tip->GetBlockTime();
    }
    if (m_consensus_params.fAuxpowFirstBlockASERTAnchor) {
        if (const CBlockIndex* auxpow_anchor{FindFirstBlockInChannel(
                chain_start, /*is_auxpow=*/true, anchor_height)}) {
            state.auxpow_anchor_known = true;
            state.auxpow_anchor_time = auxpow_anchor->GetBlockTime();
        }
    }
    if (const CBlockIndex* legacy_tip{FindLastBlockInChannel(
            chain_start, /*is_auxpow=*/false, anchor_height)}) {
        state.legacy_tip_known = true;
        state.legacy_tip_time = legacy_tip->GetBlockTime();
    }

    return state;
}

bool HeadersSyncState::ValidateAndAdvanceDifficulty(DifficultyState& state, const CPureBlockHeader& current) const
{
    // A fork point loaded from an old block index must never turn into a
    // partially usable difficulty state. In particular, no height-2 header
    // may advance on top of a launch block that violates the commitment.
    if (!state.valid) return false;

    // Premature AuxPoW headers must not contribute claimed work during the
    // low-memory presync phase. Final AcceptBlockHeader validation repeats
    // this consensus gate, but presync must fail before committing work from
    // a header that can never be accepted.
    const int64_t next_height{state.height + 1};
    if (current.IsAuxpow() &&
        !m_consensus_params.IsAuxpowEnabled(next_height)) {
        return false;
    }

    // Presync must enforce the launch commitment before using block 1 as the
    // ASERT time origin. Ordinary checkpoints are optional and cannot provide
    // this consensus guarantee.
    if (!CheckLaunchBlockCommitment(current, m_consensus_params)) {
        return false;
    }

    std::vector<int64_t> sorted_times{
        state.recent_times.begin(), state.recent_times.end()};
    std::sort(sorted_times.begin(), sorted_times.end());
    if (!sorted_times.empty() &&
        current.GetBlockTime() <= sorted_times[sorted_times.size() / 2]) {
        return false;
    }
    if (current.Time() >
        NodeClock::now() + std::chrono::seconds{MAX_FUTURE_BLOCK_TIME}) {
        return false;
    }

    const auto& anchor{m_consensus_params.asertAnchorParams};
    const bool is_auxpow{current.IsAuxpow()};
    const uint32_t anchor_nbits{
        is_auxpow ? anchor.nBitsAuxPow : anchor.nBitsLegacy};

    uint32_t expected_nbits;
    if (m_consensus_params.fPowNoRetargeting) {
        expected_nbits = state.last_nbits;
    } else if (state.height <= anchor.nHeight) {
        expected_nbits = anchor_nbits;
    } else if (m_consensus_params.fPowAllowMinDifficultyBlocks &&
               current.GetBlockTime() >
                   state.last_time + 2 * m_consensus_params.nPowTargetSpacingAuxPow) {
        expected_nbits = UintToArith256(m_consensus_params.powLimit).GetCompact();
    } else {
        const bool channel_tip_known{
            is_auxpow ? state.auxpow_tip_known : state.legacy_tip_known};
        if (!channel_tip_known) {
            expected_nbits = anchor_nbits;
        } else {
            if (anchor.nHeight != 0) return false;
            int64_t reference_time{anchor.nBlockTime};
            int64_t height_diff;

            if (!state.launch_block_known) return false;
            if (is_auxpow && m_consensus_params.fAuxpowFirstBlockASERTAnchor) {
                if (!state.auxpow_anchor_known || state.auxpow_count == 0) {
                    return false;
                }
                reference_time = state.auxpow_anchor_time;
                height_diff = static_cast<int64_t>(state.auxpow_count) - 1;
            } else {
                reference_time = m_consensus_params.fRequireLaunchBlock
                    ? m_consensus_params.nLaunchBlockTime
                    : state.launch_block_time;
            }
            if (is_auxpow && !m_consensus_params.fAuxpowFirstBlockASERTAnchor) {
                height_diff = state.auxpow_count -
                    (state.launch_block_auxpow ? 1 : 0);
            } else if (!is_auxpow) {
                height_diff = state.height - state.auxpow_count -
                    (state.launch_block_auxpow ? 0 : 1);
            }

            if (height_diff < 0) return false;
            if (height_diff == 0) {
                expected_nbits = anchor_nbits;
            } else {
                const int64_t channel_tip_time{
                    is_auxpow ? state.auxpow_tip_time : state.legacy_tip_time};
                const int64_t target_spacing{
                    is_auxpow ? m_consensus_params.nPowTargetSpacingAuxPow
                              : m_consensus_params.nPowTargetSpacingLegacy};
                expected_nbits = CalculateASERT(
                    arith_uint256{}.SetCompact(anchor_nbits),
                    target_spacing,
                    channel_tip_time - reference_time,
                    height_diff,
                    UintToArith256(m_consensus_params.powLimit),
                    m_consensus_params.nASERTHalfLife
                ).GetCompact();
            }
        }
    }

    if (current.nBits != expected_nbits) return false;

    ++state.height;
    if (is_auxpow) ++state.auxpow_count;

    if (anchor.nHeight == 0 && state.height == 1) {
        state.launch_block_known = true;
        state.launch_block_auxpow = is_auxpow;
        state.launch_block_time = m_consensus_params.fRequireLaunchBlock
            ? m_consensus_params.nLaunchBlockTime
            : current.GetBlockTime();
    }

    if (state.height > anchor.nHeight) {
        if (is_auxpow) {
            if (m_consensus_params.fAuxpowFirstBlockASERTAnchor &&
                !state.auxpow_anchor_known) {
                state.auxpow_anchor_known = true;
                state.auxpow_anchor_time = current.GetBlockTime();
            }
            state.auxpow_tip_known = true;
            state.auxpow_tip_time = current.GetBlockTime();
        } else {
            state.legacy_tip_known = true;
            state.legacy_tip_time = current.GetBlockTime();
        }
    }

    state.last_nbits = current.nBits;
    state.last_time = current.GetBlockTime();
    state.recent_times.push_back(current.GetBlockTime());
    if (state.recent_times.size() > CBlockIndex::nMedianTimeSpan) {
        state.recent_times.pop_front();
    }
    return true;
}

/** Free any memory in use, and mark this object as no longer usable. This is
 * required to guarantee that we won't reuse this object with the same
 * SaltedTxidHasher for another sync. */
void HeadersSyncState::Finalize()
{
    Assume(m_download_state != State::FINAL);
    ClearShrink(m_header_commitments);
    m_last_header_received.SetNull();
    ClearShrink(m_redownloaded_headers);
    m_redownload_buffer_last_hash.SetNull();
    m_redownload_buffer_first_prev_hash.SetNull();
    m_process_all_remaining_headers = false;
    m_current_height = 0;

    m_download_state = State::FINAL;
}

/** Process the next batch of headers received from our peer.
 *  Validate and store commitments, and compare total chainwork to our target to
 *  see if we can switch to REDOWNLOAD mode.  */
HeadersSyncState::ProcessingResult HeadersSyncState::ProcessNextHeaders(const
        std::vector<CBlockHeader>& received_headers, const bool full_headers_message)
{
    ProcessingResult ret;

    Assume(!received_headers.empty());
    if (received_headers.empty()) return ret;

    Assume(m_download_state != State::FINAL);
    if (m_download_state == State::FINAL) return ret;

    if (m_download_state == State::PRESYNC) {
        // During PRESYNC, we minimally validate block headers and
        // occasionally add commitments to them, until we reach our work
        // threshold (at which point m_download_state is updated to REDOWNLOAD).
        ret.success = ValidateAndStoreHeadersCommitments(received_headers);
        if (ret.success) {
            if (full_headers_message || m_download_state == State::REDOWNLOAD) {
                // A full headers message means the peer may have more to give us;
                // also if we just switched to REDOWNLOAD then we need to re-request
                // headers from the beginning.
                ret.request_more = true;
            } else {
                Assume(m_download_state == State::PRESYNC);
                // If we're in PRESYNC and we get a non-full headers
                // message, then the peer's chain has ended and definitely doesn't
                // have enough work, so we can stop our sync.
                LogDebug(BCLog::NET, "Initial headers sync aborted with peer=%d: incomplete headers message at height=%i (presync phase)\n", m_id, m_current_height);
            }
        }
    } else if (m_download_state == State::REDOWNLOAD) {
        // During REDOWNLOAD, we compare our stored commitments to what we
        // receive, and add headers to our redownload buffer. When the buffer
        // gets big enough (meaning that we've checked enough commitments),
        // we'll return a batch of headers to the caller for processing.
        ret.success = true;
        for (const auto& hdr : received_headers) {
            if (!ValidateAndStoreRedownloadedHeader(hdr)) {
                // Something went wrong -- the peer gave us an unexpected chain.
                // We could consider looking at the reason for failure and
                // punishing the peer, but for now just give up on sync.
                ret.success = false;
                break;
            }
        }

        if (ret.success) {
            // Return any headers that are ready for acceptance.
            ret.pow_validated_headers = PopHeadersReadyForAcceptance();

            // If we hit our target blockhash, then all remaining headers will be
            // returned and we can clear any leftover internal state.
            if (m_redownloaded_headers.empty() && m_process_all_remaining_headers) {
                LogDebug(BCLog::NET, "Initial headers sync complete with peer=%d: releasing all at height=%i (redownload phase)\n", m_id, m_redownload_buffer_last_height);
            } else if (full_headers_message) {
                // If the headers message is full, we need to request more.
                ret.request_more = true;
            } else {
                // For some reason our peer gave us a high-work chain, but is now
                // declining to serve us that full chain again. Give up.
                // Note that there's no more processing to be done with these
                // headers, so we can still return success.
                LogDebug(BCLog::NET, "Initial headers sync aborted with peer=%d: incomplete headers message at height=%i (redownload phase)\n", m_id, m_redownload_buffer_last_height);
            }
        }
    }

    if (!(ret.success && ret.request_more)) Finalize();
    return ret;
}

bool HeadersSyncState::ValidateAndStoreHeadersCommitments(const std::vector<CBlockHeader>& headers)
{
    // The caller should not give us an empty set of headers.
    Assume(headers.size() > 0);
    if (headers.size() == 0) return true;

    Assume(m_download_state == State::PRESYNC);
    if (m_download_state != State::PRESYNC) return false;

    if (headers[0].hashPrevBlock != m_last_header_received.GetHash()) {
        // Somehow our peer gave us a header that doesn't connect.
        // This might be benign -- perhaps our peer reorged away from the chain
        // they were on. Give up on this sync for now (likely we will start a
        // new sync with a new starting point).
        LogDebug(BCLog::NET, "Initial headers sync aborted with peer=%d: non-continuous headers at height=%i (presync phase)\n", m_id, m_current_height);
        return false;
    }

    // If it does connect, (minimally) validate and occasionally store
    // commitments.
    for (const auto& hdr : headers) {
        if (!ValidateAndProcessSingleHeader(hdr)) {
            return false;
        }
    }

    if (m_current_chain_work >= m_minimum_required_work) {
        m_redownloaded_headers.clear();
        m_redownload_buffer_last_height = m_chain_start->nHeight;
        m_redownload_buffer_first_prev_hash = m_chain_start->GetBlockHash();
        m_redownload_buffer_last_hash = m_chain_start->GetBlockHash();
        m_redownload_chain_work = m_chain_start->nChainWork;
        m_download_state = State::REDOWNLOAD;
        LogDebug(BCLog::NET, "Initial headers sync transition with peer=%d: reached sufficient work at height=%i, redownloading from height=%i\n", m_id, m_current_height, m_redownload_buffer_last_height);
    }
    return true;
}

bool HeadersSyncState::ValidateAndProcessSingleHeader(const CPureBlockHeader& current)
{
    Assume(m_download_state == State::PRESYNC);
    if (m_download_state != State::PRESYNC) return false;

    int next_height = m_current_height + 1;

    // Ruble uses an absolute ASERT schedule with independent ordinary and
    // AuxPoW channels. Validate the exact target while retaining only the
    // timestamps and counts required by that schedule.
    if (!ValidateAndAdvanceDifficulty(m_presync_difficulty_state, current)) {
        LogDebug(BCLog::NET, "Initial headers sync aborted with peer=%d: invalid difficulty transition at height=%i (presync phase)\n", m_id, next_height);
        return false;
    }

    if (next_height % HEADER_COMMITMENT_PERIOD == m_commit_offset) {
        // Add a commitment.
        m_header_commitments.push_back(m_hasher(current.GetHash()) & 1);
        if (m_header_commitments.size() > m_max_commitments) {
            // The peer's chain is too long; give up.
            // It's possible the chain grew since we started the sync; so
            // potentially we could succeed in syncing the peer's chain if we
            // try again later.
            LogDebug(BCLog::NET, "Initial headers sync aborted with peer=%d: exceeded max commitments at height=%i (presync phase)\n", m_id, next_height);
            return false;
        }
    }

    m_current_chain_work += GetBlockProof(CBlockIndex(current));
    m_last_header_received = current;
    m_current_height = next_height;

    return true;
}

bool HeadersSyncState::ValidateAndStoreRedownloadedHeader(const CBlockHeader& header)
{
    Assume(m_download_state == State::REDOWNLOAD);
    if (m_download_state != State::REDOWNLOAD) return false;

    int64_t next_height = m_redownload_buffer_last_height + 1;

    // Ensure that we're working on a header that connects to the chain we're
    // downloading.
    if (header.hashPrevBlock != m_redownload_buffer_last_hash) {
        LogDebug(BCLog::NET, "Initial headers sync aborted with peer=%d: non-continuous headers at height=%i (redownload phase)\n", m_id, next_height);
        return false;
    }

    // Repeat the same exact ASERT validation during the second download.
    if (!ValidateAndAdvanceDifficulty(m_redownload_difficulty_state, header)) {
        LogDebug(BCLog::NET, "Initial headers sync aborted with peer=%d: invalid difficulty transition at height=%i (redownload phase)\n", m_id, next_height);
        return false;
    }

    // Track work on the redownloaded chain
    m_redownload_chain_work += GetBlockProof(CBlockIndex(header));

    if (m_redownload_chain_work >= m_minimum_required_work) {
        m_process_all_remaining_headers = true;
    }

    // If we're at a header for which we previously stored a commitment, verify
    // it is correct. Failure will result in aborting download.
    // Also, don't check commitments once we've gotten to our target blockhash;
    // it's possible our peer has extended its chain between our first sync and
    // our second, and we don't want to return failure after we've seen our
    // target blockhash just because we ran out of commitments.
    if (!m_process_all_remaining_headers && next_height % HEADER_COMMITMENT_PERIOD == m_commit_offset) {
        if (m_header_commitments.size() == 0) {
            LogDebug(BCLog::NET, "Initial headers sync aborted with peer=%d: commitment overrun at height=%i (redownload phase)\n", m_id, next_height);
            // Somehow our peer managed to feed us a different chain and
            // we've run out of commitments.
            return false;
        }
        bool commitment = m_hasher(header.GetHash()) & 1;
        bool expected_commitment = m_header_commitments.front();
        m_header_commitments.pop_front();
        if (commitment != expected_commitment) {
            LogDebug(BCLog::NET, "Initial headers sync aborted with peer=%d: commitment mismatch at height=%i (redownload phase)\n", m_id, next_height);
            return false;
        }
    }

    // Store this header for later processing.
    m_redownloaded_headers.emplace_back(header);
    m_redownload_buffer_last_height = next_height;
    m_redownload_buffer_last_hash = header.GetHash();

    return true;
}

std::vector<CBlockHeader> HeadersSyncState::PopHeadersReadyForAcceptance()
{
    std::vector<CBlockHeader> ret;

    Assume(m_download_state == State::REDOWNLOAD);
    if (m_download_state != State::REDOWNLOAD) return ret;

    while (m_redownloaded_headers.size() > REDOWNLOAD_BUFFER_SIZE ||
            (m_redownloaded_headers.size() > 0 && m_process_all_remaining_headers)) {
        ret.emplace_back(m_redownloaded_headers.front().GetFullHeader(m_redownload_buffer_first_prev_hash));
        m_redownloaded_headers.pop_front();
        m_redownload_buffer_first_prev_hash = ret.back().GetHash();
    }
    return ret;
}

CBlockLocator HeadersSyncState::NextHeadersRequestLocator() const
{
    Assume(m_download_state != State::FINAL);
    if (m_download_state == State::FINAL) return {};

    auto chain_start_locator = LocatorEntries(m_chain_start);
    std::vector<uint256> locator;

    if (m_download_state == State::PRESYNC) {
        // During pre-synchronization, we continue from the last header received.
        locator.push_back(m_last_header_received.GetHash());
    }

    if (m_download_state == State::REDOWNLOAD) {
        // During redownload, we will download from the last received header that we stored.
        locator.push_back(m_redownload_buffer_last_hash);
    }

    locator.insert(locator.end(), chain_start_locator.begin(), chain_start_locator.end());

    return CBlockLocator{std::move(locator)};
}
