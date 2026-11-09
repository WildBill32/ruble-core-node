// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <clientversion.h>
#include <node/blockstorage.h>
#include <node/context.h>
#include <node/kernel_notifications.h>
#include <script/solver.h>
#include <primitives/block.h>
#include <util/chaintype.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>
#include <test/util/logging.h>
#include <test/util/setup_common.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

using node::BLOCK_SERIALIZATION_HEADER_SIZE;
using node::BlockManager;
using node::KernelNotifications;
using node::MAX_BLOCKFILE_SIZE;

namespace {

constexpr size_t AUXPOW_STARTUP_TEST_HEIGHT{4};

class AuxpowStartupIndex
{
public:
    AuxpowStartupIndex(const CChainParams& params,
                       const std::array<bool, AUXPOW_STARTUP_TEST_HEIGHT>& channels,
                       int wrong_bits_height = -1,
                       int wrong_chain_id_height = -1)
    {
        const CBlock& genesis{params.GenesisBlock()};
        SetHeader(m_blocks[0], genesis);
        m_hashes[0] = genesis.GetHash();
        m_blocks[0].phashBlock = &m_hashes[0];
        m_blocks[0].nHeight = 0;

        const Consensus::Params& consensus{params.GetConsensus()};
        for (size_t height = 1; height < m_blocks.size(); ++height) {
            CPureBlockHeader header;
            if (channels[height - 1]) {
                const int32_t chain_id{consensus.nAuxpowChainId +
                    (static_cast<int>(height) == wrong_chain_id_height ? 1 : 0)};
                header.SetBaseVersion(4, chain_id);
                header.SetAuxpowVersion(true);
            } else {
                header.nVersion = 4;
            }
            header.hashPrevBlock = m_hashes[height - 1];
            header.hashMerkleRoot = ArithToUint256(height + 1'000);
            header.nTime = m_blocks[height - 1].nTime + 1;
            header.nBits = m_blocks[height - 1].nBits;
            if (static_cast<int>(height) == wrong_bits_height) {
                ++header.nBits;
            }
            header.nNonce = static_cast<uint32_t>(height);

            SetHeader(m_blocks[height], header);
            m_hashes[height] = header.GetHash();
            m_blocks[height].phashBlock = &m_hashes[height];
            m_blocks[height].pprev = &m_blocks[height - 1];
            m_blocks[height].nHeight = static_cast<int>(height);
        }
    }

    std::vector<const CBlockIndex*> Blocks() const
    {
        std::vector<const CBlockIndex*> blocks;
        blocks.reserve(m_blocks.size());
        for (const CBlockIndex& block : m_blocks) {
            blocks.push_back(&block);
        }
        return blocks;
    }

    const uint256& Hash(size_t height) const { return m_hashes.at(height); }

private:
    static void SetHeader(CBlockIndex& index, const CPureBlockHeader& header)
    {
        index.nVersion = header.nVersion;
        index.hashMerkleRoot = header.hashMerkleRoot;
        index.nTime = header.nTime;
        index.nBits = header.nBits;
        index.nNonce = header.nNonce;
    }

    std::array<CBlockIndex, AUXPOW_STARTUP_TEST_HEIGHT + 1> m_blocks;
    std::array<uint256, AUXPOW_STARTUP_TEST_HEIGHT + 1> m_hashes;
};

bool WriteStartupIndex(const fs::path& path, const AuxpowStartupIndex& index)
{
    kernel::BlockTreeDB index_db{DBParams{
        .path = path,
        .cache_bytes = 1 << 20,
    }};
    return index_db.WriteBatchSync({}, 0, index.Blocks());
}

std::unique_ptr<const CChainParams> AuxpowRegtestParams()
{
    ArgsManager args;
    args.ForceSetArg("-testauxpowactivationheight", "3");
    return CreateChainParams(args, ChainType::REGTEST);
}

} // namespace

// use BasicTestingSetup here for the data directory configuration, setup, and cleanup
BOOST_FIXTURE_TEST_SUITE(blockmanager_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(blockmanager_find_block_pos)
{
    const auto params {CreateChainParams(ArgsManager{}, ChainType::MAIN)};
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    const BlockManager::Options blockman_opts{
        .chainparams = *params,
        .blocks_dir = m_args.GetBlocksDirPath(),
        .notifications = notifications,
        .block_tree_db_params = DBParams{
            .path = m_args.GetDataDirNet() / "blocks" / "index",
            .cache_bytes = 0,
        },
    };
    BlockManager blockman{*Assert(m_node.shutdown_signal), blockman_opts};
    // simulate adding a genesis block normally
    BOOST_CHECK_EQUAL(blockman.WriteBlock(params->GenesisBlock(), 0).nPos, BLOCK_SERIALIZATION_HEADER_SIZE);
    // simulate what happens during reindex
    // simulate a well-formed genesis block being found at offset 8 in the blk00000.dat file
    // the block is found at offset 8 because there is an 8 byte serialization header
    // consisting of 4 magic bytes + 4 length bytes before each block in a well-formed blk file.
    const FlatFilePos pos{0, BLOCK_SERIALIZATION_HEADER_SIZE};

    // Ruble's finalized mainnet genesis predates the live ASERT powLimit. The
    // exact hard-coded genesis must nevertheless survive the same disk read
    // path used during startup and reindex.
    CBlock read_genesis;
    BOOST_REQUIRE(blockman.ReadBlock(read_genesis, pos));
    BOOST_CHECK_EQUAL(read_genesis.GetHash(), params->GenesisBlock().GetHash());

    blockman.UpdateBlockInfo(params->GenesisBlock(), 0, pos);
    // now simulate what happens after reindex for the first new block processed
    // the actual block contents don't matter, just that it's a block.
    // verify that the write position is at offset 0x12d.
    // this is a check to make sure that https://github.com/bitcoin/bitcoin/issues/21379 does not recur
    // 8 bytes (for serialization header) + 285 (for serialized genesis block) = 293
    // add another 8 bytes for the second block's serialization header and we get 293 + 8 = 301
    FlatFilePos actual{blockman.WriteBlock(params->GenesisBlock(), 1)};
    BOOST_CHECK_EQUAL(actual.nPos, BLOCK_SERIALIZATION_HEADER_SIZE + ::GetSerializeSize(TX_WITH_WITNESS(params->GenesisBlock())) + BLOCK_SERIALIZATION_HEADER_SIZE);

    // The exception must be hash-exact. A one-field mutation is written to
    // disk successfully but must fail proof-of-work validation when read.
    CBlock mutated_genesis{params->GenesisBlock()};
    ++mutated_genesis.nNonce;
    const FlatFilePos mutated_pos{blockman.WriteBlock(mutated_genesis, 2)};
    CBlock rejected_block;
    BOOST_CHECK(!blockman.ReadBlock(rejected_block, mutated_pos));

    // Disk reads and reindex must also fail closed while the exact mainnet
    // launch block is unset; contextual checkpoints are not involved here.
    CBlock unset_launch;
    unset_launch.nVersion = 4;
    unset_launch.hashPrevBlock = params->GenesisBlock().GetHash();
    unset_launch.hashMerkleRoot = ArithToUint256(1);
    unset_launch.nTime = params->GenesisBlock().nTime + 1;
    unset_launch.nBits = params->GetConsensus().asertAnchorParams.nBitsLegacy;
    const FlatFilePos unset_launch_pos{blockman.WriteBlock(unset_launch, 1)};
    CBlock rejected_launch;
    BOOST_CHECK(!blockman.ReadBlock(rejected_launch, unset_launch_pos));
}

BOOST_AUTO_TEST_CASE(blockmanager_rejects_stale_launch_block_index)
{
    const auto params{CreateChainParams(ArgsManager{}, ChainType::MAIN)};
    const fs::path index_path{
        m_args.GetDataDirNet() / "stale-launch-block-index"};

    const CBlock& genesis{params->GenesisBlock()};
    uint256 genesis_hash{genesis.GetHash()};
    CBlockIndex genesis_index{genesis};
    genesis_index.phashBlock = &genesis_hash;
    genesis_index.nHeight = 0;

    CBlockHeader stale_launch;
    stale_launch.nVersion = 4;
    stale_launch.hashPrevBlock = genesis_hash;
    stale_launch.hashMerkleRoot = ArithToUint256(3);
    stale_launch.nTime = genesis.nTime + 1;
    stale_launch.nBits = params->GetConsensus().asertAnchorParams.nBitsLegacy;
    uint256 stale_launch_hash{stale_launch.GetHash()};
    CBlockIndex stale_launch_index{stale_launch};
    stale_launch_index.phashBlock = &stale_launch_hash;
    stale_launch_index.pprev = &genesis_index;
    stale_launch_index.nHeight = 1;

    {
        kernel::BlockTreeDB index_db{DBParams{
            .path = index_path,
            .cache_bytes = 1 << 20,
        }};
        BOOST_REQUIRE(index_db.WriteBatchSync(
            {}, 0, {&genesis_index, &stale_launch_index}));
    }

    KernelNotifications notifications{
        Assert(m_node.shutdown_request), m_node.exit_status,
        *Assert(m_node.warnings)};
    BlockManager blockman{
        *Assert(m_node.shutdown_signal),
        BlockManager::Options{
            .chainparams = *params,
            .blocks_dir = m_args.GetBlocksDirPath(),
            .notifications = notifications,
            .block_tree_db_params = DBParams{
                .path = index_path,
                .cache_bytes = 1 << 20,
            },
        }};

    LOCK(::cs_main);
    BOOST_CHECK(!blockman.LoadBlockIndexDB(std::nullopt));
}

BOOST_AUTO_TEST_CASE(blockmanager_rejects_premature_auxpow_block_index)
{
    const auto params{AuxpowRegtestParams()};
    BOOST_REQUIRE_EQUAL(params->GetConsensus().nAuxpowActivationHeight, 3);
    const AuxpowStartupIndex index{
        *params, {false, true, false, false}};
    const fs::path index_path{
        m_args.GetDataDirNet() / "premature-auxpow-block-index"};
    BOOST_REQUIRE(WriteStartupIndex(index_path, index));

    KernelNotifications notifications{
        Assert(m_node.shutdown_request), m_node.exit_status,
        *Assert(m_node.warnings)};
    BlockManager blockman{
        *Assert(m_node.shutdown_signal),
        BlockManager::Options{
            .chainparams = *params,
            .blocks_dir = m_args.GetBlocksDirPath(),
            .notifications = notifications,
            .block_tree_db_params = DBParams{
                .path = index_path,
                .cache_bytes = 1 << 20,
            },
        }};

    LOCK(::cs_main);
    BOOST_CHECK(!blockman.LoadBlockIndexDB(std::nullopt));
}

BOOST_AUTO_TEST_CASE(blockmanager_rejects_wrong_auxpow_difficulty_on_startup)
{
    const auto params{AuxpowRegtestParams()};
    BOOST_REQUIRE_EQUAL(params->GetConsensus().nAuxpowActivationHeight, 3);
    const AuxpowStartupIndex index{
        *params, {false, false, true, false}, /*wrong_bits_height=*/3};
    const fs::path index_path{
        m_args.GetDataDirNet() / "wrong-auxpow-difficulty-block-index"};
    BOOST_REQUIRE(WriteStartupIndex(index_path, index));

    KernelNotifications notifications{
        Assert(m_node.shutdown_request), m_node.exit_status,
        *Assert(m_node.warnings)};
    BlockManager blockman{
        *Assert(m_node.shutdown_signal),
        BlockManager::Options{
            .chainparams = *params,
            .blocks_dir = m_args.GetBlocksDirPath(),
            .notifications = notifications,
            .block_tree_db_params = DBParams{
                .path = index_path,
                .cache_bytes = 1 << 20,
            },
        }};

    LOCK(::cs_main);
    BOOST_CHECK(!blockman.LoadBlockIndexDB(std::nullopt));
}

BOOST_AUTO_TEST_CASE(blockmanager_rejects_wrong_auxpow_chain_id_on_startup)
{
    const auto params{AuxpowRegtestParams()};
    BOOST_REQUIRE_EQUAL(params->GetConsensus().nAuxpowActivationHeight, 3);
    const AuxpowStartupIndex index{
        *params, {false, false, true, false}, /*wrong_bits_height=*/-1,
        /*wrong_chain_id_height=*/3};
    const fs::path index_path{
        m_args.GetDataDirNet() / "wrong-auxpow-chain-id-block-index"};
    BOOST_REQUIRE(WriteStartupIndex(index_path, index));

    KernelNotifications notifications{
        Assert(m_node.shutdown_request), m_node.exit_status,
        *Assert(m_node.warnings)};
    BlockManager blockman{
        *Assert(m_node.shutdown_signal),
        BlockManager::Options{
            .chainparams = *params,
            .blocks_dir = m_args.GetBlocksDirPath(),
            .notifications = notifications,
            .block_tree_db_params = DBParams{
                .path = index_path,
                .cache_bytes = 1 << 20,
            },
        }};

    LOCK(::cs_main);
    BOOST_CHECK(!blockman.LoadBlockIndexDB(std::nullopt));
}

BOOST_AUTO_TEST_CASE(blockmanager_recomputes_auxpow_count_on_startup)
{
    const auto params{AuxpowRegtestParams()};
    BOOST_REQUIRE_EQUAL(params->GetConsensus().nAuxpowActivationHeight, 3);
    const AuxpowStartupIndex index{
        *params, {false, false, true, false}};
    const fs::path index_path{
        m_args.GetDataDirNet() / "valid-auxpow-block-index"};
    BOOST_REQUIRE(WriteStartupIndex(index_path, index));

    KernelNotifications notifications{
        Assert(m_node.shutdown_request), m_node.exit_status,
        *Assert(m_node.warnings)};
    BlockManager blockman{
        *Assert(m_node.shutdown_signal),
        BlockManager::Options{
            .chainparams = *params,
            .blocks_dir = m_args.GetBlocksDirPath(),
            .notifications = notifications,
            .block_tree_db_params = DBParams{
                .path = index_path,
                .cache_bytes = 1 << 20,
            },
        }};

    LOCK(::cs_main);
    BOOST_REQUIRE(blockman.LoadBlockIndexDB(std::nullopt));
    constexpr std::array<unsigned int, AUXPOW_STARTUP_TEST_HEIGHT + 1>
        expected_auxpow_count{0, 0, 0, 1, 1};
    for (size_t height = 0; height < expected_auxpow_count.size(); ++height) {
        const CBlockIndex* loaded{blockman.LookupBlockIndex(index.Hash(height))};
        BOOST_REQUIRE(loaded != nullptr);
        BOOST_CHECK_EQUAL(loaded->nHeight, height);
        BOOST_CHECK_EQUAL(loaded->nAuxPow, expected_auxpow_count[height]);
    }
}

BOOST_FIXTURE_TEST_CASE(blockmanager_scan_unlink_already_pruned_files, TestChain100Setup)
{
    // Cap last block file size, and mine new block in a new block file.
    const auto& chainman = Assert(m_node.chainman);
    auto& blockman = chainman->m_blockman;
    const CBlockIndex* old_tip{WITH_LOCK(chainman->GetMutex(), return chainman->ActiveChain().Tip())};
    WITH_LOCK(chainman->GetMutex(), blockman.GetBlockFileInfo(old_tip->GetBlockPos().nFile)->nSize = MAX_BLOCKFILE_SIZE);
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));

    // Prune the older block file, but don't unlink it
    int file_number;
    {
        LOCK(chainman->GetMutex());
        file_number = old_tip->GetBlockPos().nFile;
        blockman.PruneOneBlockFile(file_number);
    }

    const FlatFilePos pos(file_number, 0);

    // Check that the file is not unlinked after ScanAndUnlinkAlreadyPrunedFiles
    // if m_have_pruned is not yet set
    WITH_LOCK(chainman->GetMutex(), blockman.ScanAndUnlinkAlreadyPrunedFiles());
    BOOST_CHECK(!blockman.OpenBlockFile(pos, true).IsNull());

    // Check that the file is unlinked after ScanAndUnlinkAlreadyPrunedFiles
    // once m_have_pruned is set
    blockman.m_have_pruned = true;
    WITH_LOCK(chainman->GetMutex(), blockman.ScanAndUnlinkAlreadyPrunedFiles());
    BOOST_CHECK(blockman.OpenBlockFile(pos, true).IsNull());

    // Check that calling with already pruned files doesn't cause an error
    WITH_LOCK(chainman->GetMutex(), blockman.ScanAndUnlinkAlreadyPrunedFiles());

    // Check that the new tip file has not been removed
    const CBlockIndex* new_tip{WITH_LOCK(chainman->GetMutex(), return chainman->ActiveChain().Tip())};
    BOOST_CHECK_NE(old_tip, new_tip);
    const int new_file_number{WITH_LOCK(chainman->GetMutex(), return new_tip->GetBlockPos().nFile)};
    const FlatFilePos new_pos(new_file_number, 0);
    BOOST_CHECK(!blockman.OpenBlockFile(new_pos, true).IsNull());
}

BOOST_FIXTURE_TEST_CASE(blockmanager_block_data_availability, TestChain100Setup)
{
    // The goal of the function is to return the first not pruned block in the range [upper_block, lower_block].
    LOCK(::cs_main);
    auto& chainman = m_node.chainman;
    auto& blockman = chainman->m_blockman;
    const CBlockIndex& tip = *chainman->ActiveTip();

    // Function to prune all blocks from 'last_pruned_block' down to the genesis block
    const auto& func_prune_blocks = [&](CBlockIndex* last_pruned_block)
    {
        LOCK(::cs_main);
        CBlockIndex* it = last_pruned_block;
        while (it != nullptr && it->nStatus & BLOCK_HAVE_DATA) {
            it->nStatus &= ~BLOCK_HAVE_DATA;
            it = it->pprev;
        }
    };

    // 1) Return genesis block when all blocks are available
    BOOST_CHECK_EQUAL(blockman.GetFirstBlock(tip, BLOCK_HAVE_DATA), chainman->ActiveChain()[0]);
    BOOST_CHECK(blockman.CheckBlockDataAvailability(tip, *chainman->ActiveChain()[0]));

    // 2) Check lower_block when all blocks are available
    CBlockIndex* lower_block = chainman->ActiveChain()[tip.nHeight / 2];
    BOOST_CHECK(blockman.CheckBlockDataAvailability(tip, *lower_block));

    // Prune half of the blocks
    int height_to_prune = tip.nHeight / 2;
    CBlockIndex* first_available_block = chainman->ActiveChain()[height_to_prune + 1];
    CBlockIndex* last_pruned_block = first_available_block->pprev;
    func_prune_blocks(last_pruned_block);

    // 3) The last block not pruned is in-between upper-block and the genesis block
    BOOST_CHECK_EQUAL(blockman.GetFirstBlock(tip, BLOCK_HAVE_DATA), first_available_block);
    BOOST_CHECK(blockman.CheckBlockDataAvailability(tip, *first_available_block));
    BOOST_CHECK(!blockman.CheckBlockDataAvailability(tip, *last_pruned_block));
}

BOOST_AUTO_TEST_CASE(blockmanager_flush_block_file)
{
    KernelNotifications notifications{Assert(m_node.shutdown_request), m_node.exit_status, *Assert(m_node.warnings)};
    node::BlockManager::Options blockman_opts{
        .chainparams = Params(),
        .blocks_dir = m_args.GetBlocksDirPath(),
        .notifications = notifications,
        .block_tree_db_params = DBParams{
            .path = m_args.GetDataDirNet() / "blocks" / "index",
            .cache_bytes = 0,
        },
    };
    BlockManager blockman{*Assert(m_node.shutdown_signal), blockman_opts};

    // Test blocks with no transactions, not even a coinbase
    CBlock block1;
    block1.nVersion = 1;
    CBlock block2;
    block2.nVersion = 2;
    CBlock block3;
    block3.nVersion = 3;

    // They are 80 bytes header + 1 byte 0x00 for vtx length
    constexpr int TEST_BLOCK_SIZE{81};

    // Blockstore is empty
    BOOST_CHECK_EQUAL(blockman.CalculateCurrentUsage(), 0);

    // Write the first block to a new location.
    FlatFilePos pos1{blockman.WriteBlock(block1, /*nHeight=*/1)};

    // Write second block
    FlatFilePos pos2{blockman.WriteBlock(block2, /*nHeight=*/2)};

    // Two blocks in the file
    BOOST_CHECK_EQUAL(blockman.CalculateCurrentUsage(), (TEST_BLOCK_SIZE + BLOCK_SERIALIZATION_HEADER_SIZE) * 2);

    // First two blocks are written as expected
    // Errors are expected because block data is junk, thrown AFTER successful read
    CBlock read_block;
    BOOST_CHECK_EQUAL(read_block.nVersion, 0);
    {
        ASSERT_DEBUG_LOG("ReadBlockOrHeader: Errors in block header");
        BOOST_CHECK(!blockman.ReadBlock(read_block, pos1));
        BOOST_CHECK_EQUAL(read_block.nVersion, 1);
    }
    {
        ASSERT_DEBUG_LOG("ReadBlockOrHeader: Errors in block header");
        BOOST_CHECK(!blockman.ReadBlock(read_block, pos2));
        BOOST_CHECK_EQUAL(read_block.nVersion, 2);
    }

    // During reindex, the flat file block storage will not be written to.
    // UpdateBlockInfo will, however, update the blockfile metadata.
    // Verify this behavior by attempting (and failing) to write block 3 data
    // to block 2 location.
    CBlockFileInfo* block_data = blockman.GetBlockFileInfo(0);
    BOOST_CHECK_EQUAL(block_data->nBlocks, 2);
    blockman.UpdateBlockInfo(block3, /*nHeight=*/3, /*pos=*/pos2);
    // Metadata is updated...
    BOOST_CHECK_EQUAL(block_data->nBlocks, 3);
    // ...but there are still only two blocks in the file
    BOOST_CHECK_EQUAL(blockman.CalculateCurrentUsage(), (TEST_BLOCK_SIZE + BLOCK_SERIALIZATION_HEADER_SIZE) * 2);

    // Block 2 was not overwritten:
    blockman.ReadBlock(read_block, pos2);
    BOOST_CHECK_EQUAL(read_block.nVersion, 2);
}

BOOST_AUTO_TEST_SUITE_END()
