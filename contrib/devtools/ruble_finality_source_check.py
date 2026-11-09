#!/usr/bin/env python3
# Copyright (c) 2026 The Ruble Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Fail-closed structural check for Ruble rolling-finality bindings.

This checker complements, but does not replace, the C++ unit and functional
tests. It is intentionally dependency-free so a source archive can be checked
before installing build packages.
"""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]


def require(path: str, *needles: str) -> int:
    text = (ROOT / path).read_text(encoding="utf-8")
    for needle in needles:
        if needle not in text:
            raise AssertionError(f"{path}: missing required binding: {needle!r}")
    return len(needles)


def reject(path: str, *needles: str) -> int:
    text = (ROOT / path).read_text(encoding="utf-8")
    for needle in needles:
        if needle in text:
            raise AssertionError(f"{path}: forbidden binding present: {needle!r}")
    return len(needles)


def main() -> None:
    checks = 0
    checks += require(
        "CMakeLists.txt",
        "set(CLIENT_VERSION_BUILD 1)",
        "set(CLIENT_VERSION_RC 0)",
        'set(CLIENT_VERSION_IS_RELEASE "true")',
    )
    checks += require(
        "src/consensus/params.h",
        "int nFinalityDepth{0};",
        "int nFinalityFloorHeight{0};",
        "The anchor is\n     * monotonic and never moves backward",
    )
    checks += require(
        "src/kernel/chainparams.cpp",
        "constexpr int RUBLE_MAINNET_FINALITY_DEPTH{20};",
        "consensus.nFinalityDepth = RUBLE_MAINNET_FINALITY_DEPTH;",
        "consensus.nFinalityFloorHeight = RUBLE_PREMINE_HEIGHT;",
        "consensus.nFinalityDepth = opts.enable_finality ? RUBLE_MAINNET_FINALITY_DEPTH : 0;",
    )
    checks += require(
        "src/node/blockstorage.cpp",
        "DB_RUBLE_FINALIZED_BLOCK{'z'}",
        "batch.Write(DB_RUBLE_FINALIZED_BLOCK, *finalized_block);",
        "bool BlockTreeDB::HasFinalizedBlock() const",
        "bool BlockTreeDB::ReadFinalizedBlock(uint256& hash) const",
    )
    checks += require(
        "src/validation.cpp",
        "bool ChainstateManager::LoadFinalizedBlock",
        "bool ChainstateManager::UpdateFinalizedBlock",
        "m_blockman.WriteBlockIndexDB(candidate->GetBlockHash())",
        "m_finalized_block = candidate;",
        'BlockValidationResult::BLOCK_FINALITY,\n                "bad-finality-fork"',
        'BlockValidationResult::BLOCK_FINALITY,\n                "finalized-block"',
        "const CBlockIndex* finalized{GetFinalizedBlock()};",
    )
    checks += require(
        "src/init.cpp",
        "rolling_finality_mainnet",
        "Full -reindex is disabled because it would erase the persisted",
        "Use -reindex-chainstate",
    )
    checks += require(
        "src/rpc/blockchain.cpp",
        'finality.pushKV("enabled"',
        'finality.pushKV("depth"',
        'finality.pushKV("finalized_height"',
        'finality.pushKV("finalized_hash"',
        '"finality-conflict"',
    )
    checks += require(
        "test/functional/feature_ruble_finality.py",
        'self.log.info("A reorg disconnecting 21 blocks is rejected automatically")',
        'self.log.info("Finality never moves backward and survives restart")',
        'self.log.info("Build the boundary case: exactly 20 blocks may reorganize")',
        "self.restart_node(0)",
    )
    checks += require(
        "test/functional/test_runner.py",
        "'feature_ruble_finality.py'",
    )
    checks += require(
        "doc/ruble-rolling-finality.md",
        "finalized block is monotonic",
        "A full `-reindex` would erase the block-index database",
    )

    # Mainnet finality must not become an operator-selectable policy knob.
    checks += reject(
        "src/init.cpp",
        'AddArg("-finalitydepth"',
        'AddArg("-disablefinality"',
        'AddArg("-unfinalize"',
    )
    checks += reject(
        "src/rpc/blockchain.cpp",
        'RPCHelpMan{"unfinalizeblock"',
        'RPCHelpMan{"finalizeblock"',
    )

    print(f"FINALITY_SOURCE_CHECKS={checks}")
    print("RUBLE_FINALITY_SOURCE_BINDINGS=OK")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, UnicodeError) as exc:
        print(f"RUBLE_FINALITY_SOURCE_BINDINGS=FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
