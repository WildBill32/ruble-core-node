#!/usr/bin/env python3
# Copyright (c) 2026 The Ruble Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Structural gate for fixed-height AuxPoW activation in the full node."""

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
        "set(CLIENT_VERSION_MAJOR 1)",
        "set(CLIENT_VERSION_MINOR 0)",
        "set(CLIENT_VERSION_BUILD 1)",
        "set(CLIENT_VERSION_RC 0)",
        'set(CLIENT_VERSION_IS_RELEASE "true")',
    )
    checks += require(
        "src/kernel/chainparams.cpp",
        "constexpr int RUBLE_MAINNET_AUXPOW_ACTIVATION_HEIGHT{7'000};",
        "consensus.nAuxpowActivationHeight = RUBLE_MAINNET_AUXPOW_ACTIVATION_HEIGHT;",
    )
    checks += reject(
        "src/kernel/chainparams.cpp",
        "consensus.nAuxpowActivationHeight = std::numeric_limits<int>::max();",
    )
    checks += require(
        "src/consensus/params.h",
        "bool IsAuxpowEnabled(int64_t height) const noexcept",
    )
    checks += require(
        "src/headerssync.cpp",
        "const int64_t next_height{state.height + 1};",
        "!m_consensus_params.IsAuxpowEnabled(next_height)",
    )
    checks += require(
        "src/node/blockstorage.cpp",
        "!GetConsensus().IsAuxpowEnabled(pindex->nHeight)",
        "pure_header.GetChainId() != GetConsensus().nAuxpowChainId",
        "pindex->nBits != GetNextWorkRequired(",
    )
    checks += require(
        "src/test/validation_tests.cpp",
        "constexpr int activation_height{7'000};",
        "activation_height - 1",
        "activation_height + 1",
    )
    checks += require(
        "src/test/headers_sync_chainwork_tests.cpp",
        "headers_sync_ruble_auxpow_activation_boundary",
    )
    checks += require(
        "src/test/blockmanager_tests.cpp",
        "blockmanager_rejects_premature_auxpow_block_index",
        "blockmanager_rejects_wrong_auxpow_difficulty_on_startup",
        "blockmanager_rejects_wrong_auxpow_chain_id_on_startup",
        "blockmanager_recomputes_auxpow_count_on_startup",
    )
    # This distribution contains the full node; the external coordinator is separate.

    print(f"AUXPOW_ACTIVATION_SOURCE_CHECKS={checks}")
    print("RUBLE_AUXPOW_ACTIVATION_BINDINGS=OK")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, UnicodeError) as exc:
        print(f"RUBLE_AUXPOW_ACTIVATION_BINDINGS=FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
