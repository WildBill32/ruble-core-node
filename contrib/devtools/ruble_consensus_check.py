#!/usr/bin/env python3
# Copyright (c) 2026 The Ruble Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Independently reproduce Ruble genesis hashes and monetary-policy totals."""

from dataclasses import dataclass
import hashlib
import struct


COIN = 100_000_000
INITIAL_SUBSIDY = 100 * COIN
PREMINE_HEIGHT = 1
PREMINE = 5_000_000 * COIN
HALVING_INTERVAL = 500_000
TAIL_SUBSIDY = COIN // 10
TAIL_HEIGHT = 5_000_000
INITIAL_COMBINED_HASHRATE = 100_000_000_000_000  # 100 TH/s
INITIAL_COMBINED_SPACING = 180
INITIAL_ORDINARY_HASHRATE = 200_000_000_000_000 // 3
INITIAL_AUXPOW_HASHRATE = 100_000_000_000_000 // 3
ORDINARY_SPACING = 270
AUXPOW_SPACING = 540
INITIAL_MAINNET_BITS = 0x1A0400D1
LIVE_MAINNET_POW_LIMIT = int("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
MAINNET_LAUNCH_HASH = "00000000000003e4b7526e931b9ba1f5154b9ab13dfd9820fefef03bd1aee192"
MAINNET_LAUNCH_TIME = 1_786_213_343
MAINNET_LAUNCH_BLOCK_HEX = (
    "0060cf285a0b2353de64c8f26a215e7754a3f42d655acf289afe106d1e02f66f2a0c000098faffb5"
    "a8b57fba928e7196b022fce7bb449c8b1569feb537ab207c154bc724df73776ad100041a0d80136f"
    "0102000000010000000000000000000000000000000000000000000000000000000000000000ffff"
    "ffff1151002f5275626c652f454090ddd6000000ffffffff0100406352bfc60100160014d66945ac"
    "0db4a7caf4dc7cb94c0fb0d74bab409800000000"
)
MAINNET_PREMINE_SCRIPT_HEX = "0014d66945ac0db4a7caf4dc7cb94c0fb0d74bab4098"
MAINNET_LAUNCH_COINBASE_TXID = "24c74b157c20ab37b5fe69158b9c44bbe7fc22b096718e92ba7fb5a8b5fffa98"
MAINNET_FINALITY_DEPTH = 20
MAINNET_FINALITY_FLOOR_HEIGHT = 1


@dataclass(frozen=True)
class Genesis:
    network: str
    timestamp: str
    time: int
    nonce: int
    bits: int
    expected_hash: str
    expected_merkle_root: str
    coinbase_value: int = 0
    script_pubkey_hex: str = "6a"


GENESIS_BLOCKS = (
    Genesis(
        "mainnet",
        "Ruble (RUB) Genesis Block — Built by the community, secured by Bitcoin.",
        1784710520,
        582296,
        0x1E0FFFF0,
        "00000c2a6ff6021e6d10fe9a28cf5a652df4a354775e216af2c864de53230b5a",
        "4c422303101396cf081fc7919c91a6e714f974985ed617d6c53622f4a7a85bca",
        50 * COIN,
        "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac",
    ),
    Genesis(
        "testnet3",
        "28/Jul/2026 Ruble testnet genesis - community development",
        1785196861,
        1452779023,
        0x1D00FFFF,
        "000000002cf445f5ca3e4d4ee118517f86f48b39ae2ddd0239a8e5318acfbf03",
        "83a3906ec09047cdd26ee860b2f1b2d15625f2697a15ebf9f1e237002176b163",
    ),
    Genesis(
        "testnet4",
        "28/Jul/2026 Ruble testnet4 genesis - protocol testing",
        1785196891,
        3677704107,
        0x1D00FFFF,
        "00000000c18d0967b53a961f55fe209f51cd79af12857f7c527808e1f3dcd3ec",
        "942ca0f1be95880554dd69f02291764002e5360078848a2c9b5bdff28419e8af",
    ),
    Genesis(
        "signet",
        "28/Jul/2026 Ruble signet genesis - community development",
        1785196921,
        0,
        0x207FFFFF,
        "4810234406518a4cb293c64d79b7be54106f000f1e0e2587a93c620cbe63102f",
        "787b9756415d59f4f7024b65e2aab8d3e4d4ed0b01afd623d955a0b43517e405",
    ),
    Genesis(
        "regtest",
        "Ruble regtest genesis - deterministic local testing",
        1296688602,
        0,
        0x207FFFFF,
        "5a3f68d82df274d2e892b6b50de381059f9541402bf99082fe54fd29b0c85724",
        "8a29e646a4b2de9a2c531e8e20dcc8b4cc90ba3eff85998fe8e5eb68d1977f17",
    ),
)


def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def compact_size(value: int) -> bytes:
    if value < 253:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", value)
    if value <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", value)
    return b"\xff" + struct.pack("<Q", value)


def read_compact_size(data: bytes, offset: int) -> tuple[int, int]:
    """Decode one canonical CompactSize and return (value, next offset)."""
    first = data[offset]
    offset += 1
    if first < 253:
        return first, offset
    formats = {253: ("<H", 253), 254: ("<I", 0x10000), 255: ("<Q", 0x100000000)}
    fmt, minimum = formats[first]
    size = struct.calcsize(fmt)
    value = struct.unpack_from(fmt, data, offset)[0]
    assert value >= minimum, "non-canonical CompactSize"
    return value, offset + size


def script_push(data: bytes) -> bytes:
    """Encode one minimally pushed CScript byte vector."""
    if len(data) <= 75:
        return bytes([len(data)]) + data
    if len(data) <= 0xFF:
        return b"\x4c" + bytes([len(data)]) + data
    if len(data) <= 0xFFFF:
        return b"\x4d" + struct.pack("<H", len(data)) + data
    return b"\x4e" + struct.pack("<I", len(data)) + data


def genesis_coinbase(genesis: Genesis) -> bytes:
    timestamp_bytes = genesis.timestamp.encode("utf-8")
    # CScript() << 486604799 << CScriptNum(4) << timestamp.
    script_sig = bytes.fromhex("04ffff001d0104") + script_push(timestamp_bytes)
    script_pubkey = bytes.fromhex(genesis.script_pubkey_hex)

    return (
        struct.pack("<I", 1)
        + compact_size(1)
        + bytes(32)
        + struct.pack("<I", 0xFFFFFFFF)
        + compact_size(len(script_sig))
        + script_sig
        + struct.pack("<I", 0xFFFFFFFF)
        + compact_size(1)
        + struct.pack("<Q", genesis.coinbase_value)
        + compact_size(len(script_pubkey))
        + script_pubkey
        + struct.pack("<I", 0)
    )


def reproduce_genesis(genesis: Genesis) -> tuple[str, str]:
    merkle_internal = sha256d(genesis_coinbase(genesis))
    header = (
        struct.pack("<I", 1)
        + bytes(32)
        + merkle_internal
        + struct.pack("<III", genesis.time, genesis.bits, genesis.nonce)
    )
    return sha256d(header)[::-1].hex(), merkle_internal[::-1].hex()


def verify_launch_block() -> None:
    raw = bytes.fromhex(MAINNET_LAUNCH_BLOCK_HEX)
    assert len(raw) == 180
    header = raw[:80]
    block_hash = sha256d(header)[::-1].hex()
    version = struct.unpack_from("<I", header)[0]
    previous_hash = header[4:36][::-1].hex()
    merkle_root = header[36:68][::-1].hex()
    block_time, bits, nonce = struct.unpack_from("<III", header, 68)

    assert block_hash == MAINNET_LAUNCH_HASH
    assert version == 0x28CF6000
    assert version & (1 << 8) == 0, "launch block must be native, not AuxPoW"
    assert previous_hash == GENESIS_BLOCKS[0].expected_hash
    assert block_time == MAINNET_LAUNCH_TIME
    assert bits == INITIAL_MAINNET_BITS
    assert nonce == 1_863_548_941
    assert int(block_hash, 16) <= compact_target(bits)

    transaction_count, offset = read_compact_size(raw, 80)
    assert transaction_count == 1
    coinbase = raw[offset:]
    assert sha256d(coinbase)[::-1].hex() == MAINNET_LAUNCH_COINBASE_TXID
    assert merkle_root == MAINNET_LAUNCH_COINBASE_TXID

    tx_offset = 0
    tx_version = struct.unpack_from("<I", coinbase, tx_offset)[0]
    tx_offset += 4
    input_count, tx_offset = read_compact_size(coinbase, tx_offset)
    assert tx_version == 2 and input_count == 1
    assert coinbase[tx_offset:tx_offset + 32] == bytes(32)
    tx_offset += 32
    prevout_index = struct.unpack_from("<I", coinbase, tx_offset)[0]
    tx_offset += 4
    script_sig_size, tx_offset = read_compact_size(coinbase, tx_offset)
    script_sig = coinbase[tx_offset:tx_offset + script_sig_size]
    tx_offset += script_sig_size
    sequence = struct.unpack_from("<I", coinbase, tx_offset)[0]
    tx_offset += 4
    assert prevout_index == 0xFFFFFFFF and sequence == 0xFFFFFFFF
    assert script_sig.hex() == "51002f5275626c652f454090ddd6000000"

    output_count, tx_offset = read_compact_size(coinbase, tx_offset)
    assert output_count == 1
    output_value = struct.unpack_from("<Q", coinbase, tx_offset)[0]
    tx_offset += 8
    script_size, tx_offset = read_compact_size(coinbase, tx_offset)
    script_pubkey = coinbase[tx_offset:tx_offset + script_size]
    tx_offset += script_size
    lock_time = struct.unpack_from("<I", coinbase, tx_offset)[0]
    tx_offset += 4

    assert tx_offset == len(coinbase)
    assert output_value == PREMINE
    assert script_pubkey.hex() == MAINNET_PREMINE_SCRIPT_HEX
    assert lock_time == 0


def compact_target(bits: int) -> int:
    size = bits >> 24
    word = bits & 0x007FFFFF
    return word >> (8 * (3 - size)) if size <= 3 else word << (8 * (size - 3))


def subsidy(height: int) -> int:
    if height == 0:
        return 50 * COIN
    if height == PREMINE_HEIGHT:
        return PREMINE
    halvings = height // HALVING_INTERVAL
    regular = INITIAL_SUBSIDY >> halvings if halvings < 64 else 0
    return max(regular, TAIL_SUBSIDY)


def finalized_height(tip_height: int) -> int | None:
    if tip_height < MAINNET_FINALITY_FLOOR_HEIGHT:
        return None
    return max(
        MAINNET_FINALITY_FLOOR_HEIGHT,
        max(0, tip_height - MAINNET_FINALITY_DEPTH),
    )


def advance_finalized_height(previous: int | None, tip_height: int) -> int | None:
    """Model the persisted monotonic finality height across accepted tips."""
    candidate = finalized_height(tip_height)
    if candidate is None:
        return previous
    return candidate if previous is None else max(previous, candidate)


def spendable_before_tail() -> int:
    total = PREMINE
    total += (HALVING_INTERVAL - 2) * INITIAL_SUBSIDY
    for epoch in range(1, TAIL_HEIGHT // HALVING_INTERVAL):
        total += HALVING_INTERVAL * (INITIAL_SUBSIDY >> epoch)
    return total


def format_rub(atoms: int) -> str:
    return f"{atoms // COIN:,}.{atoms % COIN:08d}"


def main() -> None:
    for genesis in GENESIS_BLOCKS:
        block_hash, merkle_root = reproduce_genesis(genesis)
        assert block_hash == genesis.expected_hash, (genesis.network, block_hash)
        assert merkle_root == genesis.expected_merkle_root, (genesis.network, merkle_root)
        assert int(block_hash, 16) <= compact_target(genesis.bits), (
            genesis.network,
            "insufficient genesis proof of work",
        )
        print(f"{genesis.network:8} genesis={block_hash} merkle={merkle_root}")

    verify_launch_block()
    print(
        f"mainnet launch raw={len(bytes.fromhex(MAINNET_LAUNCH_BLOCK_HEX))} bytes; "
        f"coinbase={MAINNET_LAUNCH_COINBASE_TXID}"
    )

    expected_supply = 10_490_214_375_000_000
    actual_supply = spendable_before_tail()
    assert actual_supply == expected_supply
    assert subsidy(0) == 50 * COIN
    assert subsidy(1) == PREMINE
    assert subsidy(2) == INITIAL_SUBSIDY
    assert subsidy(499_999) == 100 * COIN
    assert subsidy(500_000) == 50 * COIN
    assert subsidy(4_999_999) == 19_531_250
    assert subsidy(5_000_000) == TAIL_SUBSIDY
    assert subsidy(100_000_000) == TAIL_SUBSIDY

    print(f"spendable before tail={format_rub(actual_supply)} RUB")
    print("tail subsidy=0.10000000 RUB; annual target issuance=17,520 RUB")

    assert finalized_height(0) is None
    assert finalized_height(1) == 1
    assert finalized_height(21) == 1
    assert finalized_height(22) == 2
    assert 22 - finalized_height(22) == 20
    persisted_finality = advance_finalized_height(None, 22)
    assert persisted_finality == 2
    assert advance_finalized_height(persisted_finality, 2) == 2
    assert advance_finalized_height(persisted_finality, 100) == 80
    print("rolling finality depth=20; persisted monotonic anchor; maximum automatic reorg=20 blocks")

    initial_target = compact_target(INITIAL_MAINNET_BITS)
    genesis_target = compact_target(GENESIS_BLOCKS[0].bits)
    assert LIVE_MAINNET_POW_LIMIT >> 224 == 0
    assert initial_target <= LIVE_MAINNET_POW_LIMIT < genesis_target
    expected_hashes = (1 << 256) / (initial_target + 1)
    exact_expected_hashes = (1 << 256) // (initial_target + 1)
    expected_seconds = expected_hashes / INITIAL_COMBINED_HASHRATE
    difficulty = compact_target(0x1D00FFFF) / initial_target
    assert AUXPOW_SPACING == 2 * ORDINARY_SPACING
    assert (
        ORDINARY_SPACING * AUXPOW_SPACING
        == INITIAL_COMBINED_SPACING * (ORDINARY_SPACING + AUXPOW_SPACING)
    )
    assert exact_expected_hashes == 18_000_047_580_434_167
    assert abs(expected_seconds - INITIAL_COMBINED_SPACING) < 0.01
    assert abs(expected_hashes / INITIAL_ORDINARY_HASHRATE - ORDINARY_SPACING) < 0.01
    assert abs(expected_hashes / INITIAL_AUXPOW_HASHRATE - AUXPOW_SPACING) < 0.01
    assert int(MAINNET_LAUNCH_HASH, 16) <= initial_target
    assert MAINNET_LAUNCH_TIME > GENESIS_BLOCKS[0].time
    print(
        f"mainnet initial nBits=0x{INITIAL_MAINNET_BITS:08x}; "
        f"difficulty={difficulty:,.3f}; "
        f"100 TH/s interval={expected_seconds:.6f}s"
    )
    print("launch allocation=66.7 TH/s ordinary + 33.3 TH/s AuxPoW; expected blocks=2:1")
    print(
        f"mainnet launch hash={MAINNET_LAUNCH_HASH}; "
        f"time={MAINNET_LAUNCH_TIME}"
    )
    print("live powLimit has 32-bit ASERT headroom; finalized genesis uses its own easier target")


if __name__ == "__main__":
    main()
