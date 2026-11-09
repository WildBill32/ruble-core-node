# AuxPoW merged-mining integration

Ruble mainnet activation height: **7000**. AuxPoW chain ID: **0x5255 (21077)**.
Native mining remains supported; ordinary SHA-256d pools use
[POOL-NATIVE.md](POOL-NATIVE.md).

## Candidate and submission flow

Connect your coordinator to a synchronized Ruble node and to your Bitcoin node.
Use an operator-controlled RUB payout address:

```bash
ruble-cli createauxblock "$ruble_payout_address"
```

The response fields are:

| Field | Meaning |
|---|---|
| `hash` | Exact child candidate hash in RPC display order; keep this string unchanged for submission. |
| `chainid` | 21077 on Ruble mainnet. |
| `previousblockhash` | Ruble tip on which this candidate builds. |
| `coinbasevalue` | Child payout value in integer base units (10^-8 RUB). |
| `bits` | Compact Ruble AuxPoW target, as eight hexadecimal digits. |
| `height` | Candidate's Ruble height. |
| `_target` | Deprecated target as little-endian bytes in hex; it is not GBT target display order. |

Derive the positive target from `bits` with Bitcoin's compact-target rules.
Keep a mapping between each Stratum job and its child candidate, parent
template, coinbase/extranonce, Merkle branches and negotiated version bits.
Build the Bitcoin parent coinbase and witness commitment from the Bitcoin
template. Include the Ruble commitment described below in that coinbase's
input script. Apply the miner's actual extranonce, nonce, timestamp and allowed
version changes when reconstructing the solved parent header and proof.

When the parent SHA-256d hash meets the **Ruble** target, send the hex-encoded
`CAuxPow` proof, not a Bitcoin block and not a complete Ruble block:

```bash
ruble-cli submitauxblock "$child_candidate_hash" "$auxpow_proof_hex"
```

This returns a boolean and may raise an RPC error. On success, look up the
child hash with `getblockheader` and confirm active-chain membership with
`getblockhash` at its height before attributing the reward. On a timeout,
check that hash before retrying. A false result or RPC error must not credit a
reward. Handle orphaning and coinbase maturity (100 blocks).

Ruble and Bitcoin targets are independent. A RUB solution usually need not
meet the Bitcoin target. If it also meets Bitcoin's target, independently
submit the complete valid Bitcoin block to the Bitcoin node and track its
acceptance separately.

Refresh work on changes to either chain. Child candidates are cached in the
Ruble node's memory. A new child tip clears obsolete candidates when new work
is requested; restarting the node loses the cache. `block hash unknown` means
the submitted candidate is not in that cache: obtain fresh work and rebuild
the parent commitment. Never substitute a new child hash into an old proof.

## Coinbase commitment and byte order

The recommended commitment inside the parent coinbase input script is:

```text
fa be 6d 6d | chain_merkle_root[32] | tree_size_le32 | merkle_nonce_le32
```

Use one merged-mining marker, immediately followed by the chain root. Preserve
Bitcoin's coinbase height encoding and coinbase script size requirements.
`tree_size` is `2 ** h`, where `h` is the child-chain Merkle branch length,
at most 30. The nonce here is the chain-tree nonce, not the parent header nonce.

Merkle hashing uses SHA-256d and hashes in Bitcoin wire byte order. Reverse
the final chain-root bytes when placing them in the coinbase commitment.
For the single-child case (`h=0`), this means the commitment contains exactly
`bytes.fromhex(createauxblock_result['hash'])`, with tree size 1 and child index 0.

For multiple child chains, the required child index is computed as follows
(matching `CAuxPow::getExpectedIndex`):

```python
size = 1 << h
slot = (merkle_nonce * 1103515245 + 12345) % size
slot = ((slot + 21077) * 1103515245 + 12345) % size
```

Use a tree size/nonce that places every child chain in its required slot.
Changing parent extranonce changes the parent coinbase txid and its Merkle
root, so update the parent proof accordingly. Do not change the child
candidate header or its AuxPoW/chain-ID version bits after requesting it.

## Proof serialization

Concatenate these fields, in this order, with no trailing bytes:

| Field | Encoding |
|---|---|
| Parent coinbase transaction | Bitcoin transaction serialization, including witness when present. |
| Legacy `hashBlock` field | 32 zero bytes (retained for wire compatibility). |
| Parent coinbase Merkle branch | CompactSize count, followed by 32-byte sibling hashes in wire order. |
| Parent coinbase index | Signed int32 little-endian, value 0. |
| Child-chain Merkle branch | CompactSize count, followed by 32-byte sibling hashes in wire order. |
| Child-chain index | Signed int32 little-endian, the required slot above. |
| Solved parent header | Exactly 80 Bitcoin header bytes, including the miner's actual version and nonce. |

The parent transaction branch uses the coinbase **txid**, not its wtxid.
Left/right order is determined by the corresponding index bits. Hash fields
in branches and the parent header use wire order; the coinbase's chain-root
commitment uses the reversed representation described above.

## Reproducible serialization example

This offline Python example has one child chain and one parent transaction.
It uses a synthetic candidate and an unmined parent header to demonstrate
encoding only. It creates no wallet, contacts no node and produces no solved
mainnet block. Real pool jobs must use current node templates and actual work.

```python
import hashlib
import struct

def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

child_hash = '00' * 31 + '01'  # Synthetic RPC-display hash.
commitment = bytes.fromhex('fabe6d6d' + child_hash) + struct.pack('<II', 1, 0)
script_sig = bytes.fromhex('03a08601') + bytes([len(commitment)]) + commitment
coinbase = (
    struct.pack('<I', 2) + b'\x01' + b'\x00' * 32 + b'\xff' * 4
    + bytes([len(script_sig)]) + script_sig + b'\xff' * 4
    + b'\x01' + struct.pack('<Q', 0) + b'\x01\x51' + b'\x00' * 4
)
parent_header = (
    struct.pack('<I', 0x20000000) + b'\x00' * 32 + sha256d(coinbase)
    + struct.pack('<III', 1700000000, 0x1d00ffff, 0)
)
proof = (
    coinbase + b'\x00' * 32
    + b'\x00' + struct.pack('<i', 0)  # Empty parent branch; coinbase index 0.
    + b'\x00' + struct.pack('<i', 0)  # Empty child branch; child index 0.
    + parent_header
)
assert len(parent_header) == 80
assert len(proof) == 232
print(proof.hex())
```

The authoritative implementation is in `src/auxpow.h`, `src/auxpow.cpp` and
`src/rpc/auxpow_miner.cpp`; existing coverage is in `src/test/auxpow_tests.cpp`.
Run `help createauxblock` and `help submitauxblock` on the selected server build.
The pool operates its own Stratum/coordinator and verifies its adapter against
these interfaces.
