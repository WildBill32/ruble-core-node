# Distribution validation

Source distribution: `ruble-core-node-1.0.1-h7000-integration3`.
Preparation date: **2026-09-08**. Server node version: **1.0.1 H7000**.

## Checks performed

| Check | Result |
|---|---|
| Fresh out-of-tree Linux configure and build | PASS |
| Existing C++ unit tests | PASS: 685 test cases; no errors detected |
| Required build-input check and distributed file checksums | PASS |
| Regression check: required helper omitted even from manifest | Detected and rejected |
| Existing genesis, finality and AuxPoW source checks | PASS |
| Documented AuxPoW serialization example | PASS: round-trip using the existing proof parser |
| English integration documents and local documentation links | PASS |
| Original node source, dependency sources and build definitions | Preserved unchanged |

Build environment: Ubuntu 24.04 x86_64, CMake 3.28.3, Ninja 1.11.1,
Boost 1.83, SQLite 3.45.1 and libevent 2.1.12.
Compiler: `c++ (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0`.
Configuration: Release; server daemon, CLI and SQLite wallet enabled;
GUI, BDB, ZMQ and benchmarks disabled; unit tests enabled.
Optional GUI, BDB and ZMQ build profiles were not tested for this revision.

## Built-node RPC checks

A fresh, isolated **mainnet** data directory with P2P activity disabled was
used to check the built node. It had no peer connections and no funds.

- Mainnet genesis and activation-height reporting.
- Exchange, native-mining and AuxPoW RPC method availability.
- SQLite descriptor-wallet creation and `rub1` address validation.
- Wallet deposit-cursor response and transaction-index initialization.
- Unavailable automatic fee estimate reported by an empty node.
- Backup and restoration of the newly created, unfunded wallet.
- Clean node shutdown.

These are software/package checks. Live chain synchronization, transfers of
funds, accepted mainnet mining blocks and a third-party exchange or pool
adapter were not exercised. Operators complete their own live integration
checks before accepting customer funds or hashrate.

The source manifest covers this report and the final distributed files.
The post-build edits only record validation results in documentation; the
compiled source and build script remain identical to those tested.
