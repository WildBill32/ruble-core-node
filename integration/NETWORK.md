# Ruble mainnet parameters

Values below are read from the preserved H7000 source, not inferred from a
marketing description. Live hashrate, difficulty, height and exchange price are
not fixed configuration parameters.

| Parameter | Value |
|---|---|
| Project / native coin / ticker | Ruble Core / Ruble / RUB |
| Precision | 8 decimals; 1 RUB = 100,000,000 base units |
| Proof of work | SHA-256d; native PoW and AuxPoW |
| Mainnet AuxPoW activation | Height 7000 |
| Native block target interval | 270 seconds |
| AuxPoW block target interval | 540 seconds |
| Combined long-run interval | 180 seconds with both channels |
| Difficulty adjustment | Separate per-channel ASERT; 7200-second half-life |
| Initial regular subsidy | 100 RUB |
| Halving interval | 500,000 blocks |
| Coinbase maturity | 100 blocks |
| Rolling finality depth | 20 blocks, with a height-1 floor |
| P2P port | 33888/TCP |
| RPC port | 33887/TCP; bind to loopback |
| Message-start bytes | c1 c7 18 65 |
| Bech32 HRP | rub |
| Base58 public-key address prefix | 60 |
| Base58 script address prefix | 122 |
| WIF prefix | 163 |
| Extended public-key version | 04 0b f2 a6 |
| Extended private-key version | 04 0b ee 6c |
| AuxPoW chain ID | 0x5255 (21077) |
| Default data directory | ~/.ruble |
| Configuration file | ruble.conf |
| Source bootstrap seed | pool.rublecore.org |

Genesis hash:
`00000c2a6ff6021e6d10fe9a28cf5a652df4a354775e216af2c864de53230b5a`

Consensus-locked height-1 hash:
`00000000000003e4b7526e931b9ba1f5154b9ab13dfd9820fefef03bd1aee192`

Height-1 timestamp: `1786213343`, 2026-08-08 18:22:23 UTC.

## Supply disclosure for technical review

Height 1 allocates 5,000,000 RUB to the owner in place of that block's regular
subsidy. The regular schedule starts at 100 RUB and halves every 500,000 blocks;
from height 5,000,000, subsidy is 0.1 RUB per block indefinitely. There is no
aggregate fixed maximum supply. Fees are separate from subsidy. Read
`coinbasevalue` from the actual template for mining and use chain-derived supply
for market data. The authoritative rules are implemented in the source files listed below.

Reference files for the parameters above are
`src/kernel/chainparams.cpp`, `src/chainparamsbase.cpp`, `src/consensus/consensus.h`,
`src/consensus/amount.h`, `src/validation.cpp` and `src/pow.cpp`.
