# Ruble Core file system

The default data directory is `$HOME/.ruble` on Linux and other Unix-like
systems, `$HOME/Library/Application Support/Ruble` on macOS, and
`%LOCALAPPDATA%\Ruble` on Windows. `-datadir=<path>` selects another location.

Important files and directories include:

| Path | Purpose |
|---|---|
| `ruble.conf` | Static configuration; see [configuration](bitcoin-conf.md). |
| `settings.json` | Runtime settings written by GUI/RPC commands. |
| `debug.log` | Diagnostic log. |
| `.cookie` | Ephemeral RPC authentication token; protect as a credential. |
| `rubled.pid` | Daemon process ID when configured. |
| `blocks/blk*.dat` | Serialized block data. |
| `blocks/rev*.dat` | Undo data used for reorganizations. |
| `blocks/index/` | Block index database. |
| `chainstate/` | Current UTXO database. |
| `indexes/` | Optional transaction, block-filter and coin-stat indexes. |
| `wallets/` | Wallet databases and metadata. |
| `peers.dat` | Known peer addresses. |
| `banlist.json` | Persisted peer bans. |
| `mempool.dat` | Persisted mempool state. |

Network-specific data lives under `testnet3/`, `testnet4/`, `signet/` or
`regtest/`. Mainnet uses the data-directory root.

Never copy a live data directory while `rubled` or `ruble-qt` is writing to it.
Back up wallets separately and never include `wallet.dat`, descriptors, seed
phrases, private keys, `.cookie` or RPC credentials in support archives.

RC4 data directories use a superseded genesis identity and are not compatible
with the live Ruble mainnet. Use a new empty directory when migrating from RC4.
Database formats and optional index files are inherited from Bitcoin Core and
may change between development snapshots; the program's log is authoritative
when a reindex is required.
