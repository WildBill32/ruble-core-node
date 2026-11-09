# Native SHA-256d mining-pool integration

Run a Ruble full node and connect your pool backend to its RPC. The pool can use
its own Stratum service, payout scheme and worker configuration. It does not need
the project's pool website, coordinator, BTC node, or merge-mining port 3340.

## Required RPC flow

```bash
ruble-cli getblockchaininfo
ruble-cli getmininginfo
ruble-cli getblocktemplate '{"rules":["segwit"]}'
```

`getblocktemplate` requires a connected, synchronized node. Use its returned
`version`, `previousblockhash`, `bits`, `target`, `height`, `curtime`, transactions,
`coinbasevalue`, rules and limits. `coinbasevalue` is an integer in 10^-8 RUB units;
never hard-code the block reward into pool accounting.

Build a native block with a correct BIP34 height in the coinbase scriptSig, an
operator-owned payout script and the SegWit witness commitment when required.
Recompute the coinbase txid/Merkle root whenever extranonce changes. Do not hash
or submit a Bitcoin block template in place of a Ruble template.

Submit the complete solved block with `submitblock`. A JSON `null` result means
accepted by that RPC call; a string is a rejection/duplicate result that must be
interpreted. `submitblock` does not return a block hash: calculate it from your
submitted header and verify that hash is on the active chain before
crediting its reward. Handle orphaned blocks and confirmation rollback.

## Pool-specific points

- Algorithm: double SHA-256. Native header length: 80 bytes.
- Keep the native proof type from the node's template. Do not set the AuxPoW flag
  (`0x100`) accidentally. For ASICBoost/BIP310, apply only negotiated version bits
  and preserve all protocol-required bits; version-rolling support belongs in the
  pool's Stratum engine. This package does not claim a tested adapter for yiimp,
  NOMP or any named pool backend.
- Update jobs when the RUB tip changes, including when an AuxPoW block advances
  the chain. Native mining remains valid after height 7000.
- Obtain the native target from GBT. Do not substitute the AuxPoW difficulty or
  the Stratum share target for network block difficulty.
- Target spacing is 270 seconds for native blocks, 540 for AuxPoW, and 180 seconds
  combined when both channels participate. A native-only configuration must not
  assume a guaranteed 180-second block schedule.
- Coinbase maturity is 100 blocks; use actual wallet/chain maturity status before
  spending or paying a mined output.
- Address validation should use the node, not a Bitcoin-prefix validator. Native
  SegWit starts with `rub1`; see NETWORK.md for other encodings.

Verify template parsing, share accounting, coinbase construction, version rolling,
accepted-block handling and payouts on your backend before accepting public
hashrate. Supplying a daemon does not prove an arbitrary pool adapter needs no
changes.
