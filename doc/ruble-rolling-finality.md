# Ruble rolling finality

Status: mandatory mainnet fork-choice rule in Ruble Core v1.0.1.

## Exact rule

Let `H` be the active-chain tip height. Mainnet uses:

- finality depth: `20` blocks;
- immutable floor: height `1`, already protected by the launch-block
  commitment;
- rolling candidate height: `max(1, H - 20)`.

When that candidate is above the node's previously finalized block, its exact
hash is committed synchronously with the block-index metadata. The persisted
finalized block is monotonic: it can advance, but it never moves backward after
a short reorganization, an `invalidateblock` call, a clean restart, or crash
recovery. A candidate tip is compatible only when it is on the persisted
finalized block's ancestry path. Compatible branches continue to use normal
accumulated-chainwork ordering. An incompatible header or candidate is not
activated even when its chainwork is larger.

This gives an exact boundary:

- disconnecting 20 active blocks is allowed;
- disconnecting 21 active blocks is rejected;
- a transfer should not be represented as protected by rolling finality until
  the block containing it is at or below the reported finalized height.

The rule is fixed in mainnet chain parameters. Operators cannot change it in a
configuration file, disable it with `-checkpoints=0`, override it with
`preciousblock`, or invalidate a finalized active block. A regtest-only
`-test=finality` switch exists so automated tests can exercise the production
depth without breaking inherited tests that intentionally create very deep
forks.

## Automatic attack behavior

When a synchronized node receives a late private branch that forked below its
finalized block, it rejects the incompatible header/candidate and keeps its
current tip. Honest miners continue building on the unchanged public history.
Stopping the attacker requires no source edit, checkpoint release, database
deletion, or operator RPC. Known diagnostic side branches are reported by
`getchaintips` as `finality-conflict`; new incompatible headers are rejected
before their block bodies are downloaded.

The `finality` object returned by `getblockchaininfo` contains:

- `enabled`;
- `depth`;
- `finalized_height` when a finalized block exists;
- `finalized_hash` when a finalized block exists.

## What it does not solve

Rolling finality is intentionally a weak-subjectivity rule: the node protects
history it has already observed and buried. It cannot provide all three of the
following at once using proof of work alone: immunity to a majority-hash fork,
automatic convergence after an arbitrarily long network partition, and no
external trust source.

In particular:

- two network partitions that each mine far enough can finalize conflicting
  histories and will not automatically merge;
- a brand-new or long-offline node connected only to hostile peers can be
  bootstrapped onto the attacker's history before it has a local finalized
  reference;
- an eclipse attack inside the unfinalized window can still influence the
  victim's first-seen history;
- a majority miner can still reorganize up to 20 active blocks, censor
  transactions, or stop producing public blocks;
- finality does not defend RPC credentials, private keys, binaries, servers,
  DNS seeds, pools, or network availability.

A full `-reindex` would erase the block-index database that contains the local
finality record, so Ruble Core v1.0.1 refuses that operation on mainnet. The narrower
`-reindex-chainstate` recovery retains the record and can rebuild only along
its permitted ancestry. Destructive datadir replacement remains an explicit
disaster-recovery event, not an automatic response to a hash-rate attack.

These boundaries are why every release must still test eclipse/partition scenarios and
run several independently hosted, well-connected nodes. Exchange and explorer
integrations should consume the reported finalized height rather than infer
finality only from elapsed time.
