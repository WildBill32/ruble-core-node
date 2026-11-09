# Source verification

Distribution: `ruble-core-node-1.0.1-h7000-integration3` (2026-09-08).
This is the server-node 1.0.1 source with mainnet AuxPoW activation at height 7000.

All files in `src/`, the dependency sources and node build definitions are unchanged
from the preserved server-node source. The source-only package excludes
development administration, historical notes and duplicated archives.

This packaging revision restores the required `contrib/filter-lcov.py` build
input, adds an independent check for literal root CMake configuration inputs,
and clarifies the exchange, native-pool and AuxPoW integration instructions.
It also exposes the optional ZMQ build setting through `RUBLE_WITH_ZMQ`.

Verify distributed file hashes and the offline node checks with:

```bash
python3 -B integration/verify-source.py
```

The manifest covers the distributed source and documentation. Required build
inputs are checked separately so that an incomplete package cannot pass merely
because its manifest was generated after an accidental omission. Existing checks
recompute genesis and issuance values, check rolling-finality bindings and
check node-side AuxPoW activation bindings. They do not start a node.

Source integrity and offline structural checks pass. The Linux build script
builds the node and records the outcome of its C++ unit tests on the build host.
These checks do not certify a third-party exchange's custody/accounting system
or a pool's Stratum adapter. Each operator validates its own integration before
enabling customer deposits, withdrawals or public hashrate.

The clean Linux build, existing C++ unit tests and isolated mainnet RPC checks
passed for this revision. See [VALIDATION.md](VALIDATION.md) for the exact scope
and results. No live network operation was required for these checks.
