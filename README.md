# Ruble Core (RUB)

Source for the Ruble mainnet full node: **1.0.1, AuxPoW activation height 7000**.
The same node provides the wallet RPC used by exchanges and the mining RPC
used by native SHA-256d and AuxPoW merged-mining pools.

## Integration

1. [Build the Linux node](integration/BUILD-LINUX.md).
2. [Configure and synchronize](integration/NODE-SETUP.md).
3. Follow the [exchange guide](integration/EXCHANGE.md),
   [native pool guide](integration/POOL-NATIVE.md), or
   [AuxPoW merged-mining guide](integration/AUXPOW.md).

References: [network parameters](integration/NETWORK.md),
[RPC](integration/RPC.md), [AuxPoW](integration/AUXPOW.md),
[configuration](integration/ruble.conf.example),
[source verification](integration/PROVENANCE.md).

Windows GUI wallet 1.0.2 contains startup and logo fixes and is distributed
[separately](https://github.com/WildBill32/ruble-core-releases/releases).
These fixes do not require a new Linux node version.

[Website](https://rublecore.org/) · [X](https://x.com/RubleCore) ·
Contact: rublecore.org@gmail.com

See [COPYING](COPYING) and individual file notices for licensing. Bitcoin Core
and Fractal Bitcoin attribution is retained.
