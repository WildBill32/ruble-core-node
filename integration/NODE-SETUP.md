# Run a Ruble mainnet node

Use the server binaries from [BUILD-LINUX.md](BUILD-LINUX.md), a dedicated OS
account and a fresh data directory on your own host.

From the binary package directory:

```bash
sha256sum -c SHA256SUMS
./bin/rubled --version
install -d -m 700 "$HOME/.ruble"
cp -n /path/to/ruble-core-source/integration/ruble.conf.example "$HOME/.ruble/ruble.conf"
chmod 600 "$HOME/.ruble/ruble.conf"
./bin/rubled -datadir="$HOME/.ruble" -daemon
./bin/ruble-cli -datadir="$HOME/.ruble" getblockchaininfo
./bin/ruble-cli -datadir="$HOME/.ruble" getnetworkinfo
./bin/ruble-cli -datadir="$HOME/.ruble" getblockhash 0
./bin/ruble-cli -datadir="$HOME/.ruble" getblockhash 1
./bin/ruble-cli -datadir="$HOME/.ruble" getindexinfo
```

Confirm `chain=main`, `auxpowactivationheight=7000`, the genesis and height-1
hashes in [NETWORK.md](NETWORK.md), connected peers and completed initial sync.
Compare the tip with independent Ruble nodes. Wait for `txindex` synchronization
before using arbitrary historical transaction lookup.

- P2P: TCP **33888**. RPC: TCP **33887**.
- The example uses RPC cookie authentication on loopback. Run the CLI under
  the same OS account and data directory.
- For a separate backend account, generate your own credentials with
  `share/rpcauth/rpcauth.py`. Keep RPC on a trusted private connection with
  appropriately restricted access.
- The source includes `pool.rublecore.org` as a bootstrap seed. If it is
  unavailable, request a current peer from the project.
- The optional [systemd example](rubled.service.example) uses user `ruble`,
  `/var/lib/ruble` for data and `/etc/ruble/ruble.conf` for configuration.
  Create those paths first and adjust binary paths. For that layout, use
  `sudo -u ruble /opt/ruble/bin/ruble-cli -datadir=/var/lib/ruble -conf=/etc/ruble/ruble.conf`
  followed by the RPC method.

For that systemd layout, install the binaries under `/opt/ruble/bin`, create a
dedicated `ruble` user/group, and make `/var/lib/ruble` owned by that account
with mode `0700`. Make `/etc/ruble/ruble.conf` readable by that account with
mode `0600` and use the supplied example as the starting configuration.
Install the service example as `/etc/systemd/system/rubled.service`, then use
`systemctl daemon-reload` and `systemctl enable --now rubled`. Use either this
service layout or the manual start above on a given host/port. An existing
installation should retain its own paths, configuration and service account.

Ruble stores a rolling-finality anchor. For recovery, read
[the finality guide](../doc/ruble-rolling-finality.md) before deleting chainstate
or attempting a full reindex.
