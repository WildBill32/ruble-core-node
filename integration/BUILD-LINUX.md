# Build the Linux server node

Target documented here: Ubuntu 24.04 x86_64, Ruble Core 1.0.1 H7000.
The Windows 1.0.2 GUI fixes do not require a new Linux node version.

On your build machine, install the dependencies:

```bash
sudo apt-get update
sudo apt-get install build-essential cmake ninja-build pkgconf python3 libevent-dev libboost-dev libsqlite3-dev
```

From this source directory:

```bash
bash integration/build-linux.sh
```

The script verifies source checksums, builds out of tree, runs the existing C++
unit tests and creates a package containing `rubled`, `ruble-cli`, `ruble-wallet`,
license notices, build/source identifiers and SHA-256 checksums. It does not
start a daemon or run functional-test networks. `RUBLE_BUILD_JOBS=2` is the
default; set it to the number of build jobs appropriate for your host.

The exact output path under `/tmp/ruble-integration-build.*/package/` is printed
on success. Copy that package out of temporary storage and keep its build logs.
Then follow [NODE-SETUP.md](NODE-SETUP.md).

Extract the source ZIP with a tool that preserves Unix executable permissions
(for example, `unzip` on Linux). The source verifier checks those permissions as
well as file hashes. If your transfer tool changes them, extract the original
ZIP again on the build host.

This configuration enables SQLite descriptor wallets and disables GUI and BDB.
Legacy BDB wallets need the compatible Berkeley DB 4.8 build described in
[the platform build guide](../doc/build-unix.md).

For optional ZMQ notifications, install `libzmq3-dev` and run:

```bash
RUBLE_WITH_ZMQ=ON bash integration/build-linux.sh
```

This passes `-DWITH_ZMQ=ON` to CMake. Configure the desired notification
endpoints on your node; see [the ZMQ guide](../doc/zmq.md). RPC polling works
with the default `RUBLE_WITH_ZMQ=OFF` build.

The build script records success only after compilation and the unit-test
executable both finish successfully. See [PROVENANCE.md](PROVENANCE.md) for
the validation performed on this particular source distribution.
