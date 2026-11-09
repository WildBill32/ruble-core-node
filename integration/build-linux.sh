#!/usr/bin/env bash
# Build/package on an integrator build machine. Never install or run a node.
set -Eeuo pipefail
umask 077
src_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
for build_tool in cmake ninja c++ pkg-config python3 sha256sum; do
    command -v "$build_tool" >/dev/null || { echo "Missing build dependency: $build_tool" >&2; exit 1; }
done
build_jobs="${RUBLE_BUILD_JOBS:-2}"
[[ "$build_jobs" =~ ^[1-9][0-9]*$ ]] || { echo 'RUBLE_BUILD_JOBS must be a positive integer' >&2; exit 1; }
build_zmq="${RUBLE_WITH_ZMQ:-OFF}"
[[ "$build_zmq" == ON || "$build_zmq" == OFF ]] || { echo 'RUBLE_WITH_ZMQ must be ON or OFF' >&2; exit 1; }
python3 -B "$src_dir/integration/verify-source.py"
build_root="$(mktemp -d /tmp/ruble-integration-build.XXXXXXXX)"
printf 'Build output: %s\n' "$build_root"
cmake -S "$src_dir" -B "$build_root/build" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_DAEMON=ON -DBUILD_CLI=ON -DBUILD_GUI=OFF -DBUILD_WALLET_TOOL=ON \
    -DBUILD_TESTS=ON -DBUILD_BENCH=OFF \
    -DENABLE_WALLET=ON -DWITH_SQLITE=ON -DWITH_BDB=OFF \
    -DWITH_ZMQ="$build_zmq" -DWITH_CCACHE=OFF \
    2>&1 | tee "$build_root/configure.log"
cmake --build "$build_root/build" --parallel "$build_jobs" 2>&1 | tee "$build_root/build.log"
"$build_root/build/bin/test_bitcoin" --log_level=test_suite 2>&1 | tee "$build_root/unit-tests.log"
package_dir="$build_root/package"
install -d "$package_dir/bin"
install -m 0755 "$build_root/build/bin/rubled" "$build_root/build/bin/ruble-cli" "$build_root/build/bin/ruble-wallet" "$package_dir/bin/"
install -m 0644 "$src_dir/COPYING" "$package_dir/COPYING"
install -d "$package_dir/licenses"
install -m 0644 "$src_dir/src/secp256k1/COPYING" "$package_dir/licenses/secp256k1-COPYING"
install -m 0644 "$src_dir/src/minisketch/LICENSE" "$package_dir/licenses/minisketch-LICENSE"
install -m 0644 "$src_dir/src/leveldb/LICENSE" "$package_dir/licenses/leveldb-LICENSE"
install -m 0644 "$src_dir/src/crc32c/LICENSE" "$package_dir/licenses/crc32c-LICENSE"
cp "$src_dir/integration/source-baseline.json" "$package_dir/source-baseline.json"
"$package_dir/bin/rubled" --version > "$package_dir/VERSION.txt"
python3 - "$src_dir" "$package_dir" <<'PY'
import hashlib, json, subprocess, sys
from pathlib import Path
src, dst = map(Path, sys.argv[1:])
data = json.loads((src / 'integration/source-baseline.json').read_text())
record = {'version': data['server_version'], 'distribution': data['distribution'],
          'source_manifest_sha256': hashlib.sha256((src / 'integration/source-baseline.json').read_bytes()).hexdigest()}
try:
    checkout_root = subprocess.check_output(['git', '-C', str(src), 'rev-parse', '--show-toplevel'], text=True, stderr=subprocess.DEVNULL).strip()
    record['checkout_commit'] = (subprocess.check_output(['git', '-C', str(src), 'rev-parse', 'HEAD'], text=True, stderr=subprocess.DEVNULL).strip()
                                 if Path(checkout_root).resolve() == src.resolve() else None)
except (OSError, subprocess.CalledProcessError):
    record['checkout_commit'] = None
(dst / 'SOURCE.json').write_text(json.dumps(record, indent=2) + '\n')
(dst / 'BUILD-VALIDATION.txt').write_text('BUILD=PASS\nCPP_UNIT_TESTS=PASS\nLIVE_CHAIN_SYNC=NOT_RUN\nPOOL_EXCHANGE_END_TO_END=NOT_RUN\n')
PY
(
    cd "$package_dir"
    sha256sum bin/rubled bin/ruble-cli bin/ruble-wallet COPYING licenses/* source-baseline.json VERSION.txt SOURCE.json BUILD-VALIDATION.txt > SHA256SUMS
    sha256sum -c SHA256SUMS
)
printf '\nBUILD_AND_UNIT_TESTS=PASS\nPackage: %s\n' "$package_dir"
