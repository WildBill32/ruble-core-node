#!/usr/bin/env python3
"""Verify the distributed source and run node-side offline structural checks."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
manifest = json.loads((root / 'integration/source-baseline.json').read_text())
failures = []
# A manifest can be self-consistent while omitting a required build input.
# Check literal root configure_file inputs independently of the manifest.
# Module-local calls may be relative to their caller and are not guessed here;
# a real CMake configure/build remains the authoritative build check.
required_inputs = {
    'CMakeLists.txt', 'src/CMakeLists.txt', 'contrib/filter-lcov.py',
    'contrib/devtools/ruble_consensus_check.py',
    'contrib/devtools/ruble_finality_source_check.py',
    'contrib/devtools/ruble_auxpow_activation_source_check.py',
}
cmake_file = root / 'CMakeLists.txt'
if cmake_file.is_file():
    cmake_text = cmake_file.read_text(encoding='utf-8')
    for match in re.finditer(r'(?m)^\s*configure_file\s*\(\s*(?:"([^"\n]+)"|([^\s\)]+))', cmake_text):
        source = match.group(1) or match.group(2)
        if '$' not in source:
            required_inputs.add(source)
for name in sorted(required_inputs):
    p = root / name
    if not p.is_file() or p.is_symlink():
        failures.append(name + ': required build/check input missing')

seen = set()
for entry in manifest['entries']:
    relative = Path(entry['path'])
    if relative.is_absolute() or '..' in relative.parts or entry['path'] in seen:
        failures.append(entry['path'] + ': invalid or duplicate manifest path')
        continue
    seen.add(entry['path'])
    p = root / entry['path']
    if not p.is_file() or p.is_symlink():
        failures.append(entry['path'] + ': missing or unexpected symlink')
    elif hashlib.sha256(p.read_bytes()).hexdigest() != entry['sha256']:
        failures.append(entry['path'] + ': checksum mismatch')
    elif sys.platform != 'win32' and bool(p.stat().st_mode & 0o111) != (entry['mode'] == '100755'):
        failures.append(entry['path'] + ': executable mode mismatch')
for name in sorted(required_inputs - seen):
    failures.append(name + ': required input absent from manifest')
if failures:
    print('\n'.join(failures), file=sys.stderr)
    raise SystemExit(1)
print('DISTRIBUTED_SOURCE_CHECKSUMS=PASS', flush=True)
print('REQUIRED_BUILD_INPUTS=PASS', flush=True)
for script in ('ruble_consensus_check.py', 'ruble_finality_source_check.py', 'ruble_auxpow_activation_source_check.py'):
    subprocess.run([sys.executable, '-B', str(root / 'contrib/devtools' / script)], cwd=root, check=True)
print('OFFLINE_NODE_SOURCE_GATES=PASS')
