# `ruble.conf` configuration file

`ruble.conf` is read by `rubled`, `ruble-qt` and `ruble-cli`. The filename of
this inherited documentation file is retained only to avoid breaking internal
links.

The configuration file is not created automatically. Start from the inactive,
comment-only example at `share/examples/ruble.conf` and enable only settings
you understand. Never paste RPC credentials, wallet seeds or private keys from
an untrusted source.

Default locations are:

| Platform | Data directory | Configuration file |
|---|---|---|
| Linux and other Unix-like systems | `$HOME/.ruble` | `$HOME/.ruble/ruble.conf` |
| macOS | `$HOME/Library/Application Support/Ruble` | `$HOME/Library/Application Support/Ruble/ruble.conf` |
| Windows | `%LOCALAPPDATA%\Ruble` | `%LOCALAPPDATA%\Ruble\ruble.conf` |

Use `-datadir=<path>` to select another data directory and `-conf=<path>` to
select another configuration file. Relative paths are interpreted according to
the option documented by `rubled --help`.

Each setting has the form `option=value` without a leading dash. Blank lines
and text after `#` are ignored. Command-line options override configuration
values; runtime values in `settings.json` may override or augment them.

Network-specific sections use `[main]`, `[test]`, `[testnet4]`, `[signet]` and
`[regtest]`. For example:

```ini
regtest=1

[regtest]
server=1
```

Changes take effect after restarting the process. Check `debug.log` for active
paths, ignored sections and unrecognized options. The program's `--help`
output is authoritative for the exact v1.0.1 option set.
