# Exchange integration

Run your own synchronized `rubled` from this repository. RUB is the native
asset of the Ruble blockchain, with **8 decimal places**. Integration uses the
node's Bitcoin Core-style wallet and chain RPC.

## Wallet and deposit addresses

For a new SQLite descriptor wallet:

```bash
ruble-cli -named createwallet wallet_name=exchange descriptors=true load_on_startup=true
ruble-cli -rpcwallet=exchange getwalletinfo
ruble-cli -rpcwallet=exchange getnewaddress "deposit-reference" "bech32"
```

Use your exchange's key custody, encryption and backup policy. For wallet RPC,
select `-rpcwallet=exchange` or HTTP endpoint `/wallet/exchange`.

## Deposits

Use `listsinceblock` with a persisted block-hash cursor and `gettransaction` for
wallet activity. Set the variables below from your stored cursor and your
exchange's confirmation policy:

```bash
ruble-cli -rpcwallet=exchange -named listsinceblock \
  blockhash="$deposit_cursor" target_confirmations="$required_confirmations" \
  include_removed=true include_watchonly=true
```

On the initial scan, omit `blockhash`. `target_confirmations` controls the
returned `lastblock` cursor; it does **not** filter out unconfirmed deposits.
Store `lastblock` only after recording all returned wallet changes. Identify
each deposit output by `(txid, vout)` and apply confirmation/category rules
before crediting it. Repeated RPC results must not produce duplicate credits.
Process `removed`, conflicts and confirmation rollback, and continue checking
pending deposits until they meet your policy. Relevant wallet descriptors must
be imported before relying on wallet activity, with an appropriate historical
rescan if the addresses were used earlier.

Store amounts in integer base units: **1 RUB = 100,000,000 base units**.
RPC amounts are decimal RUB; parse them with decimal arithmetic, not binary
floating-point rounding.
Validate addresses through the node; native SegWit addresses start with `rub1`.

Choose required deposit confirmations under your exchange's policy. The
network's finality depth is 20 blocks; this is a consensus property, not an
exchange-credit rule. Coinbase outputs have a 100-block maturity requirement.

## Withdrawals

Use `sendtoaddress`, or your normal PSBT flow with `walletcreatefundedpsbt`,
`walletprocesspsbt`, `finalizepsbt` and `sendrawtransaction`. Record transaction
IDs against your own withdrawal IDs. An RPC timeout does not prove the payment
failed: reconcile wallet activity and the previously prepared transaction before
retrying. `sendtoaddress` has no exchange-withdrawal idempotency key.

### Fee selection

A new node, or a node with little transaction history, may have no usable
automatic fee estimate. The default fallback fee is disabled (`0`), so a
withdrawal relying on that estimate can return `Fee estimation failed`.

Your backend can supply an explicit fee rate under its own fee policy. With
your real destination, amount, rate and withdrawal ID in the variables below:

```bash
ruble-cli -rpcwallet=exchange -named sendtoaddress \
  address="$withdrawal_address" amount="$withdrawal_amount_rub" \
  fee_rate="$withdrawal_fee_rate" comment="$withdrawal_id"
```

For `sendtoaddress`, `fee_rate` is in **base units per virtual byte**
(1 base unit = 0.00000001 RUB). Do not combine an explicit `fee_rate` with
`conf_target` or an `estimate_mode` other than `unset`. Check `help` for the
exact fee option of each PSBT/funding method; do not assume all fee fields
use the same units.

`estimatesmartfee` returns `feerate` in **RUB per 1,000 virtual bytes** and
can return `errors` instead of a usable rate. `getmempoolinfo` exposes current
node fee floors in RUB per 1,000 virtual bytes. Convert units explicitly and
enforce an exchange-side maximum fee before signing. An operator-configured
`fallbackfee` is also expressed in **RUB per 1,000 virtual bytes**. For unit
conversion only, 1 base unit/vB equals 0.00001 RUB/1,000 vB; this is not a
recommended fee rate.

An explicit `sendtoaddress` fee rate defaults to RBF signaling unless
`replaceable` is specified. Track replacements by withdrawal ID and reconcile
the eventual confirmed transaction.

## Before enabling customer transfers

Before opening customer deposits and withdrawals, verify synchronization,
address creation, deposit recognition, withdrawal confirmation and restoration
of your chosen wallet backup in an isolated recovery environment. Include
insufficient-fee-estimate handling, repeated deposit notifications, RPC timeouts
and transaction replacement handling in your backend's checks. Choose custody,
wallet encryption and signing arrangements under your exchange's own policy.
Keep the source revision and binary hashes.

See [RPC.md](RPC.md) and [NETWORK.md](NETWORK.md) for exact interfaces and
network parameters. Prefer decoded node RPC when indexing: AuxPoW blocks
contain additional proof data that a Bitcoin-only raw-header parser may omit.
