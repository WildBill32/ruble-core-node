#!/usr/bin/env python3
# Copyright (c) 2026 The Ruble Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Test Ruble's premine, halving schedule, tail subsidy, and maturity."""

from decimal import Decimal

from test_framework.address import ADDRESS_BCRT1_UNSPENDABLE, address_to_scriptpubkey
from test_framework.blocktools import create_block, create_coinbase
from test_framework.script import CScript, OP_FALSE, OP_TRUE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
)
from test_framework.wallet import MiniWallet, MiniWalletMode


PREMINE = Decimal("5000000.00000000")
REGULAR_SUBSIDY = Decimal("100.00000000")
PRE_TAIL_SUBSIDY = Decimal("0.19531250")
TAIL_SUBSIDY = Decimal("0.10000000")


class RubleTokenomicsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-test=premine"]]

    @staticmethod
    def coinbase_total(block):
        return sum((output["value"] for output in block["tx"][0]["vout"]), Decimal("0"))

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Reject an underpaid height-1 premine")
        underpaid_premine = create_block(
            hashprev=int(node.getbestblockhash(), 16),
            coinbase=create_coinbase(1, nValue=4_999_999),
        )
        underpaid_premine.solve()
        assert_equal(node.submitblock(underpaid_premine.serialize().hex()), "bad-cb-premine")

        self.log.info("Reject an overpaid height-1 premine")
        overpaid_premine = create_block(
            hashprev=int(node.getbestblockhash(), 16),
            coinbase=create_coinbase(1, nValue=5_000_001),
        )
        overpaid_premine.solve()
        assert_equal(node.submitblock(overpaid_premine.serialize().hex()), "bad-cb-premine")

        self.log.info("Reject the exact amount when it pays the wrong owner script")
        wrong_owner_premine = create_block(
            hashprev=int(node.getbestblockhash(), 16),
            coinbase=create_coinbase(
                1,
                script_pubkey=CScript([OP_FALSE]),
                nValue=5_000_000,
            ),
        )
        wrong_owner_premine.solve()
        assert_equal(node.submitblock(wrong_owner_premine.serialize().hex()), "bad-cb-premine-script")

        self.log.info("The standard block assembler pays the configured owner, not the miner address")
        premine_hash = self.generatetoaddress(
            node,
            1,
            ADDRESS_BCRT1_UNSPENDABLE,
        )[0]
        premine_block = node.getblock(premine_hash, 2)
        premine_tx = premine_block["tx"][0]

        assert_equal(premine_block["height"], 1)
        assert_equal(self.coinbase_total(premine_block), PREMINE)
        assert any(
            output["value"] == PREMINE
            and output["scriptPubKey"]["hex"] == CScript([OP_TRUE]).hex()
            for output in premine_tx["vout"]
        )
        assert not any(
            output["value"] == PREMINE
            and output["scriptPubKey"].get("address") == ADDRESS_BCRT1_UNSPENDABLE
            for output in premine_tx["vout"]
        )

        wallet = MiniWallet(node, mode=MiniWalletMode.RAW_OP_TRUE)

        self.log.info("The premine replaces rather than augments the regular reward")
        regular_hash = self.generate(wallet, 1)[0]
        regular_block = node.getblock(regular_hash, 2)
        assert_equal(regular_block["height"], 2)
        assert_equal(self.coinbase_total(regular_block), REGULAR_SUBSIDY)

        self.log.info("The premine follows normal coinbase maturity")
        premine_utxo = wallet.get_utxo(txid=premine_tx["txid"])
        premature_spend = wallet.create_self_transfer(utxo_to_spend=premine_utxo)
        premature_spend["tx"].vin[0].scriptSig = CScript()
        premature_spend["tx"].vout[0].scriptPubKey = address_to_scriptpubkey(ADDRESS_BCRT1_UNSPENDABLE)
        premature_spend["tx"].rehash()
        premature_height = node.getblockcount() + 1
        premature_block = create_block(
            hashprev=int(node.getbestblockhash(), 16),
            coinbase=create_coinbase(premature_height),
            ntime=node.getblockheader(node.getbestblockhash())["time"] + 1,
            txlist=[premature_spend["tx"]],
        )
        premature_block.solve()
        assert_equal(node.submitblock(premature_block.serialize().hex()), "bad-txns-premature-spend-of-coinbase")

        self.generate(wallet, 99)
        wallet.rescan_utxos()
        mature_premine_utxo = wallet.get_utxo(txid=premine_tx["txid"])
        mature_spend = wallet.create_self_transfer(utxo_to_spend=mature_premine_utxo)
        mature_spend["tx"].vin[0].scriptSig = CScript()
        mature_spend["tx"].vout[0].scriptPubKey = address_to_scriptpubkey(ADDRESS_BCRT1_UNSPENDABLE)
        mature_spend["tx"].rehash()
        mature_height = node.getblockcount() + 1
        mature_block = create_block(
            hashprev=int(node.getbestblockhash(), 16),
            coinbase=create_coinbase(mature_height),
            ntime=node.getblockheader(node.getbestblockhash())["time"] + 1,
            txlist=[mature_spend["tx"]],
        )
        mature_block.solve()
        assert_equal(node.submitblock(mature_block.serialize().hex()), None)

        self.log.info("Regtest reaches the perpetual 0.1 RUB tail after ten 150-block halvings")
        self.generate(wallet, 1_499 - node.getblockcount())
        pre_tail_block = node.getblock(node.getbestblockhash(), 2)
        assert_equal(pre_tail_block["height"], 1_499)
        assert_equal(self.coinbase_total(pre_tail_block), PRE_TAIL_SUBSIDY)

        tail_hash = self.generate(wallet, 1)[0]
        tail_block = node.getblock(tail_hash, 2)
        assert_equal(tail_block["height"], 1_500)
        assert_equal(self.coinbase_total(tail_block), TAIL_SUBSIDY)

        later_tail_hash = self.generate(wallet, 150)[-1]
        later_tail_block = node.getblock(later_tail_hash, 2)
        assert_equal(self.coinbase_total(later_tail_block), TAIL_SUBSIDY)


if __name__ == "__main__":
    RubleTokenomicsTest(__file__).main()
