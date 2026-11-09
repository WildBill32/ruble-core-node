#!/usr/bin/env python3
# Copyright (c) 2026 The Ruble Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Verify that Ruble rejects an unspent duplicate transaction (BIP30)."""

import copy

from test_framework.address import ADDRESS_BCRT1_UNSPENDABLE
from test_framework.blocktools import create_block, create_coinbase
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


DUPLICATE_COINBASE_SCRIPT_SIG = b"\x01\x78"  # BIP34 encoding of height 120


class RubleBIP30Test(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-testactivationheight=bip34@2"]]

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Create a height-1 coinbase that can be repeated at height 120")
        duplicate_coinbase = create_coinbase(1)
        duplicate_coinbase.vin[0].scriptSig = DUPLICATE_COINBASE_SCRIPT_SIG
        duplicate_coinbase.rehash()

        first_block = create_block(
            hashprev=int(node.getbestblockhash(), 16),
            coinbase=duplicate_coinbase,
        )
        first_block.solve()
        assert_equal(node.submitblock(first_block.serialize().hex()), None)

        self.generatetoaddress(node, 118, ADDRESS_BCRT1_UNSPENDABLE)
        assert_equal(node.getblockcount(), 119)

        self.log.info("Reject the duplicate while its original output is unspent")
        tip = node.getblockheader(node.getbestblockhash())
        duplicate_block = create_block(
            hashprev=int(tip["hash"], 16),
            coinbase=copy.deepcopy(duplicate_coinbase),
            ntime=tip["time"] + 1,
        )
        duplicate_block.solve()
        assert_equal(
            node.submitblock(duplicate_block.serialize().hex()),
            "bad-txns-BIP30",
        )
        assert_equal(node.getblockcount(), 119)


if __name__ == "__main__":
    RubleBIP30Test(__file__).main()
