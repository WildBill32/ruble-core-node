#!/usr/bin/env python3
# Copyright (c) 2019-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test basic Ruble signet functionality."""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


SIGNET_DEFAULT_CHALLENGE = "2084ada4a264ded2b6f94cc3666ee843986bd700b1d48f69c50eaeb242b2182b8e7551"


class SignetParams:
    def __init__(self, challenge=None):
        # Keep these nodes archival. During IBD, nodes deliberately do not
        # download blocks from NODE_NETWORK_LIMITED peers, which would make a
        # pair of pruned nodes exchange headers without transferring blocks.
        if challenge is None:
            self.challenge = SIGNET_DEFAULT_CHALLENGE
            self.shared_args = []
        else:
            self.challenge = challenge
            self.shared_args = [f"-signetchallenge={challenge}"]


class SignetBasicTest(BitcoinTestFramework):
    def set_test_params(self):
        self.chain = "signet"
        self.num_nodes = 6
        self.setup_clean_chain = True
        self.signets = [
            SignetParams(challenge="51"),  # OP_TRUE
            SignetParams(),  # Ruble default: <network commitment> OP_DROP OP_TRUE
            SignetParams(challenge="00"),  # OP_FALSE, rejects unsigned blocks
        ]

        self.extra_args = [
            self.signets[0].shared_args,
            self.signets[0].shared_args,
            self.signets[1].shared_args,
            self.signets[1].shared_args,
            self.signets[2].shared_args,
            self.signets[2].shared_args,
        ]

    def setup_network(self):
        self.setup_nodes()

        # Set up three signets with incompatible network magic/challenges.
        self.connect_nodes(0, 1)
        self.connect_nodes(2, 3)
        self.connect_nodes(4, 5)

    def run_test(self):
        self.log.info("getblockchaininfo")

        def check_getblockchaininfo(node_idx, signet_idx):
            blockchain_info = self.nodes[node_idx].getblockchaininfo()
            assert_equal(blockchain_info["chain"], "signet")
            assert_equal(blockchain_info["signet_challenge"], self.signets[signet_idx].challenge)

        check_getblockchaininfo(node_idx=1, signet_idx=0)
        check_getblockchaininfo(node_idx=2, signet_idx=1)
        check_getblockchaininfo(node_idx=5, signet_idx=2)

        self.log.info("getmininginfo")

        def check_getmininginfo(node_idx, signet_idx):
            mining_info = self.nodes[node_idx].getmininginfo()
            assert_equal(mining_info["blocks"], 0)
            assert_equal(mining_info["chain"], "signet")
            assert "currentblocktx" not in mining_info
            assert "currentblockweight" not in mining_info
            assert_equal(mining_info["networkhashps"], Decimal("0"))
            assert_equal(mining_info["pooledtx"], 0)
            assert_equal(mining_info["signet_challenge"], self.signets[signet_idx].challenge)

        check_getmininginfo(node_idx=0, signet_idx=0)
        check_getmininginfo(node_idx=3, signet_idx=1)
        check_getmininginfo(node_idx=4, signet_idx=2)

        self.log.info("mine and synchronize an OP_TRUE signet block")
        self.generate(self.nodes[0], 1, sync_fun=self.no_op)
        self.sync_blocks(self.nodes[0:2])

        self.log.info("mine and synchronize a default Ruble signet block")
        default_block_hash = self.generate(self.nodes[2], 1, sync_fun=self.no_op)[0]
        self.sync_blocks(self.nodes[2:4])

        self.log.info("reject a Ruble signet block under an incompatible challenge")
        default_block = self.nodes[2].getblock(default_block_hash, 0)
        assert_equal(self.nodes[4].submitblock(default_block), "bad-signet-blksig")
        assert_equal(self.nodes[4].getblockcount(), 0)

        self.log.info("test that signet logs the network magic on node start")
        with self.nodes[0].assert_debug_log(["Signet derived magic (message start)"]):
            self.restart_node(0)
        self.stop_node(0)
        self.nodes[0].assert_start_raises_init_error(
            extra_args=["-signetchallenge=abc"],
            expected_msg="Error: -signetchallenge must be hex, not 'abc'.",
        )
        self.nodes[0].assert_start_raises_init_error(
            extra_args=["-signetchallenge=abc"] * 2,
            expected_msg="Error: -signetchallenge cannot be multiple values.",
        )


if __name__ == "__main__":
    SignetBasicTest(__file__).main()
