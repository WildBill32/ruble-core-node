#!/usr/bin/env python3
# Copyright (c) 2026 The Ruble Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise Ruble rolling finality at both sides of its exact boundary."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class RubleFinalityTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 4
        # Nodes 0 and 2 enforce the production depth. Nodes 1 and 3 model
        # private miners constructing more-work branches without that policy.
        self.extra_args = [
            ["-test=finality"],
            [],
            ["-test=finality"],
            [],
        ]

    def run_test(self):
        self.log.info("Create a five-block common prefix")
        self.generate(self.nodes[0], 5)
        self.sync_blocks()
        common_hash = self.nodes[0].getbestblockhash()

        # Default topology is 0-1-2-3. Isolate all four miners before making
        # the two independent reorganization cases.
        self.disconnect_nodes(0, 1)
        self.disconnect_nodes(1, 2)
        self.disconnect_nodes(2, 3)

        self.log.info("Build a 21-block-deep honest history and a heavier attack branch")
        self.generate(self.nodes[0], 21, sync_fun=self.no_op)
        protected_tip = self.nodes[0].getbestblockhash()
        self.generate(self.nodes[1], 22, sync_fun=self.no_op)
        attack_tip = self.nodes[1].getbestblockhash()
        assert protected_tip != attack_tip

        info = self.nodes[0].getblockchaininfo()["finality"]
        assert_equal(info["enabled"], True)
        assert_equal(info["depth"], 20)
        assert_equal(info["finalized_height"], 6)

        self.log.info("A reorg disconnecting 21 blocks is rejected automatically")
        with self.nodes[0].assert_debug_log(["conflicts with finalized block"]):
            self.connect_nodes(0, 1)
            self.wait_until(
                lambda: self.nodes[0].getbestblockhash() == protected_tip,
                timeout=10,
            )
        assert_equal(self.nodes[0].getblockcount(), 26)
        assert_equal(self.nodes[0].getbestblockhash(), protected_tip)
        assert_equal(self.nodes[1].getbestblockhash(), attack_tip)

        self.disconnect_nodes(0, 1)
        finalized_hash = self.nodes[0].getblockhash(6)
        assert_raises_rpc_error(
            -20,
            "finalized-block",
            self.nodes[0].invalidateblock,
            finalized_hash,
        )

        self.log.info("Finality never moves backward and survives restart")
        first_unfinalized_hash = self.nodes[0].getblockhash(7)
        self.nodes[0].invalidateblock(first_unfinalized_hash)
        assert_equal(self.nodes[0].getblockcount(), 6)
        assert_equal(
            self.nodes[0].getblockchaininfo()["finality"]["finalized_hash"],
            finalized_hash,
        )
        self.restart_node(0)
        restarted_info = self.nodes[0].getblockchaininfo()["finality"]
        assert_equal(restarted_info["finalized_height"], 6)
        assert_equal(restarted_info["finalized_hash"], finalized_hash)
        assert_raises_rpc_error(
            -20,
            "finalized-block",
            self.nodes[0].invalidateblock,
            finalized_hash,
        )

        self.log.info("Build the boundary case: exactly 20 blocks may reorganize")
        assert_equal(self.nodes[2].getbestblockhash(), common_hash)
        assert_equal(self.nodes[3].getbestblockhash(), common_hash)
        self.generate(self.nodes[2], 20, sync_fun=self.no_op)
        old_boundary_tip = self.nodes[2].getbestblockhash()
        self.generate(self.nodes[3], 21, sync_fun=self.no_op)
        allowed_tip = self.nodes[3].getbestblockhash()
        assert old_boundary_tip != allowed_tip

        boundary_info = self.nodes[2].getblockchaininfo()["finality"]
        assert_equal(boundary_info["finalized_height"], 5)
        assert_equal(boundary_info["finalized_hash"], common_hash)

        self.connect_nodes(2, 3)
        self.sync_blocks(self.nodes[2:4])
        assert_equal(self.nodes[2].getbestblockhash(), allowed_tip)
        assert_equal(self.nodes[2].getblockcount(), 26)


if __name__ == "__main__":
    RubleFinalityTest(__file__).main()
