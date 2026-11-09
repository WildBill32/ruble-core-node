#!/usr/bin/env python3
# Copyright (c) 2026 The Ruble Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Document the unavailable Ruble mainnet ASERT fixture.

This inherited test previously replayed Bitcoin-specific blocks and therefore
could not test Ruble. Ruble block 1 uses nBits 0x1a0400d1 and cannot be mined in
a bounded functional test. Re-enable this test only with a pinned, independently
verified Ruble fixture containing valid native and AuxPoW blocks, the exact
height-1 premine, and a real ASERT transition.
"""

from test_framework.test_framework import BitcoinTestFramework, SkipTest


class MiningMainnetTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.chain = ""  # main

    def skip_test_if_missing_module(self):
        # This hook runs before setup_chain/setup_network, so no mainnet node is
        # started while the required immutable fixture is unavailable.
        raise SkipTest(
            "No pinned Ruble mainnet ASERT fixture; "
            "nBits 0x1a0400d1 cannot be mined in a functional test"
        )

    def run_test(self):
        raise AssertionError("unreachable without a verified Ruble fixture")


if __name__ == "__main__":
    MiningMainnetTest(__file__).main()
