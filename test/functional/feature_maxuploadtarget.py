#!/usr/bin/env python3
# Copyright (c) 2015-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test behavior of -maxuploadtarget.

* Verify that getdata requests for old blocks (>1week) are dropped
if uploadtarget has been reached.
* Verify that getdata requests for recent blocks are respected even
if uploadtarget has been reached.
* Verify that mempool requests lead to a disconnect if uploadtarget has been reached.
* Verify that the upload counters are reset after 24 hours.
"""
from collections import defaultdict
import time

from test_framework.messages import (
    CInv,
    MAX_BLOCK_SERIALIZED_SIZE,
    MSG_BLOCK,
    msg_getdata,
    msg_mempool,
)
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    mine_large_block,
)
from test_framework.wallet import MiniWallet


UPLOAD_TARGET_MB = 256


class TestP2PConn(P2PInterface):
    def __init__(self):
        super().__init__()
        self.block_receive_map = defaultdict(int)

    def on_inv(self, message):
        pass

    def on_block(self, message):
        message.block.calc_sha256()
        self.block_receive_map[message.block.sha256] += 1

class MaxUploadTest(BitcoinTestFramework):

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[
            f"-maxuploadtarget={UPLOAD_TARGET_MB}M",
            "-datacarriersize=100000",
        ]]
        self.supports_cli = False

    def assert_uploadtarget_state(self, *, target_reached, serve_historical_blocks):
        """Verify the node's current upload target state via the `getnettotals` RPC call."""
        uploadtarget = self.nodes[0].getnettotals()["uploadtarget"]
        assert_equal(uploadtarget["target_reached"], target_reached)
        assert_equal(uploadtarget["serve_historical_blocks"], serve_historical_blocks)

    def run_test(self):
        # A full day of 48 MB relay reserve is intentionally larger than this
        # test target, so historical serving starts disabled.
        self.assert_uploadtarget_state(target_reached=False, serve_historical_blocks=False)

        # Before we connect anything, we first set the time on the node
        # to be in the past, otherwise things break because the CNode
        # time counters can't be reset backward after initialization
        old_time = int(time.time() - 2*60*60*24*7)
        self.nodes[0].setmocktime(old_time)

        # Generate some old blocks
        self.wallet = MiniWallet(self.nodes[0])
        self.generate(self.wallet, 130)

        # p2p_conns[0] will only request old blocks
        # p2p_conns[1] will only request new blocks
        # p2p_conns[2] will test resetting the counters
        p2p_conns = []

        for _ in range(3):
            # Don't use v2transport in this test (too slow with the unoptimized python ChaCha20 implementation)
            p2p_conns.append(self.nodes[0].add_p2p_connection(TestP2PConn(), supports_v2_p2p=False))

        # Now mine a big block
        mine_large_block(self, self.wallet, self.nodes[0])

        # Store the hash; we'll request this later
        big_old_block = self.nodes[0].getbestblockhash()
        old_block_size = self.nodes[0].getblock(big_old_block, True)['size']
        big_old_block = int(big_old_block, 16)

        # Advance to two days ago
        cycle_start_time = int(time.time()) - 2*60*60*24
        self.nodes[0].setmocktime(cycle_start_time)

        # Mine one more block, so that the prior block looks old
        mine_large_block(self, self.wallet, self.nodes[0])

        # We'll be requesting this new block too
        big_new_block = self.nodes[0].getbestblockhash()
        new_block_size = self.nodes[0].getblock(big_new_block, True)['size']
        big_new_block = int(big_new_block, 16)

        # Start a fresh upload cycle at two days ago, then move near its end.
        # This shrinks the relay reserve to at most one 48 MB block and makes
        # room for exercising the historical-serving threshold without
        # transferring several gigabytes.
        p2p_conns[2].sync_with_ping()
        self.nodes[0].setmocktime(cycle_start_time + 23 * 60 * 60 + 50 * 60)
        self.assert_uploadtarget_state(target_reached=False, serve_historical_blocks=True)

        # p2p_conns[0] will test what happens if we just keep requesting the
        # the same big old block too many times (expect: disconnect)

        getdata_request = msg_getdata()
        getdata_request.inv.append(CInv(MSG_BLOCK, big_old_block))

        uploadtarget = self.nodes[0].getnettotals()["uploadtarget"]
        relay_buffer = (
            uploadtarget["time_left_in_cycle"] // (10 * 60)
        ) * MAX_BLOCK_SERIALIZED_SIZE
        max_bytes_available = max(0, uploadtarget["bytes_left_in_cycle"] - relay_buffer)
        block_message_size = old_block_size + 24  # v1 header
        success_count = max(0, max_bytes_available // block_message_size - 1)

        # Stay just below the dynamically calculated historical-serving limit.
        for i in range(success_count):
            p2p_conns[0].send_and_ping(getdata_request)
            assert_equal(p2p_conns[0].block_receive_map[big_old_block], i+1)

        assert_equal(len(self.nodes[0].getpeerinfo()), 3)
        # Up to three more responses can fit (depending on message overhead).
        # The following request must observe the crossed threshold and disconnect.
        # Send sequentially so every getdata request observes the bytes queued by
        # the previous response.
        with self.nodes[0].assert_debug_log(expected_msgs=["historical block serving limit reached, disconnecting peer=0"]):
            for _ in range(4):
                blocks_before = p2p_conns[0].block_receive_map[big_old_block]
                p2p_conns[0].send_message(getdata_request)
                p2p_conns[0].wait_until(
                    lambda: (
                        not p2p_conns[0].is_connected
                        or p2p_conns[0].block_receive_map[big_old_block] > blocks_before
                    ),
                    check_connected=False,
                )
                if not p2p_conns[0].is_connected:
                    break
            p2p_conns[0].wait_for_disconnect()
        assert_equal(len(self.nodes[0].getpeerinfo()), 2)
        self.log.info("Peer 0 disconnected after downloading old block too many times")

        # Historical blocks serving limit is reached by now, but total limit still isn't
        self.assert_uploadtarget_state(target_reached=False, serve_historical_blocks=False)

        # Requesting the current block on p2p_conns[1] should succeed even when
        # it takes total traffic over the upload target.
        getdata_request.inv = [CInv(MSG_BLOCK, big_new_block)]
        bytes_left = self.nodes[0].getnettotals()["uploadtarget"]["bytes_left_in_cycle"]
        recent_requests = bytes_left // (new_block_size + 24) + 5
        for i in range(recent_requests):
            p2p_conns[1].send_and_ping(getdata_request)
            assert_equal(p2p_conns[1].block_receive_map[big_new_block], i+1)

        # Both historical blocks serving limit and total limit are reached
        self.assert_uploadtarget_state(target_reached=True, serve_historical_blocks=False)

        self.log.info("Peer 1 able to repeatedly download new block")

        # But if p2p_conns[1] tries for an old block, it gets disconnected too.
        getdata_request.inv = [CInv(MSG_BLOCK, big_old_block)]
        with self.nodes[0].assert_debug_log(expected_msgs=["historical block serving limit reached, disconnecting peer=1"]):
            p2p_conns[1].send_message(getdata_request)
            p2p_conns[1].wait_for_disconnect()
        assert_equal(len(self.nodes[0].getpeerinfo()), 1)

        self.log.info("Peer 1 disconnected after trying to download old block")

        self.log.info("Advancing system time on node to clear counters...")

        # If we advance the time by 24 hours, the counters reset. A small
        # target still reserves the full next day for new blocks, so historical
        # serving remains disabled while a recent block is served normally.
        self.nodes[0].setmocktime(int(time.time()))
        p2p_conns[2].sync_with_ping()
        getdata_request.inv = [CInv(MSG_BLOCK, big_new_block)]
        p2p_conns[2].send_and_ping(getdata_request)
        assert_equal(p2p_conns[2].block_receive_map[big_new_block], 1)
        self.assert_uploadtarget_state(target_reached=False, serve_historical_blocks=False)

        self.log.info("Peer 2 able to download recent block after counters reset")

        self.nodes[0].disconnect_p2ps()

        self.log.info("Restarting node 0 with download permission, bloom filter support and 1MB maxuploadtarget")
        self.restart_node(0, ["-whitelist=download@127.0.0.1", "-peerbloomfilters", "-maxuploadtarget=1"])
        # Total limit isn't reached after restart, but 1 MB is too small to serve historical blocks
        self.assert_uploadtarget_state(target_reached=False, serve_historical_blocks=False)

        # Reconnect to self.nodes[0]
        peer = self.nodes[0].add_p2p_connection(TestP2PConn(), supports_v2_p2p=False)

        # Sending mempool message shouldn't disconnect peer, as total limit isn't reached yet
        peer.send_and_ping(msg_mempool())

        #retrieve 20 blocks which should be enough to break the 1MB limit
        getdata_request.inv = [CInv(MSG_BLOCK, big_new_block)]
        for i in range(20):
            peer.send_and_ping(getdata_request)
            assert_equal(peer.block_receive_map[big_new_block], i+1)

        # Total limit is exceeded
        self.assert_uploadtarget_state(target_reached=True, serve_historical_blocks=False)

        getdata_request.inv = [CInv(MSG_BLOCK, big_old_block)]
        peer.send_and_ping(getdata_request)

        self.log.info("Peer still connected after trying to download old block (download permission)")
        peer_info = self.nodes[0].getpeerinfo()
        assert_equal(len(peer_info), 1)  # node is still connected
        assert_equal(peer_info[0]['permissions'], ['download'])

        self.log.info("Peer gets disconnected for a mempool request after limit is reached")
        with self.nodes[0].assert_debug_log(expected_msgs=["mempool request with bandwidth limit reached, disconnecting peer=0"]):
            peer.send_message(msg_mempool())
            peer.wait_for_disconnect()

        self.log.info("Test passing an unparsable value to -maxuploadtarget throws an error")
        self.stop_node(0)
        self.nodes[0].assert_start_raises_init_error(extra_args=["-maxuploadtarget=abc"], expected_msg="Error: Unable to parse -maxuploadtarget: 'abc'")

if __name__ == '__main__':
    MaxUploadTest(__file__).main()
