#!/usr/bin/env python3
# Copyright (c) 2023 The Bitcoin Core developers
# Copyright (c) 2026 The Ruble Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Test validateaddress against Ruble mainnet encodings."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


VALID_DATA = [
    (
        "RQ9do639WtBDJxHVVSuex3SYkE1USTGjpA",
        {
            "scriptPubKey": "76a914a31c06bd463e3923bc1aadbde48b16976c08071788ac",
            "isscript": False,
            "iswitness": False,
        },
    ),
    (
        "rBGdaNCdAGySFrtubbpczmCx5S889GppYG",
        {
            "scriptPubKey": "a914373b819a068f32b7a6b38b6b38729647cfde01c287",
            "isscript": True,
            "iswitness": False,
        },
    ),
    (
        "rub1qvyq0cc6rahyvsazfdje0twl7ez82ndmud6ml3g",
        {
            "scriptPubKey": "00146100fc6343edc8c874496cb2f5bbfec88ea9b77c",
            "isscript": False,
            "iswitness": True,
            "witness_version": 0,
            "witness_program": "6100fc6343edc8c874496cb2f5bbfec88ea9b77c",
        },
    ),
    (
        "RUB1QVYQ0CC6RAHYVSAZFDJE0TWL7EZ82NDMUD6ML3G",
        {
            "address": "rub1qvyq0cc6rahyvsazfdje0twl7ez82ndmud6ml3g",
            "scriptPubKey": "00146100fc6343edc8c874496cb2f5bbfec88ea9b77c",
            "isscript": False,
            "iswitness": True,
            "witness_version": 0,
            "witness_program": "6100fc6343edc8c874496cb2f5bbfec88ea9b77c",
        },
    ),
    (
        "rub1qyucykdlhp62tezs0hagqury402qwhk589q80tqs5myh3rxq34nwq98p56m",
        {
            "scriptPubKey": "002027304b37f70e94bc8a0fbf500e0c957a80ebda87280ef58214d92f119811acdc",
            "isscript": True,
            "iswitness": True,
            "witness_version": 0,
            "witness_program": "27304b37f70e94bc8a0fbf500e0c957a80ebda87280ef58214d92f119811acdc",
        },
    ),
    (
        "rub1p83n3au0rjylefxq2nc2xh2y4jzz4pm6zxj4mw5pagdjjr2a9f36sgr7s9e",
        {
            "scriptPubKey": "51203c671ef1e3913f94980a9e146ba895908550ef4234abb7503d436521aba54c75",
            "isscript": True,
            "iswitness": True,
            "witness_version": 1,
            "witness_program": "3c671ef1e3913f94980a9e146ba895908550ef4234abb7503d436521aba54c75",
        },
    ),
    (
        "rub1z2rks57q0tq",
        {
            "scriptPubKey": "520250ed",
            "iswitness": True,
            "witness_version": 2,
            "witness_program": "50ed",
        },
    ),
]

INVALID_DATA = [
    (
        "rub10uexgzna2dpfk0vjt35srz6a27ps6m0l89jweznt83n2sqn2fx4hvn9ym5af8wut34sajvd2h",
        "Invalid Bech32 address program size (41 bytes)",
    ),
    (
        "rub1qdsuzmn04k2z8vryw8l4dj8m5ygq4df44g",
        "Invalid padding in Bech32 data section",
    ),
    (
        "rub1qpu6d26mrulzetu4jqhd7rsunv9aqru26ekf45r",
        "Version 0 witness address must use Bech32 checksum",
    ),
    (
        "rub1p702xksx4z3uqf0u2phllxkfe5cgu0adxptqs0uelx0tqt8e885sq344nu6",
        "Version 1+ witness address must use Bech32m checksum",
    ),
    ("rub1n0c4ph", "Empty Bech32 data section"),
    (
        "RQ9do639WtBDJxHVVSuex3SYkE1USTGjpB",
        "Invalid checksum or length of Base58 address (P2PKH or P2SH)",
    ),
]


class ValidateAddressMainTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.chain = ""  # main
        self.num_nodes = 1
        self.extra_args = [["-prune=899"]]

    def check_valid(self, input_address, expected):
        info = self.nodes[0].validateaddress(input_address)
        assert_equal(info["isvalid"], True)
        assert_equal(info["address"], expected.get("address", input_address))
        for key, value in expected.items():
            if key != "address":
                assert_equal(info[key], value)
        assert "error" not in info
        assert "error_locations" not in info

    def check_invalid(self, address, error):
        info = self.nodes[0].validateaddress(address)
        assert_equal(info["isvalid"], False)
        assert_equal(info["error"], error)
        assert_equal(info["error_locations"], [])
        for key in ("address", "scriptPubKey", "isscript", "iswitness"):
            assert key not in info

    def run_test(self):
        for address, expected in VALID_DATA:
            self.check_valid(address, expected)
        for address, error in INVALID_DATA:
            self.check_invalid(address, error)


if __name__ == "__main__":
    ValidateAddressMainTest(__file__).main()
