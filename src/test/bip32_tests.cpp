// Copyright (c) 2013-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <clientversion.h>
#include <key.h>
#include <key_io.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <string>
#include <vector>

namespace {

struct TestDerivation {
    std::string pub;
    std::string prv;
    unsigned int nChild;
};

struct TestVector {
    std::string strHexMaster;
    std::vector<TestDerivation> vDerive;

    explicit TestVector(std::string strHexMasterIn) : strHexMaster(strHexMasterIn) {}

    TestVector& operator()(std::string pub, std::string prv, unsigned int nChild) {
        vDerive.emplace_back();
        TestDerivation &der = vDerive.back();
        der.pub = pub;
        der.prv = prv;
        der.nChild = nChild;
        return *this;
    }
};

TestVector test1 =
  TestVector("000102030405060708090a0b0c0d0e0f")
    ("rpub491n9MufwLLjA7NyRw9o3dcpoTGrh3F4uLJJtSnNABs6XJ4c5KiGfA5rRnPiSopJrxW4WaLTyg1FaZAVLUiwJfMkU5jKxkLiBk88tkVRWUN",
     "rprv7v2RjrNn6xnRwdJWKucngVg6FRSNHaXDY7Ni64NkbrL7eVjTXnQ27MmNaWkQvvQEwRc81dKKLNewn2yM3EtHgdMfgP16oDq7RdXPrTziZ96",
     0x80000000)
    ("rpub4BHC95D92bTiJiWgdh2Rvfiw8GqD57j5awjCrYAV8P4NtaMnVZFMnJSGD3xRC7iqsAndNostiK5LYx8dHWTKNYpUfiXat4EvhgFhCSpgduy",
     "rprv7xHqjZgFCDuR6ESDXfVRZXnCaEziff1EDioc49ksa3XQ1n2dx1w7EW7nMn6kLdnCeUVpNveBijVpVo14gqAUUhSBkFgF3BY18eAFHfMuL3Y",
     1)
    ("rpub4DTKLrm2RJLn9AZ8MwvJXQcbBepK59TNXGQ3SowJ51rb87rvDMffjsLVd8Qzc4SBptQgAEKzpuZp9FsSkqdD4CeQxvNSMhFCLQnUVPkNj9W",
     "rprv7zTxwME8avnUvgUfFvPJAGfrdcypfgjXA3USeRXgWgKcFKXmfpMRC521mqHowZZF6ZFWBkEcoSTEdjXHpAxTFrvdG2dy6wJroSUcpYcqYqf",
     0x80000002)
    ("rpub4G4bPPat8BCC1LMDcYKftQejQogqLh3Mrodih9ETEtE2Xy4327W6eJtRB9bq3vsWBQWQmcJcCr8nbb1jTwAk7eoFYpLaSeJt46hcaeHYcsY",
     "rprv835Eyt3zHodtnrGkWWnfXGhzrmrLwEKWVai7tkpqgYh3fAitUaBr6WZwKsWRuo4jc2GtnDBYDrH8rwG3QBseNxNHceCXFsYoQiDqTBKooXu",
     2)
    ("rpub4JHzDphqJesB5opwJoXkmup3VcyZyHMZJHX1x6kvZKndu4gQ5tCTqtMLrUbDTj2EeidaucnZFb2uA1MjZEbwqFGWTbtmGqCi4ncTjFGsdRd",
     "rprv85JdpKAwUHJssKkUCmzkQmsJwb95Zpdhw4bR9iMJzzFf2GMFYLtDJ62s1ButNTUAfpQbQ8R78fjJL8AVbcQzaLxL1tHcoxNWZggzxfdcsbh",
     1000000000)
    ("rpub4L1khWK5RnFNc9cPRM6V5cp3HrYsnnAb6XuaCP94mQB8cC5ncJT86zWQVJWAJz6x8Qv8QxiMnnjVkRkkf66ngWRdL9Jr5JnLskENyP1yH6t",
     "rprv872QHznBbQh5PfXvKKZUiUsJjpiPPKSjjJyyPzjTD4e9jPke4m8sZCBve3h6HNbFHDorBVQ3yiGRLJAs8gRihJbsMP3qvs8Dr2FMhmnUHWD",
     0);

TestVector test2 =
  TestVector("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542")
    ("rpub491n9MufwLLj9itJY6E5VqLb3eRHNfVtav63BPXC8ZyxpH5oFUVD64FSmtUhA4BGmWjrREzdNkWWJLtiTfe6SaMhL1vnoEqNW7oFAjWQ7cE",
     "rprv7v2RjrNn6xnRwEoqS4h58hPrVcanyCn3DhASP17aaESywUkehwAxYFvxvaXU7RxLBUMYkummcUh8sZhT5fGzHzgS8o5LwZjqzt9dDQyEeHS",
     0)
    ("rpub4CHXR5bdRMAofzUbfsbxZdk7QcAY5dzB95qQMCYeCyqvWFXmpjqHEtphMMSax9BhyqE2HTzNmqMUTWKQLpLWnB1yc4fThaykdbuubxpvUg1",
     "rprv7yJB1a4jaycWTWQ8Zr4xCVoNraL3gBGKmruoYp92eeJwdTCdHCX2h6WDW5oGkVoAb8bNevBW3e7GE5LGdwn3EDqq8yVQL3ub8J4BajxkBP3",
     0xFFFFFFFF)
    ("rpub4DSafgd9oFLuqrgn6Kbc2yRfoMPSd89sEEuwGbTQricJxYmESdFbSxcHxjghhsnomM9ZwJqz53n58BBk7ipdWKUc99HX4KEmVzBWSgHFJnf",
     "rprv7zTEGB6FxsncdNcJzJ4bfqUwFKYxDfS1s1zLUD3oJP5L5kS5u5wLuAHp7SHFUkXeVMvGRwP96ecNfK53NKPAoXHPZhik6Zdqv5PiMBF1btP",
     1)
    ("rpub4GFZ5hc5xte6wUMv9ykAzvMu8tFwjK58YgQo7f7kAbxkdNdPk8nJLrzfoXsqVkV6MXc7mwwDiB5uCySm2dFamewWjRVNGrfyRkrThBqEbn3",
     "rprv83GCgC5C8X5oizHT3xDAdnRAarRTKrMHBTVCKGi8cGRmkaJFCbU3o4gBxEUsWTjLoKGyBETXWCHaz1rCRCuYp16ghUFYwfcEPspSpkVq5TQ",
     0xFFFFFFFE)
    ("rpub4HRazfYSaHbpERbWtTZiNS463cjJnHhdaP8geNpA1NE15ixKqoiJsPMmSC1Lh81YJyFkaSzvknQkrcc9iWN6V1dy1Korq9mPHyw3EAgWkcE",
     "rprv84SEbA1Yjv3X1wX3nS2i1J7MVatpNpynDAD5qzQYT2h2CvdBJGQ4Kb3HawDG8t7dLtZfV4EWtZsAo8wZw9p3VqmrXQns5sdrjTpxtcetqUb",
     2)
    ("rpub4Jncx6kx6Tv3ygnQcXhQMBS4SgGR2cciEYka4AAeeA5b9vHu1Se53xJmWb5cphNEq2TyrNWLeVRkM3feYc3zoGVYeVdwmX47yH8DtmX82EW",
     "rprv85oGYbE4G6MkmChwWWAPz3VKteRvd9trsKpyFmm35pYcH7xkTuKpW9zHfLtGHuChPCRPmosLLfhrqgq5fUBGYpWaLGJN9HmaRqAWy8cD1ap",
     0);

TestVector test3 =
  TestVector("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be")
    ("rpub491n9MufwLLj8nLU4UishpbcvHkP8XfAJFrbagYkQG4knXK4ucjB3KUyFt1fyekuwbViFEsdmRLMjeXdJNgXrv1qTFq1XoHDHqJwhCnZiuq",
     "rprv7v2RjrNn6xnRvJFzxTBsLgetNFutj4wJw2vznJ98qvXmuiyvN5QvVXAVQaFe4TBfGB2JKqTsWuRrEDJmK6RR5UBgf5dz915pHboysNcGPRN",
      0x80000000)
    ("rpub4BNytKjochi5LKRsHd4Nm5MHceMmHP54hk6YPvEbLZz83YSXV7W37nGgZbrBi1Mf8xzZ2CdNcNXrN7TyEcciSAHn8Mmu5en1n1frMadE6dw",
     "rprv7xPdUpCunL9n7qMQBbXNPwQZ4cXGsvMDLXAwbXpynET9Ak7NwaBnZyxCiLbzQQWaiKfiLnFkAe4JskwutK1AqEPK6DZ2tAMdQcmdpmfr4KC",
      0);

TestVector test4 =
  TestVector("3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678")
    ("rpub491n9MufwLLjAqr2uD5gWa4WYXLZ3n4uYPYzxRELGnuSdR8Q7XKwFY34x1GM16LyX8dGPv6piC76YXJkiahSwmskDg8667F2CRzAn46imvP",
     "rprv7v2RjrNn6xnRxMmZoBYg9S7mzVW4eKM4BAdQA2piiTNTkcoFZz1ghjib6jXm5BaqqdyvS2M1TEdcsDw3yBgLAHr5AKW2BsyUZjg8dTgrXmN",
     0x80000000)
    ("rpub4CAtXk2LK6TAoisAXY1TWyAGzTDpm5bTHhAfJPQJvEyR7xBWfrkfPaiR7bY72ii6wEPdLxVSK83M5SzpRN9r35vnFzZ3xvLQFEYDaUD2p56",
     "rprv7yBY8EVSUitsbEnhRWUT9qDYSRPLMcsbvUF4VzzhMuSSF9rN8KSQqnPwGHT17zmCod1MxbXEmgjhot89aZLyAvj11hohPoRUYzhwNMdqZwN",
     0x80000001)
    ("rpub4EJaBjRLppVmUsiofovMcqk8APPuG1JFwdDV58vWaS4ru3W2YMENchgJ1YJdsuLnX1zzEjRYmaPL3wKisxxzkNs9bnQ6vepM7eu7e3nb1WY",
     "rprv81KDnDtSzSwUGPeLZnPMFhoPcMZQrYaQaQHtGkWu26Xt2FAszov84uMpAFR6BPo2tPQU9CMCYKqaWqwryVJ6TKCEG3WiVqfoQgFdTxVAGFj",
     0);

const std::vector<std::string> TEST5 = {
    "rpub491n9MufwLLj8mHRvxobBy5DqNfHTS3TVbsySYqKg8JWQBo8pgNgGJwdy6SJBgA4bNL97HJKAbLmiHUndT5VsptWZkodgR59JyADKxWP3am",
    "rprv7v2RjrNn6xnRvHCxpwGapq8VHLpo3yKc8NxNeARi7nmXXPTzH94RiWdA82htQm86kDaBiDgpy9oDcijCG1RzqYcYUYVCbuL8CRosZbkmE4w",
    "rpub491n9MufwLLj8mHRvxobBy5DqNfHTS3TVbsySYqKg8JWQBo8pgNgGJwdyEDGtbxC1533eZd8nupmXZstHuYNUeG1iK64f1pjHbBmJXbyVdy",
    "rprv7v2RjrNn6xnRvHCxpwGapq8VHLpo3yKc8NxNeARi7nmXXPTzH94RiWdA834zoRobbLb3k7WD8A5Jv8L6QF3pinfrCJmgoh1gMjJXYRK8w63",
    "rpub491n9MufwLLj8mHRvxobBy5DqNfHTS3TVbsySYqKg8JWQBo8pgNgGJwdy8P3Muc6So1NF6t25Axmfc5ZYZhDXXjPMPsjvZm3JdAbpaYSKVD",
    "rprv7v2RjrNn6xnRvHCxpwGapq8VHLpo3yKc8NxNeARi7nmXXPTzH94RiWdA7wEmGjTW34ZNLem6QRDK4AXmeuCfmg9DqPZN5EwzNmHN4b3mDXz",
    "rprv7v2rZarsW4EizVJtVCXe1GYiqmhHoG3kcf1TLYU1FGPViibQQTP6AxkDYToqCMLWpDrfWWTPow9w5pPfXb7VCnCGVmEEsC9MHsxhLKsEthd",
    "rpub492Cy6PmLRo2CyPMbE4eNQVTPoXnCimbysw48vscobvUbWvYwzhLim4hPnMybnbjnXzhvM5kx17JD8jewUT5gD6dSZYZVL2S34Nq65EW1KD",
    "rprv7v2RjrNnAkoamwCDyBp66cp6iCSMapkAX5ctQbYXd8pRiYH6cNFgJCfPr6JKsmfwhY4jHEnWWUMFFXCXVTugxamZqc4mw1KmQvX92cZASML",
    "rpub491n9Mug18MszRGh5DM6TkkqGEGqzHU1tJYVCyx9BUMQbLcF9uZvqzyshQrUHCwAfrCmh5QseYJcNqYWuMFHS1fvnQP6Z9CrA6wGnMiLrcY",
    "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHGMQzT7ayAmfo4z3gY5KfbrZWZ6St24UVf2Qgo6oujFktLHdHY4",
    "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHPmHJiEDXkTiJTVV9rHEBUem2mwVbbNfvT2MTcAqj3nesx8uBf9",
    "rprv7v2RjrNn6xnRvHCxpwGapq8VHLpo3yKc8NxNeARi7nmXXPTzH94RiWdA7uJ26W1UBdt9CqBPVqbK6qvzjnax7yJM3kVFq6G6P7GyYaU45TJ",
    "rprv7v2RjrNn6xnRvHCxpwGapq8VHLpo3yKc8NxNeARi7nmXXPTzH94RiWdA7wEmGjTW34ZNLem6QRDK4AXh82qmEetSNgJNpPEfgUFzGtwJuYM",
    "rpub491n9MufwLLj8mHRvxobBy5DqNfHTS3TVbsySYqKg8JWQBo8pgNgGJwdyAKnY948JDgbNvTiykamcvgLTgJwBEaG92wrAiSwJHAzJgpEm3m",
    "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHL"
};

void RunTest(const TestVector& test)
{
    std::vector<std::byte> seed{ParseHex<std::byte>(test.strHexMaster)};
    CExtKey key;
    CExtPubKey pubkey;
    key.SetSeed(seed);
    pubkey = key.Neuter();
    for (const TestDerivation &derive : test.vDerive) {
        unsigned char data[74];
        key.Encode(data);
        pubkey.Encode(data);

        // Test private key
        BOOST_CHECK(EncodeExtKey(key) == derive.prv);
        BOOST_CHECK(DecodeExtKey(derive.prv) == key); //ensure a base58 decoded key also matches

        // Test public key
        BOOST_CHECK(EncodeExtPubKey(pubkey) == derive.pub);
        BOOST_CHECK(DecodeExtPubKey(derive.pub) == pubkey); //ensure a base58 decoded pubkey also matches

        // Derive new keys
        CExtKey keyNew;
        BOOST_CHECK(key.Derive(keyNew, derive.nChild));
        CExtPubKey pubkeyNew = keyNew.Neuter();
        if (!(derive.nChild & 0x80000000)) {
            // Compare with public derivation
            CExtPubKey pubkeyNew2;
            BOOST_CHECK(pubkey.Derive(pubkeyNew2, derive.nChild));
            BOOST_CHECK(pubkeyNew == pubkeyNew2);
        }
        key = keyNew;
        pubkey = pubkeyNew;
    }
}

}  // namespace

BOOST_FIXTURE_TEST_SUITE(bip32_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bip32_test1) {
    RunTest(test1);
}

BOOST_AUTO_TEST_CASE(bip32_test2) {
    RunTest(test2);
}

BOOST_AUTO_TEST_CASE(bip32_test3) {
    RunTest(test3);
}

BOOST_AUTO_TEST_CASE(bip32_test4) {
    RunTest(test4);
}

BOOST_AUTO_TEST_CASE(bip32_test5) {
    for (const auto& str : TEST5) {
        auto dec_extkey = DecodeExtKey(str);
        auto dec_extpubkey = DecodeExtPubKey(str);
        BOOST_CHECK_MESSAGE(!dec_extkey.key.IsValid(), "Decoding '" + str + "' as xprv should fail");
        BOOST_CHECK_MESSAGE(!dec_extpubkey.pubkey.IsValid(), "Decoding '" + str + "' as xpub should fail");
    }
}

BOOST_AUTO_TEST_CASE(bip32_max_depth) {
    CExtKey key_parent{DecodeExtKey(test1.vDerive[0].prv)}, key_child;
    CExtPubKey pubkey_parent{DecodeExtPubKey(test1.vDerive[0].pub)}, pubkey_child;

    // We can derive up to the 255th depth..
    for (auto i = 0; i++ < 255;) {
        BOOST_CHECK(key_parent.Derive(key_child, 0));
        std::swap(key_parent, key_child);
        BOOST_CHECK(pubkey_parent.Derive(pubkey_child, 0));
        std::swap(pubkey_parent, pubkey_child);
    }

    // But trying to derive a non-existent 256th depth will fail!
    BOOST_CHECK(key_parent.nDepth == 255 && pubkey_parent.nDepth == 255);
    BOOST_CHECK(!key_parent.Derive(key_child, 0));
    BOOST_CHECK(!pubkey_parent.Derive(pubkey_child, 0));
}

BOOST_AUTO_TEST_SUITE_END()
