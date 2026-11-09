// Copyright (c) 2026 The Ruble Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/miner.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <stdexcept>
#include <string>

using node::BlockAssembler;

namespace {
struct MainnetLaunchMinerTestingSetup : public TestingSetup {
    MainnetLaunchMinerTestingSetup() : TestingSetup{ChainType::MAIN} {}
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(launch_miner_tests, MainnetLaunchMinerTestingSetup)

BOOST_AUTO_TEST_CASE(mainnet_block_one_templates_are_locked)
{
    BlockAssembler::Options options;
    options.coinbase_output_script = CScript{} << OP_TRUE;
    options.use_mempool = false;

    const auto launch_rejected = [](const std::runtime_error& error) {
        const std::string message{error.what()};
        return message.find("launch-locked") != std::string::npos ||
            message.find("block 1 is fixed") != std::string::npos;
    };
    const auto create_template = [&] {
        return BlockAssembler{
            m_node.chainman->ActiveChainstate(), nullptr, options}
            .CreateNewBlock();
    };

    BOOST_CHECK_EXCEPTION(
        create_template(),
        std::runtime_error, launch_rejected);

    options.set_auxpow = true;
    BOOST_CHECK_EXCEPTION(
        create_template(),
        std::runtime_error, launch_rejected);
}

BOOST_AUTO_TEST_SUITE_END()
