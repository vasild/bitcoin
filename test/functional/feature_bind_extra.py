#!/usr/bin/env python3
# Copyright (c) 2014-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test starting bitcoind with -bind and/or -bind=...=onion and confirm
that bind happens on the expected ports.
"""

import sys

from test_framework.netutil import (
    addr_to_hex,
    get_bind_addrs,
)
from test_framework.test_framework import (
    BitcoinTestFramework,
    SkipTest,
)
from test_framework.util import (
    PORT_MIN,
    PORT_RANGE,
    assert_equal,
    p2p_port,
    rpc_port,
)

# From chainparamsbase.cpp:CreateBaseChainParams().
REGTEST_TOR_TARGET_PORT = 18445

class BindExtraTest(BitcoinTestFramework):
    def set_test_params(self):
        # Avoid any -bind= on the command line. Force the framework to avoid
        # adding -bind=127.0.0.1.
        self.setup_clean_chain = True
        self.bind_to_localhost_only = False
        self.num_nodes = 4

    def setup_network(self):
        # Override setup_network() because we want to put the result of
        # p2p_port() in self.extra_args[], before the nodes are started.
        # p2p_port() is not usable in set_test_params() because PortSeed.n is
        # not set at that time.

        # Due to OS-specific network stats queries, we only run on Linux.
        self.log.info("Checking for Linux")
        if not sys.platform.startswith('linux'):
            raise SkipTest("This test can only be run on Linux.")

        any_ipv4 = addr_to_hex('0.0.0.0')
        loopback_ipv4 = addr_to_hex('127.0.0.1')

        # Start custom ports after p2p and rpc ports.
        port = PORT_MIN + 2 * PORT_RANGE

        # Array of tuples [command line arguments, expected bind addresses].
        self.expected = []

        # Node0, no -bind, expected to bind on any + tor target.
        self.expected.append(
            [
                [],
                [(any_ipv4, p2p_port(0)), (loopback_ipv4, REGTEST_TOR_TARGET_PORT)]
            ]
        )

        # Node1, -bind=... without -bind=...=onion, the -bind= target + tor target.
        self.expected.append(
            [
                ['-bind=127.0.0.1:{}'.format(port)],
                [(loopback_ipv4, port), (loopback_ipv4, REGTEST_TOR_TARGET_PORT)]
            ],
        )
        port += 1

        # Node2, no normal -bind, thus only the Tor target.
        self.expected.append(
            [
                ['-bind=127.0.0.1:{}=onion'.format(port)],
                [(loopback_ipv4, port)]
            ],
        )
        port += 1

        # Node3, both -bind and -bind=...=onion.
        self.expected.append(
            [
                ['-bind=127.0.0.1:{}'.format(port), '-bind=127.0.0.1:{}=onion'.format(port + 1)],
                [(loopback_ipv4, port), (loopback_ipv4, port + 1)]
            ],
        )
        port += 2

        # Add RPC ports to the list of expected ports to bind to for all nodes.
        # They are not relevant for this test.
        for i in range(len(self.expected)):
            self.expected[i][1].append((loopback_ipv4, rpc_port(i)))

        self.extra_args = list(map(lambda e: e[0], self.expected))
        self.add_nodes(self.num_nodes, self.extra_args)
        # Don't start the nodes, as some of them would collide trying to bind on the same port.

    def run_test(self):
        for i in range(len(self.expected)):
            self.start_node(i)
            pid = self.nodes[i].process.pid
            actual = set(get_bind_addrs(pid))
            # Remove IPv6 addresses because on some CI environments "::1" is not configured
            # on the system (so our test_ipv6_local() would return False), but it is
            # possible to bind on "::". This makes it unpredictable whether to expect
            # that bitcoind has bound on "::1" (for RPC) and "::" (for P2P).
            actual_without_ipv6 = set(filter(lambda e: len(e[0]) != 32, actual))
            assert_equal(actual_without_ipv6, set(self.expected[i][1]))
            self.stop_node(i)

if __name__ == '__main__':
    BindExtraTest().main()
