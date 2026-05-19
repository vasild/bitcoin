#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Ensure that connection retries due to v2->v1 downgrade also use
the override proxy, if given.
"""

import threading

from test_framework.socks5 import (
    Socks5Configuration,
    Socks5Server,
)
from test_framework.test_framework import (
    BitcoinTestFramework,
)
from test_framework.util import (
    assert_equal,
    p2p_port,
)


class RetryV1OverrideProxy(BitcoinTestFramework):
    def set_test_params(self):
        self.disable_autoconnect = False
        self.num_nodes = 1

    def setup_nodes(self):
        self.destinations_mutex = threading.Lock()
        self.proxy_destinations = []
        self.proxy_override_destinations = []

        # Start two SOCKS5 proxy servers. Use ports that we know are reserved for us, but we do not use.

        def proxy_destinations_factory(requested_to_addr, requested_to_port):
            with self.destinations_mutex:
                self.proxy_destinations.append(f"{requested_to_addr}:{requested_to_port}")
            return None # Tells the Python SOCKS5 proxy to close the connection, getting bitcoind to retry v2->v1.

        proxy_config = Socks5Configuration()
        proxy_config.addr = ("127.0.0.1", p2p_port(self.num_nodes))
        proxy_config.unauth = True
        proxy_config.auth = True
        proxy_config.destinations_factory = proxy_destinations_factory
        self.proxy = Socks5Server(proxy_config)
        self.proxy.start()

        def proxy_override_destinations_factory(requested_to_addr, requested_to_port):
            with self.destinations_mutex:
                self.proxy_override_destinations.append(f"{requested_to_addr}:{requested_to_port}")
            return None # Tells the Python SOCKS5 proxy to close the connection, getting bitcoind to retry v2->v1.

        proxy_override_config = Socks5Configuration()
        proxy_override_config.addr = ("127.0.0.1", p2p_port(self.num_nodes + 1))
        proxy_override_config.unauth = True
        proxy_override_config.auth = True
        proxy_override_config.destinations_factory = proxy_override_destinations_factory
        self.proxy_override = Socks5Server(proxy_override_config)
        self.proxy_override.start()

        self.extra_args = [
            [
                "-connect=0",
                # Will not be used, but configure it so that even in case of regressions
                # the test would not try to open a real connection to the outside world.
                f"-proxy={self.proxy.conf.addr[0]}:{self.proxy.conf.addr[1]}",
                "-v2transport=1",
            ],
        ]
        super().setup_nodes()

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        connect_to = "1.2.3.4:1234"
        must_use_proxy = f"{self.proxy_override.conf.addr[0]}:{self.proxy_override.conf.addr[1]}"

        node = self.nodes[0]
        with node.busy_wait_for_debug_log([
            f"trying v2 connection (manual) to {connect_to}".encode(),
            f"Using proxy: {must_use_proxy} to connect to {connect_to}".encode(),
            f"retrying with v1 transport protocol for peer=0".encode(),
            f"trying v1 connection (manual) to {connect_to}".encode(),
            f"Using proxy: {must_use_proxy} to connect to {connect_to}".encode(),
            ]):
            node.addnode(connect_to, "onetry", v2transport=True, proxy_override=must_use_proxy)

        def got_the_connections():
            with self.destinations_mutex:
                return len(self.proxy_override_destinations) + len(self.proxy_destinations) >= 2

        self.wait_until(got_the_connections)

        with self.destinations_mutex:
            assert_equal(len(self.proxy_destinations), 0)
            assert_equal(len(self.proxy_override_destinations), 2)
            assert_equal(self.proxy_override_destinations[0], connect_to)
            assert_equal(self.proxy_override_destinations[1], connect_to)


if __name__ == "__main__":
    RetryV1OverrideProxy(__file__).main()
