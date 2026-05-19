// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <netaddress.h>
#include <netbase.h>
#include <node/connection_types.h>
#include <protocol.h>
#include <semaphore_grant.h>
#include <sync.h>
#include <test/util/net.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>
#include <util/time.h>

#include <functional>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

class LogConnectsSock : public StaticContentsSock
{
public:
    std::function<void(const sockaddr*)> m_connect_cb;

    explicit LogConnectsSock(const std::string& contents, std::function<void(const sockaddr*)> connect_cb)
        : StaticContentsSock(contents),
          m_connect_cb(connect_cb)
    {
    }

    int Connect(const sockaddr* to, socklen_t) const override
    {
        m_connect_cb(to);
        return 0;
    }
};

/**
 * NetTestingSetup + create mocked sockets that log all targets to Connect() and mimic SOCKS5 handshake.
 */
struct LogConnectionsSetup : public NetTestingSetup {
    const std::string m_socks5_handshake{"\x05" // SOCKSVersion::SOCKS5
                                         "\x00" // SOCKS5Method::NOAUTH

                                         "\x05" // SOCKSVersion::SOCKS5
                                         "\x00" // SOCKS5Reply::SUCCEEDED
                                         "\x00" // reserved field
                                         "\x01" // SOCKS5Atyp::IPV4

                                         "\x00\x00\x00\x00\x00\x00", // 6 bytes, ignored
                                         12};

    Mutex m_connect_targets_mutex;
    //! Destinations given to all socket Connect() calls.
    std::vector<CService> m_connect_targets GUARDED_BY(m_connect_targets_mutex);

    explicit LogConnectionsSetup(ChainType chain_type = ChainType::REGTEST, const TestOpts& test_opts = {})
        : NetTestingSetup{chain_type, test_opts}
    {
        CreateSock = [&](int, int, int) {
            return std::make_unique<LogConnectsSock>(m_socks5_handshake, [this](const sockaddr* to) {
                assert(to->sa_family == AF_INET);
                LOCK(m_connect_targets_mutex);
                m_connect_targets.emplace_back(*reinterpret_cast<const sockaddr_in*>(to));
            });
        };
    }

    ~LogConnectionsSetup()
    {
        CreateSock = CreateSockOS;
    }
};

BOOST_FIXTURE_TEST_SUITE(net_retry_v1_tests, LogConnectionsSetup)

BOOST_FIXTURE_TEST_CASE(proxy_override, LogConnectionsSetup)
{
    const Proxy proxy{CService{in_addr{.s_addr = ntohl(0x02030405)}, 9050}}; // 2.3.4.5:9050
    m_node.connman->OpenNetworkConnection(
        /*addrConnect=*/CAddress{CService{in_addr{.s_addr = htonl(0x01020304)}, 8333}, // 1.2.3.4:8333
                                 ServiceFlags{NODE_NETWORK | NODE_P2P_V2}},
        /*fCountFailure=*/false,
        /*grant_outbound=*/CountingSemaphoreGrant<>{},
        /*pszDest=*/nullptr,
        /*conn_type=*/ConnectionType::OUTBOUND_FULL_RELAY,
        /*use_v2transport=*/true,
        /*proxy_override=*/proxy);

    int i{0};
    while (WITH_LOCK(m_connect_targets_mutex, return m_connect_targets.size() < 2)) {
        UninterruptibleSleep(100ms);
        if (++i > 100) {
            throw std::runtime_error{"Timeout waiting for connection attempts"};
        }
    }

    LOCK(m_connect_targets_mutex);
    BOOST_REQUIRE_EQUAL(m_connect_targets.size(), 2);
    BOOST_CHECK_EQUAL(m_connect_targets[0].ToStringAddrPort(), proxy.proxy.ToStringAddrPort());
    BOOST_CHECK_EQUAL(m_connect_targets[1].ToStringAddrPort(), proxy.proxy.ToStringAddrPort());
}

BOOST_AUTO_TEST_SUITE_END()
