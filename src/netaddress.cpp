// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <netaddress.h>
#include <hash.h>
#include <util/strencodings.h>
#include <util/asmap.h>
#include <tinyformat.h>

constexpr size_t CNetAddr::V1_SERIALIZATION_SIZE;
constexpr size_t CNetAddr::MAX_ADDRv2_SIZE;

CNetAddr::Bip155NetworkId CNetAddr::ToBIP155NetworkId() const
{
    switch (m_net) {
    case NET_IPV4: return Bip155NetworkId::IPv4;
    case NET_IPV6: return Bip155NetworkId::IPv6;
    case NET_ONION:
        switch (m_addr.size()) {
        case ADDR_TORv2_SIZE: return Bip155NetworkId::TORv2;
        default: assert(!"Unexpected TOR address size");
        }
    case NET_UNROUTABLE:
    case NET_INTERNAL:
    case NET_MAX:
        assert(!"NET_UNROUTABLE, NET_INTERNAL and NET_MAX cannot be represented as "
                "BIP155 network id");
    }

    assert(!"Unexpected BIP155 network id");
    return (Bip155NetworkId)0;
}

bool CNetAddr::FromBIP155NetworkId(Bip155NetworkId bip155_network_id,
    unsigned int address_size,
    Network& net) const
{
    switch (bip155_network_id) {
    case Bip155NetworkId::IPv4:
        if (address_size == ADDR_IPv4_SIZE) {
           net = NET_IPV4;
           return true;
        }
        return false;
    case Bip155NetworkId::IPv6:
        if (address_size == ADDR_IPv6_SIZE) {
           net = NET_IPV6;
           return true;
        }
        return false;
    case Bip155NetworkId::TORv2:
        if (address_size == ADDR_TORv2_SIZE) {
           net = NET_ONION;
           return true;
        }
        return false;
    case Bip155NetworkId::TORv3:
    case Bip155NetworkId::I2P:
    case Bip155NetworkId::CJDNS:
        return false;
    }

    return false;
}

/**
 * Construct an unspecified IPv6 network address (::/128).
 *
 * @note This address is considered invalid by CNetAddr::IsValid()
 */
CNetAddr::CNetAddr() : m_net(NET_IPV6), m_addr(ADDR_IPv6_SIZE, 0x0) {}

void CNetAddr::SetIP(const CNetAddr& ipIn)
{
    m_net = ipIn.m_net;
    m_addr = ipIn.m_addr;
}

void CNetAddr::SetRaw(Network network, const uint8_t *ip_in)
{
    switch (network) {
    case NET_IPV4:
        m_net = NET_IPV4;
        m_addr.assign(ip_in, ip_in + ADDR_IPv4_SIZE);
        break;
    case NET_IPV6:
        m_net = NET_IPV6;
        m_addr.assign(ip_in, ip_in + ADDR_IPv6_SIZE);
        break;
    case NET_UNROUTABLE:
    case NET_ONION:
    case NET_INTERNAL:
    case NET_MAX: assert(!"invalid network");
    }
}

/**
 * Try to make this a dummy address that maps the specified name into IPv6 like
 * so: (0xFD + %sha256("bitcoin")[0:5]) + %sha256(name)[0:10]. Such dummy
 * addresses have a prefix of fd6b:88c0:8724::/48 and are guaranteed to not be
 * publicly routable as it falls under RFC4193's fc00::/7 subnet allocated to
 * unique-local addresses.
 *
 * CAddrMan uses these fake addresses to keep track of which DNS seeds were
 * used.
 *
 * @returns Whether or not the operation was successful.
 *
 * @see CNetAddr::IsInternal(), CNetAddr::IsRFC4193()
 */
bool CNetAddr::SetInternal(const std::string &name)
{
    if (name.empty()) {
        return false;
    }
    m_net = NET_INTERNAL;
    unsigned char hash[32] = {};
    CSHA256().Write((const unsigned char*)name.data(), name.size()).Finalize(hash);
    m_addr.assign(hash, hash + ADDR_INTERNAL_SIZE);
    return true;
}

/**
 * Try to make this a dummy address that maps the specified onion address into
 * IPv6 using OnionCat's range and encoding. Such dummy addresses have a prefix
 * of fd87:d87e:eb43::/48 and are guaranteed to not be publicly routable as they
 * fall under RFC4193's fc00::/7 subnet allocated to unique-local addresses.
 *
 * @returns Whether or not the operation was successful.
 *
 * @see CNetAddr::IsTor(), CNetAddr::IsRFC4193()
 */
bool CNetAddr::SetSpecial(const std::string &strName)
{
    if (strName.size()>6 && strName.substr(strName.size() - 6, 6) == ".onion") {
        std::vector<unsigned char> vchAddr = DecodeBase32(strName.substr(0, strName.size() - 6).c_str());
        if (vchAddr.size() != ADDR_TORv2_SIZE)
            return false;
        m_net = NET_ONION;
        m_addr = vchAddr;
        return true;
    }
    return false;
}

CNetAddr::CNetAddr(const struct in_addr& ipv4Addr)
{
    SetRaw(NET_IPV4, (const uint8_t*)&ipv4Addr);
}

CNetAddr::CNetAddr(const struct in6_addr& ipv6Addr, const uint32_t scope)
{
    assert(sizeof(ipv6Addr) == V1_SERIALIZATION_SIZE);
    uint8_t serialized[V1_SERIALIZATION_SIZE];
    memcpy(serialized, &ipv6Addr, sizeof(ipv6Addr));
    UnserializeV1Array(serialized);
    scopeId = scope;
}

bool CNetAddr::IsBindAny() const
{
    if (!IsIPv4() && !IsIPv6()) {
        return false;
    }
    for (uint8_t b : m_addr) {
        if (b != 0) {
            return false;
        }
    }

    return true;
}

bool CNetAddr::IsIPv4() const
{
    if (m_net == NET_IPV4) {
        assert(m_addr.size() == ADDR_IPv4_SIZE);
        return true;
    }
    return false;
}

bool CNetAddr::IsIPv6() const
{
    if (m_net == NET_IPV6) {
        assert(m_addr.size() == ADDR_IPv6_SIZE);
        return true;
    }
    return false;
}

bool CNetAddr::IsRFC1918() const
{
    return IsIPv4() && (
        m_addr[0] == 10 ||
        (m_addr[0] == 192 && m_addr[1] == 168) ||
        (m_addr[0] == 172 && m_addr[1] >= 16 && m_addr[1] <= 31));
}

bool CNetAddr::IsRFC2544() const
{
    return IsIPv4() &&
        m_addr[0] == 198 &&
        (m_addr[1] == 18 ||
         m_addr[1] == 19);
}

bool CNetAddr::IsRFC3927() const
{
    return IsIPv4() &&
        m_addr[0] == 169 &&
        m_addr[1] == 254;
}

bool CNetAddr::IsRFC6598() const
{
    return IsIPv4() &&
        m_addr[0] == 100 &&
        m_addr[1] >= 64 &&
        m_addr[1] <= 127;
}

bool CNetAddr::IsRFC5737() const
{
    return IsIPv4() &&
        ((m_addr[0] == 192 &&
          m_addr[1] == 0 &&
          m_addr[2] == 2) ||

         (m_addr[0] == 198 &&
          m_addr[1] == 51 &&
          m_addr[2] == 100) ||

         (m_addr[0] == 203 &&
          m_addr[1] == 0 &&
          m_addr[2] == 113));
}

bool CNetAddr::IsRFC3849() const
{
    return IsIPv6() &&
        m_addr[0] == 0x20 &&
        m_addr[1] == 0x01 &&
        m_addr[2] == 0x0D &&
        m_addr[3] == 0xB8;
}

bool CNetAddr::IsRFC3964() const
{
    return IsIPv6() &&
        m_addr[0] == 0x20 &&
        m_addr[1] == 0x02;
}

bool CNetAddr::IsRFC6052() const
{
    static const unsigned char pchRFC6052[] = {0,0x64,0xFF,0x9B,0,0,0,0,0,0,0,0};
    return IsIPv6() && memcmp(m_addr.data(), pchRFC6052, sizeof(pchRFC6052)) == 0;
}

bool CNetAddr::IsRFC4380() const
{
    return IsIPv6() &&
        m_addr[0] == 0x20 &&
        m_addr[1] == 0x01 &&
        m_addr[2] == 0x00 &&
        m_addr[3] == 0x00;
}

bool CNetAddr::IsRFC4862() const
{
    static const unsigned char pchRFC4862[] = {0xFE,0x80,0,0,0,0,0,0};
    return IsIPv6() && memcmp(m_addr.data(), pchRFC4862, sizeof(pchRFC4862)) == 0;
}

bool CNetAddr::IsRFC4193() const
{
    return IsIPv6() && (m_addr[0] & 0xFE) == 0xFC;
}

bool CNetAddr::IsRFC6145() const
{
    static const unsigned char pchRFC6145[] = {0,0,0,0,0,0,0,0,0xFF,0xFF,0,0};
    return IsIPv6() && memcmp(m_addr.data(), pchRFC6145, sizeof(pchRFC6145)) == 0;
}

bool CNetAddr::IsRFC4843() const
{
    return IsIPv6() &&
        m_addr[0] == 0x20 &&
        m_addr[1] == 0x01 &&
        m_addr[2] == 0x00 &&
        (m_addr[3] & 0xF0) == 0x10;
}

bool CNetAddr::IsRFC7343() const
{
    return IsIPv6() &&
        m_addr[0] == 0x20 &&
        m_addr[1] == 0x01 &&
        m_addr[2] == 0x00 &&
        (m_addr[3] & 0xF0) == 0x20;
}

bool CNetAddr::IsHeNet() const
{
    return IsIPv6() &&
        m_addr[0] == 0x20 &&
        m_addr[1] == 0x01 &&
        m_addr[2] == 0x04 &&
        m_addr[3] == 0x70;
}

/**
 * @returns Whether or not this is a dummy address that maps an onion address
 *          into IPv6.
 *
 * @see CNetAddr::SetSpecial(const std::string &)
 */
bool CNetAddr::IsTor() const { return m_net == NET_ONION; }

bool CNetAddr::IsLocal() const
{
    // IPv4 loopback (127.0.0.0/8 or 0.0.0.0/8)
    if (IsIPv4() && (m_addr[0] == 127 || m_addr[0] == 0))
        return true;

    // IPv6 loopback (::1/128)
    static const unsigned char pchLocal[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    if (IsIPv6() && memcmp(m_addr.data(), pchLocal, sizeof(pchLocal)) == 0)
        return true;

    return false;
}

/**
 * @returns Whether or not this network address is a valid address that @a could
 *          be used to refer to an actual host.
 *
 * @note A valid address may or may not be publicly routable on the global
 *       internet. As in, the set of valid addresses is a superset of the set of
 *       publicly routable addresses.
 *
 * @see CNetAddr::IsRoutable()
 */
bool CNetAddr::IsValid() const
{
    // Cleanup 3-byte shifted addresses caused by garbage in size field
    // of addr messages from versions before 0.2.9 checksum.
    // Two consecutive addr messages look like this:
    // header20 vectorlen3 addr26 addr26 addr26 header20 vectorlen3 addr26 addr26 addr26...
    // so if the first length field is garbled, it reads the second batch
    // of addr misaligned by 3 bytes.
    if (IsIPv6() && memcmp(m_addr.data(), IPv4_IN_IPv6_PREFIX + 3,
                        sizeof(IPv4_IN_IPv6_PREFIX) - 3) == 0)
        return false;

    // unspecified IPv6 address (::/128)
    unsigned char ipNone6[16] = {};
    if (IsIPv6() && memcmp(m_addr.data(), ipNone6, sizeof(ipNone6)) == 0)
        return false;

    // documentation IPv6 address
    if (IsRFC3849())
        return false;

    if (IsInternal())
        return false;

    if (IsIPv4())
    {
        for (uint32_t a : {(uint32_t)INADDR_ANY, (uint32_t)INADDR_NONE}) {
            if (memcmp(m_addr.data(), &a, sizeof(a)) == 0) {
                return false;
            }
        }
    }

    return true;
}

/**
 * @returns Whether or not this network address is publicly routable on the
 *          global internet.
 *
 * @note A routable address is always valid. As in, the set of routable addresses
 *       is a subset of the set of valid addresses.
 *
 * @see CNetAddr::IsValid()
 */
bool CNetAddr::IsRoutable() const
{
    return IsValid() && !(IsRFC1918() || IsRFC2544() || IsRFC3927() || IsRFC4862() || IsRFC6598() || IsRFC5737() || (IsRFC4193() && !IsTor()) || IsRFC4843() || IsRFC7343() || IsLocal() || IsInternal());
}

/**
 * @returns Whether or not this is a dummy address that represents a name.
 *
 * @see CNetAddr::SetInternal(const std::string &)
 */
bool CNetAddr::IsInternal() const
{
   return m_net == NET_INTERNAL;
}

bool CNetAddr::IsAddrV1Compatible() const
{
    switch (m_net) {
    case NET_IPV4:
    case NET_IPV6:
    case NET_INTERNAL:
        return true;
    case NET_ONION:
        return m_addr.size() == ADDR_TORv2_SIZE;
    case NET_UNROUTABLE:
    case NET_MAX:
        return false;
    }

    return false;
}

enum Network CNetAddr::GetNetwork() const
{
    if (IsInternal())
        return NET_INTERNAL;

    if (!IsRoutable())
        return NET_UNROUTABLE;

    return m_net;
}

std::string CNetAddr::ToStringIP() const
{
    if (IsTor())
        return EncodeBase32(m_addr.data(), m_addr.size()) + ".onion";
    if (IsInternal())
        return EncodeBase32(m_addr.data(), m_addr.size()) + ".internal";
    CService serv(*this, 0);
    struct sockaddr_storage sockaddr;
    socklen_t socklen = sizeof(sockaddr);
    if (serv.GetSockAddr((struct sockaddr*)&sockaddr, &socklen)) {
        char name[1025] = "";
        if (!getnameinfo((const struct sockaddr*)&sockaddr, socklen, name, sizeof(name), nullptr, 0, NI_NUMERICHOST))
            return std::string(name);
    }
    if (IsIPv4())
        return strprintf("%u.%u.%u.%u", m_addr[0], m_addr[1], m_addr[2], m_addr[3]);
    assert(IsIPv6());
    return strprintf("%x:%x:%x:%x:%x:%x:%x:%x",
                     m_addr[0] << 8 | m_addr[1], m_addr[2] << 8 | m_addr[3],
                     m_addr[4] << 8 | m_addr[5], m_addr[6] << 8 | m_addr[7],
                     m_addr[8] << 8 | m_addr[9], m_addr[10] << 8 | m_addr[11],
                     m_addr[12] << 8 | m_addr[13], m_addr[14] << 8 | m_addr[15]);
}

std::string CNetAddr::ToString() const
{
    return ToStringIP();
}

bool operator==(const CNetAddr& a, const CNetAddr& b)
{
    return a.m_net == b.m_net && a.m_addr == b.m_addr;
}

bool operator<(const CNetAddr& a, const CNetAddr& b)
{
    return a.m_net < b.m_net || (a.m_net == b.m_net && a.m_addr < b.m_addr);
}

/**
 * Try to get our IPv4 address.
 *
 * @param[out] pipv4Addr The in_addr struct to which to copy.
 *
 * @returns Whether or not the operation was successful, in particular, whether
 *          or not our address was an IPv4 address.
 *
 * @see CNetAddr::IsIPv4()
 */
bool CNetAddr::GetInAddr(struct in_addr* pipv4Addr) const
{
    if (!IsIPv4())
        return false;
    memcpy(pipv4Addr, m_addr.data(), m_addr.size());
    return true;
}

/**
 * Try to get our IPv6 address.
 *
 * @param[out] pipv6Addr The in6_addr struct to which to copy.
 *
 * @returns Whether or not the operation was successful, in particular, whether
 *          or not our address was an IPv6 address.
 *
 * @see CNetAddr::IsIPv6()
 */
bool CNetAddr::GetIn6Addr(struct in6_addr* pipv6Addr) const
{
    if (!IsIPv6()) {
        return false;
    }
    memcpy(pipv6Addr, m_addr.data(), m_addr.size());
    return true;
}

bool CNetAddr::HasLinkedIPv4() const
{
    return IsRoutable() && (IsIPv4() || IsRFC6145() || IsRFC6052() || IsRFC3964() || IsRFC4380());
}

uint32_t CNetAddr::GetLinkedIPv4() const
{
    if (IsIPv4()) {
        return ReadBE32(m_addr.data());
    } else if (IsRFC6052() || IsRFC6145()) {
        // mapped IPv4, SIIT translated IPv4: the IPv4 address is the last 4 bytes of the address
        return ReadBE32(m_addr.data() + m_addr.size() - ADDR_IPv4_SIZE);
    } else if (IsRFC3964()) {
        // 6to4 tunneled IPv4: the IPv4 address is in bytes 2-6
        return ReadBE32(m_addr.data() + 2);
    } else if (IsRFC4380()) {
        // Teredo tunneled IPv4: the IPv4 address is in the last 4 bytes of the address, but bitflipped
        return ~ReadBE32(m_addr.data() + m_addr.size() - ADDR_IPv4_SIZE);
    }
    assert(false);
}

uint32_t CNetAddr::GetNetClass() const {
    uint32_t net_class = NET_IPV6;
    if (IsLocal()) {
        net_class = 255;
    }
    if (IsInternal()) {
        net_class = NET_INTERNAL;
    } else if (!IsRoutable()) {
        net_class = NET_UNROUTABLE;
    } else if (HasLinkedIPv4()) {
        net_class = NET_IPV4;
    } else if (IsTor()) {
        net_class = NET_ONION;
    }
    return net_class;
}

uint32_t CNetAddr::GetMappedAS(const std::vector<bool> &asmap) const {
    uint32_t net_class = GetNetClass();
    if (asmap.size() == 0 || (net_class != NET_IPV4 && net_class != NET_IPV6)) {
        return 0; // Indicates not found, safe because AS0 is reserved per RFC7607.
    }
    std::vector<bool> ip_bits(128);
    if (HasLinkedIPv4()) {
        // For lookup, treat as if it was just an IPv4 address (IPv4_IN_IPv6_PREFIX + IPv4 bits)
        for (int8_t byte_i = 0; byte_i < 12; ++byte_i) {
            for (uint8_t bit_i = 0; bit_i < 8; ++bit_i) {
                ip_bits[byte_i * 8 + bit_i] = (IPv4_IN_IPv6_PREFIX[byte_i] >> (7 - bit_i)) & 1;
            }
        }
        uint32_t ipv4 = GetLinkedIPv4();
        for (int i = 0; i < 32; ++i) {
            ip_bits[96 + i] = (ipv4 >> (31 - i)) & 1;
        }
    } else {
        // Use all 128 bits of the IPv6 address otherwise
        assert(IsIPv6());
        for (int8_t byte_i = 0; byte_i < 16; ++byte_i) {
            uint8_t cur_byte = m_addr[byte_i];
            for (uint8_t bit_i = 0; bit_i < 8; ++bit_i) {
                ip_bits[byte_i * 8 + bit_i] = (cur_byte >> (7 - bit_i)) & 1;
            }
        }
    }
    uint32_t mapped_as = Interpret(asmap, ip_bits);
    return mapped_as;
}

/**
 * Get the canonical identifier of our network group
 *
 * The groups are assigned in a way where it should be costly for an attacker to
 * obtain addresses with many different group identifiers, even if it is cheap
 * to obtain addresses with the same identifier.
 *
 * @note No two connections will be attempted to addresses with the same network
 *       group.
 */
std::vector<unsigned char> CNetAddr::GetGroup(const std::vector<bool> &asmap) const
{
    std::vector<unsigned char> vchRet;
    uint32_t net_class = GetNetClass();
    // If non-empty asmap is supplied and the address is IPv4/IPv6,
    // return ASN to be used for bucketing.
    uint32_t asn = GetMappedAS(asmap);
    if (asn != 0) { // Either asmap was empty, or address has non-asmappable net class (e.g. TOR).
        vchRet.push_back(NET_IPV6); // IPv4 and IPv6 with same ASN should be in the same bucket
        for (int i = 0; i < 4; i++) {
            vchRet.push_back((asn >> (8 * i)) & 0xFF);
        }
        return vchRet;
    }

    vchRet.push_back(net_class);
    int nBits;

    if (IsLocal()) {
        // all local addresses belong to the same group
        nBits = 0;
    } else if (IsInternal()) {
        // all internal-usage addresses get their own group
        nBits = ADDR_INTERNAL_SIZE * 8;
    } else if (!IsRoutable()) {
        // all other unroutable addresses belong to the same group
        nBits = 0;
    } else if (HasLinkedIPv4()) {
        // IPv4 addresses (and mapped IPv4 addresses) use /16 groups
        uint32_t ipv4 = GetLinkedIPv4();
        vchRet.push_back((ipv4 >> 24) & 0xFF);
        vchRet.push_back((ipv4 >> 16) & 0xFF);
        return vchRet;
    } else if (IsTor()) {
        nBits = 4;
    } else if (IsHeNet()) {
        // for he.net, use /36 groups
        nBits = 36;
    } else {
        // for the rest of the IPv6 network, use /32 groups
        nBits = 32;
    }

    // push our ip onto vchRet byte by byte...
    size_t i = 0;
    while (nBits >= 8)
    {
        vchRet.push_back(m_addr.at(i));
        i++;
        nBits -= 8;
    }
    // ...for the last byte, push nBits and for the rest of the byte push 1's
    if (nBits > 0)
        vchRet.push_back(m_addr.at(i) | ((1 << (8 - nBits)) - 1));

    return vchRet;
}

uint64_t CNetAddr::GetHash() const
{
    uint256 hash = Hash(m_addr.begin(), m_addr.end());
    uint64_t nRet;
    memcpy(&nRet, &hash, sizeof(nRet));
    return nRet;
}

std::vector<unsigned char> CNetAddr::GetAddrKey() const
{
    if (IsAddrV1Compatible()) {
        uint8_t serialized[V1_SERIALIZATION_SIZE];
        SerializeV1Array(serialized);
        return std::vector<uint8_t>(serialized, serialized + sizeof(serialized));
    }
    return m_addr;
}

// private extensions to enum Network, only returned by GetExtNetwork,
// and only used in GetReachabilityFrom
static const int NET_UNKNOWN = NET_MAX + 0;
static const int NET_TEREDO  = NET_MAX + 1;
int static GetExtNetwork(const CNetAddr *addr)
{
    if (addr == nullptr)
        return NET_UNKNOWN;
    if (addr->IsRFC4380())
        return NET_TEREDO;
    return addr->GetNetwork();
}

/** Calculates a metric for how reachable (*this) is from a given partner */
int CNetAddr::GetReachabilityFrom(const CNetAddr *paddrPartner) const
{
    enum Reachability {
        REACH_UNREACHABLE,
        REACH_DEFAULT,
        REACH_TEREDO,
        REACH_IPV6_WEAK,
        REACH_IPV4,
        REACH_IPV6_STRONG,
        REACH_PRIVATE
    };

    if (!IsRoutable() || IsInternal())
        return REACH_UNREACHABLE;

    int ourNet = GetExtNetwork(this);
    int theirNet = GetExtNetwork(paddrPartner);
    bool fTunnel = IsRFC3964() || IsRFC6052() || IsRFC6145();

    switch(theirNet) {
    case NET_IPV4:
        switch(ourNet) {
        default:       return REACH_DEFAULT;
        case NET_IPV4: return REACH_IPV4;
        }
    case NET_IPV6:
        switch(ourNet) {
        default:         return REACH_DEFAULT;
        case NET_TEREDO: return REACH_TEREDO;
        case NET_IPV4:   return REACH_IPV4;
        case NET_IPV6:   return fTunnel ? REACH_IPV6_WEAK : REACH_IPV6_STRONG; // only prefer giving our IPv6 address if it's not tunnelled
        }
    case NET_ONION:
        switch(ourNet) {
        default:         return REACH_DEFAULT;
        case NET_IPV4:   return REACH_IPV4; // Tor users can connect to IPv4 as well
        case NET_ONION:    return REACH_PRIVATE;
        }
    case NET_TEREDO:
        switch(ourNet) {
        default:          return REACH_DEFAULT;
        case NET_TEREDO:  return REACH_TEREDO;
        case NET_IPV6:    return REACH_IPV6_WEAK;
        case NET_IPV4:    return REACH_IPV4;
        }
    case NET_UNKNOWN:
    case NET_UNROUTABLE:
    default:
        switch(ourNet) {
        default:          return REACH_DEFAULT;
        case NET_TEREDO:  return REACH_TEREDO;
        case NET_IPV6:    return REACH_IPV6_WEAK;
        case NET_IPV4:    return REACH_IPV4;
        case NET_ONION:     return REACH_PRIVATE; // either from Tor, or don't care about our address
        }
    }
}

CService::CService() : port(0)
{
}

CService::CService(const CNetAddr& cip, unsigned short portIn) : CNetAddr(cip), port(portIn)
{
}

CService::CService(const struct in_addr& ipv4Addr, unsigned short portIn) : CNetAddr(ipv4Addr), port(portIn)
{
}

CService::CService(const struct in6_addr& ipv6Addr, unsigned short portIn) : CNetAddr(ipv6Addr), port(portIn)
{
}

CService::CService(const struct sockaddr_in& addr) : CNetAddr(addr.sin_addr), port(ntohs(addr.sin_port))
{
    assert(addr.sin_family == AF_INET);
}

CService::CService(const struct sockaddr_in6 &addr) : CNetAddr(addr.sin6_addr, addr.sin6_scope_id), port(ntohs(addr.sin6_port))
{
   assert(addr.sin6_family == AF_INET6);
}

bool CService::SetSockAddr(const struct sockaddr *paddr)
{
    switch (paddr->sa_family) {
    case AF_INET:
        *this = CService(*(const struct sockaddr_in*)paddr);
        return true;
    case AF_INET6:
        *this = CService(*(const struct sockaddr_in6*)paddr);
        return true;
    default:
        return false;
    }
}

unsigned short CService::GetPort() const
{
    return port;
}

bool operator==(const CService& a, const CService& b)
{
    return static_cast<CNetAddr>(a) == static_cast<CNetAddr>(b) && a.port == b.port;
}

bool operator<(const CService& a, const CService& b)
{
    return static_cast<CNetAddr>(a) < static_cast<CNetAddr>(b) || (static_cast<CNetAddr>(a) == static_cast<CNetAddr>(b) && a.port < b.port);
}

/**
 * Obtain the IPv4/6 socket address this represents.
 *
 * @param[out] paddr The obtained socket address.
 * @param[in,out] addrlen The size, in bytes, of the address structure pointed
 *                        to by paddr. The value that's pointed to by this
 *                        parameter might change after calling this function if
 *                        the size of the corresponding address structure
 *                        changed.
 *
 * @returns Whether or not the operation was successful.
 */
bool CService::GetSockAddr(struct sockaddr* paddr, socklen_t *addrlen) const
{
    if (IsIPv4()) {
        if (*addrlen < (socklen_t)sizeof(struct sockaddr_in))
            return false;
        *addrlen = sizeof(struct sockaddr_in);
        struct sockaddr_in *paddrin = (struct sockaddr_in*)paddr;
        memset(paddrin, 0, *addrlen);
        if (!GetInAddr(&paddrin->sin_addr))
            return false;
        paddrin->sin_family = AF_INET;
        paddrin->sin_port = htons(port);
        return true;
    }
    if (IsIPv6()) {
        if (*addrlen < (socklen_t)sizeof(struct sockaddr_in6))
            return false;
        *addrlen = sizeof(struct sockaddr_in6);
        struct sockaddr_in6 *paddrin6 = (struct sockaddr_in6*)paddr;
        memset(paddrin6, 0, *addrlen);
        if (!GetIn6Addr(&paddrin6->sin6_addr))
            return false;
        paddrin6->sin6_scope_id = scopeId;
        paddrin6->sin6_family = AF_INET6;
        paddrin6->sin6_port = htons(port);
        return true;
    }
    return false;
}

/**
 * @returns An identifier unique to this service's address and port number.
 */
std::vector<unsigned char> CService::GetKey() const
{
    auto key = GetAddrKey();
    key.push_back(port / 0x100); // most significant byte of our port
    key.push_back(port & 0x0FF); // least significant byte of our port
    return key;
}

std::string CService::ToStringPort() const
{
    return strprintf("%u", port);
}

std::string CService::ToStringIPPort() const
{
    if (IsIPv4() || IsTor() || IsInternal()) {
        return ToStringIP() + ":" + ToStringPort();
    } else {
        return "[" + ToStringIP() + "]:" + ToStringPort();
    }
}

std::string CService::ToString() const
{
    return ToStringIPPort();
}

CSubNet::CSubNet():
    valid(false)
{
    memset(netmask, 0, sizeof(netmask));
}

CSubNet::CSubNet(const CNetAddr &addr, uint8_t mask)
{
    valid = (addr.IsIPv4() && mask <= ADDR_IPv4_SIZE * 8) ||
            (addr.IsIPv6() && mask <= ADDR_IPv6_SIZE * 8);
    if (!valid) {
        return;
    }

    assert(mask <= sizeof(netmask) * 8);

    network = addr;

    uint8_t n = mask;
    for (size_t i = 0; i < network.m_addr.size(); ++i) {
        const uint8_t bits = n < 8 ? n : 8;
        netmask[i] = (uint8_t)((uint8_t)0xFF << (8 - bits)); // Set first bits.
        network.m_addr[i] &= netmask[i]; // Normalize network according to netmask.
        n -= bits;
    }
}

/**
 * @returns The number of 1-bits in the prefix of the specified subnet mask. If
 *          the specified subnet mask is not a valid one, -1.
 */
static inline int NetmaskBits(uint8_t x)
{
    switch(x) {
    case 0x00: return 0;
    case 0x80: return 1;
    case 0xc0: return 2;
    case 0xe0: return 3;
    case 0xf0: return 4;
    case 0xf8: return 5;
    case 0xfc: return 6;
    case 0xfe: return 7;
    case 0xff: return 8;
    default: return -1;
    }
}

CSubNet::CSubNet(const CNetAddr &addr, const CNetAddr &mask)
{
    valid = (addr.IsIPv4() || addr.IsIPv6()) && addr.m_net == mask.m_net;
    // Check if `mask` contains 1-bits after 0-bits (which is an invalid netmask).
    for (auto b : mask.m_addr) {
        if (NetmaskBits(b) == -1) {
            valid = false;
            break;
        }
    }
    if (!valid) {
        return;
    }

    assert(mask.m_addr.size() <= sizeof(netmask));

    memcpy(netmask, mask.m_addr.data(), mask.m_addr.size());

    network = addr;

    // Normalize network according to netmask
    for (size_t x = 0; x < network.m_addr.size(); ++x)
        network.m_addr.at(x) &= netmask[x];
}

CSubNet::CSubNet(const CNetAddr& addr)
{
    valid = addr.IsIPv4() || addr.IsIPv6();
    if (!valid) {
        return;
    }

    assert(addr.m_addr.size() <= sizeof(netmask));

    memset(netmask, 0xFF, addr.m_addr.size());

    network = addr;
}

/**
 * @returns True if this subnet is valid, the specified address is valid, and
 *          the specified address belongs in this subnet.
 */
bool CSubNet::Match(const CNetAddr &addr) const
{
    if (!valid || !addr.IsValid() || network.m_net != addr.m_net)
        return false;
    for (size_t x = 0; x < addr.m_addr.size(); ++x)
        if ((addr.m_addr[x] & netmask[x]) != network.m_addr.at(x))
            return false;
    return true;
}

std::string CSubNet::ToString() const
{
    assert(network.m_addr.size() <= sizeof(netmask));

    uint8_t cidr = 0;

    for (size_t i = 0; i < network.m_addr.size(); ++i) {
        if (netmask[i] == 0x00) {
            break;
        }
        cidr += NetmaskBits(netmask[i]);
    }

    return network.ToString() + "/" + strprintf("%hhu", cidr);
}

bool CSubNet::IsValid() const
{
    return valid;
}

bool operator==(const CSubNet& a, const CSubNet& b)
{
    const size_t size = a.network.IsIPv4() ? ADDR_IPv4_SIZE : ADDR_IPv6_SIZE;

    return a.valid == b.valid && a.network == b.network &&
           memcmp(a.netmask, b.netmask, size) == 0;
}

bool operator<(const CSubNet& a, const CSubNet& b)
{
    const size_t size = a.network.IsIPv4() ? ADDR_IPv4_SIZE : ADDR_IPv6_SIZE;

    return a.network < b.network ||
           (a.network == b.network && memcmp(a.netmask, b.netmask, size) < 0);
}

bool SanityCheckASMap(const std::vector<bool>& asmap)
{
    return SanityCheckASMap(asmap, 128); // For IP address lookups, the input is 128 bits
}
