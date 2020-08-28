// Copyright (c) 2020-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/sha3_256.h>

extern "C" {
#include <crypto/keccak-tiny/keccak-tiny.h>
}

SHA3_256::SHA3_256() {}

SHA3_256& SHA3_256::Write(const unsigned char* data, size_t len)
{
    m_input.insert(m_input.end(), data, data + len);
    return *this;
}

void SHA3_256::Finalize(unsigned char hash[OUTPUT_SIZE]) const
{
    sha3_256(hash, OUTPUT_SIZE, m_input.data(), m_input.size());
}

SHA3_256& SHA3_256::Reset()
{
    m_input.clear();
    return *this;
}
