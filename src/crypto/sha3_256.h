// Copyright (c) 2020-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_SHA3_256_H
#define BITCOIN_CRYPTO_SHA3_256_H

#include <prevector.h>

#include <cstddef>

/** A hasher class for SHA3-256. */
class SHA3_256
{
public:
    static constexpr size_t OUTPUT_SIZE = 32;

    SHA3_256();

    // Note: the implementation is going to keep all the data until Reset() is
    // called or the object is destroyed.
    SHA3_256& Write(const unsigned char* data, size_t len);

    void Finalize(unsigned char hash[OUTPUT_SIZE]) const;

    SHA3_256& Reset();

private:
    prevector<64, unsigned char> m_input;
};

#endif // BITCOIN_CRYPTO_SHA3_256_H
