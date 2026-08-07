// Public domain SHA-256 implementation
// Based on FIPS 180-4 specification
// https://csrc.nist.gov/publications/detail/fips/180/4

#pragma once

#include <cstdint>
#include <string>

struct sha256_context {
    uint32_t h[8];
    uint64_t bitlen;
    uint8_t buf[64];
    size_t buflen;
};

void sha256_init(sha256_context * ctx);
void sha256_update(sha256_context * ctx, const uint8_t * data, size_t len);
void sha256_final(sha256_context * ctx, uint8_t digest[32]);

// Convenience function: returns lowercase hex string (64 chars)
std::string sha256_hex(const std::string & data);
