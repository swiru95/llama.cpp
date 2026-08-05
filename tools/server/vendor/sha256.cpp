#include "sha256.h"

#include <cstring>
#include <iomanip>
#include <sstream>

// Constants
static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIGMA0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SIGMA1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define sigma0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define sigma1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

static void sha256_transform(sha256_context * ctx, const uint8_t data[64]) {
    uint32_t a, b, c, d, e, f, g, h, i, t1, t2, w[64];

    for (i = 0; i < 16; ++i) {
        w[i] = ((uint32_t)data[i * 4] << 24)
             | ((uint32_t)data[i * 4 + 1] << 16)
             | ((uint32_t)data[i * 4 + 2] << 8)
             | ((uint32_t)data[i * 4 + 3]);
    }
    for (; i < 64; ++i) {
        w[i] = sigma1(w[i - 2]) + w[i - 7] + sigma0(w[i - 15]) + w[i - 16];
    }

    a = ctx->h[0];
    b = ctx->h[1];
    c = ctx->h[2];
    d = ctx->h[3];
    e = ctx->h[4];
    f = ctx->h[5];
    g = ctx->h[6];
    h = ctx->h[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + SIGMA1(e) + CH(e, f, g) + k[i] + w[i];
        t2 = SIGMA0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->h[0] += a;
    ctx->h[1] += b;
    ctx->h[2] += c;
    ctx->h[3] += d;
    ctx->h[4] += e;
    ctx->h[5] += f;
    ctx->h[6] += g;
    ctx->h[7] += h;
}

void sha256_init(sha256_context * ctx) {
    ctx->h[0] = 0x6a09e667;
    ctx->h[1] = 0xbb67ae85;
    ctx->h[2] = 0x3c6ef372;
    ctx->h[3] = 0xa54ff53a;
    ctx->h[4] = 0x510e527f;
    ctx->h[5] = 0x9b05688c;
    ctx->h[6] = 0x1f83d9ab;
    ctx->h[7] = 0x5be0cd19;
    ctx->bitlen = 0;
    ctx->buflen = 0;
}

void sha256_update(sha256_context * ctx, const uint8_t * data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->buf[ctx->buflen++] = data[i];
        if (ctx->buflen == 64) {
            sha256_transform(ctx, ctx->buf);
            ctx->bitlen += 512;
            ctx->buflen = 0;
        }
    }
}

void sha256_final(sha256_context * ctx, uint8_t digest[32]) {
    size_t i = ctx->buflen;

    if (ctx->buflen < 56) {
        ctx->buf[i++] = 0x80;
        while (i < 56) {
            ctx->buf[i++] = 0x00;
        }
    } else {
        ctx->buf[i++] = 0x80;
        while (i < 64) {
            ctx->buf[i++] = 0x00;
        }
        sha256_transform(ctx, ctx->buf);
        std::memset(ctx->buf, 0, 56);
    }

    ctx->bitlen += ctx->buflen * 8;
    ctx->buf[63] = (uint8_t)(ctx->bitlen);
    ctx->buf[62] = (uint8_t)(ctx->bitlen >> 8);
    ctx->buf[61] = (uint8_t)(ctx->bitlen >> 16);
    ctx->buf[60] = (uint8_t)(ctx->bitlen >> 24);
    ctx->buf[59] = (uint8_t)(ctx->bitlen >> 32);
    ctx->buf[58] = (uint8_t)(ctx->bitlen >> 40);
    ctx->buf[57] = (uint8_t)(ctx->bitlen >> 48);
    ctx->buf[56] = (uint8_t)(ctx->bitlen >> 56);

    sha256_transform(ctx, ctx->buf);

    for (i = 0; i < 4; ++i) {
        digest[i]      = (ctx->h[0] >> (24 - i * 8)) & 0x000000ff;
        digest[i + 4]  = (ctx->h[1] >> (24 - i * 8)) & 0x000000ff;
        digest[i + 8]  = (ctx->h[2] >> (24 - i * 8)) & 0x000000ff;
        digest[i + 12] = (ctx->h[3] >> (24 - i * 8)) & 0x000000ff;
        digest[i + 16] = (ctx->h[4] >> (24 - i * 8)) & 0x000000ff;
        digest[i + 20] = (ctx->h[5] >> (24 - i * 8)) & 0x000000ff;
        digest[i + 24] = (ctx->h[6] >> (24 - i * 8)) & 0x000000ff;
        digest[i + 28] = (ctx->h[7] >> (24 - i * 8)) & 0x000000ff;
    }
}

std::string sha256_hex(const std::string & data) {
    sha256_context ctx;
    uint8_t digest[32];
    sha256_init(&ctx);
    sha256_update(&ctx, reinterpret_cast<const uint8_t *>(data.data()), data.size());
    sha256_final(&ctx, digest);

    std::ostringstream oss;
    for (int i = 0; i < 32; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    }
    return oss.str();
}
