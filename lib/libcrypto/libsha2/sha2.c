/*
 *  sha512.c
 *
 *  Written by Jari Ruusu, April 16 2001
 *
 *  Copyright 2001 by Jari Ruusu.
 *  Redistribution of this file is permitted under the GNU Public License.
 *
 * (C)opyright 2005 Michael Richardson <mcr@xelerance.com>
 * (C)opyright 2008-2009 Avesh Agarwal <avagarwa@redhat.com>
 * (C)opyright 2012-2013 Paul Wouters <paul@libreswan.org>
 */

#include <libreswan.h> /* for DEBUG for NSS PR_ASSERT() */

#ifdef __KERNEL__
# include <linux/string.h>
# include <linux/types.h>
#else
# include <string.h>
# include <sys/types.h>
# include <pk11pub.h>
# include "lswlog.h"
#endif
#include "sha2.h"

static const u_int32_t sha256_hashInit[8] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
	0x1f83d9ab, 0x5be0cd19
};
static const u_int32_t sha256_K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
	0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
	0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
	0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
	0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static const u_int64_t sha512_hashInit[8] = {
	0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
	0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
	0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static const u_int64_t sha384_hashInit[8] = {
	0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL, 0x9159015a3070dd17ULL,
	0x152fecd8f70e5939ULL, 0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL,
	0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL
};

static const u_int64_t sha512_K[80] = {
	0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
	0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
	0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
	0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
	0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
	0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
	0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
	0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
	0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
	0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
	0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
	0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
	0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
	0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
	0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
	0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
	0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
	0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
	0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
	0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
	0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
	0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
	0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
	0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
	0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
	0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
	0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

#define Ch(x, y, z)   (((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x, y, z)  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define R(x, y)      ((y) >> (x))

void sha256_init(sha256_context *ctx)
{
	DBG(DBG_CRYPT, DBG_log("NSS: sha256 init start"));
	SECStatus status;
	ctx->ctx_nss = NULL;
	ctx->ctx_nss = PK11_CreateDigestContext(SEC_OID_SHA256);
	PR_ASSERT(ctx->ctx_nss != NULL);
	status = PK11_DigestBegin(ctx->ctx_nss);
	PR_ASSERT(status == SECSuccess);
	DBG(DBG_CRYPT, DBG_log("NSS: sha256 init end"));
}

#define S(x, y)      (((y) >> (x)) | ((y) << (32 - (x))))
#define uSig0(x)    ((S(2, (x))) ^ (S(13, (x))) ^ (S(22, (x))))
#define uSig1(x)    ((S(6, (x))) ^ (S(11, (x))) ^ (S(25, (x))))
#define lSig0(x)    ((S(7, (x))) ^ (S(18, (x))) ^ (R(3, (x))))
#define lSig1(x)    ((S(17, (x))) ^ (S(19, (x))) ^ (R(10, (x))))

void sha256_write(sha256_context *ctx, const unsigned char *datap, int length)
{
	SECStatus status = PK11_DigestOp(ctx->ctx_nss, datap, length);

	PR_ASSERT(status == SECSuccess);
	DBG(DBG_CRYPT, DBG_log("NSS: sha256 write end"));
}

void sha256_hash_buffer(unsigned char *ib, int ile, unsigned char *ob, unsigned int ole)
{
	sha256_context ctx;
	unsigned int length;

	if (ole < 1)
		return;

	memset(ob, 0, ole);
	if (ole > 32)
		ole = 32;
	sha256_init(&ctx);
	sha256_write(&ctx, ib, ile);
	SECStatus status = PK11_DigestFinal(ctx.ctx_nss, ob, &length, ole);
	PR_ASSERT(length == ole);
	PR_ASSERT(status == SECSuccess);
	PK11_DestroyContext(ctx.ctx_nss, PR_TRUE);
	DBG(DBG_CRYPT, DBG_log("NSS: sha256 final end"));
}

void sha512_init(sha512_context *ctx)
{
	DBG(DBG_CRYPT, DBG_log("NSS: sha512 init start"));
	SECStatus status;
	ctx->ctx_nss = NULL;
	ctx->ctx_nss = PK11_CreateDigestContext(SEC_OID_SHA512);
	PR_ASSERT(ctx->ctx_nss != NULL);
	status = PK11_DigestBegin(ctx->ctx_nss);
	PR_ASSERT(status == SECSuccess);
	DBG(DBG_CRYPT, DBG_log("NSS: sha512 init end"));
}

#undef S
#undef uSig0
#undef uSig1
#undef lSig0
#undef lSig1
#define S(x, y)      (((y) >> (x)) | ((y) << (64 - (x))))
#define uSig0(x)    ((S(28, (x))) ^ (S(34, (x))) ^ (S(39, (x))))
#define uSig1(x)    ((S(14, (x))) ^ (S(18, (x))) ^ (S(41, (x))))
#define lSig0(x)    ((S(1, (x))) ^ (S(8, (x))) ^ (R(7, (x))))
#define lSig1(x)    ((S(19, (x))) ^ (S(61, (x))) ^ (R(6, (x))))

void sha512_write(sha512_context *ctx, const unsigned char *datap, int length)
{
	SECStatus status = PK11_DigestOp(ctx->ctx_nss, datap, length);

	PR_ASSERT(status == SECSuccess);
	DBG(DBG_CRYPT, DBG_log("NSS: sha512 write end"));
}

void sha512_hash_buffer(unsigned char *ib, int ile, unsigned char *ob, unsigned int ole)
{
	sha512_context ctx;
	unsigned int length;

	if (ole < 1)
		return;

	memset(ob, 0, ole);
	if (ole > 64)
		ole = 64;
	sha512_init(&ctx);
	sha512_write(&ctx, ib, ile);
	SECStatus status = PK11_DigestFinal(ctx.ctx_nss, ob, &length, ole);
	PR_ASSERT(length == ole);
	PR_ASSERT(status == SECSuccess);
	PK11_DestroyContext(ctx.ctx_nss, PR_TRUE);
	DBG(DBG_CRYPT, DBG_log("NSS: sha512 final end"));
}

void sha384_init(sha512_context *ctx)
{
	DBG(DBG_CRYPT, DBG_log("NSS: sha384 init start"));
	SECStatus status;
	ctx->ctx_nss = NULL;
	ctx->ctx_nss = PK11_CreateDigestContext(SEC_OID_SHA384);
	PR_ASSERT(ctx->ctx_nss != NULL);
	status = PK11_DigestBegin(ctx->ctx_nss);
	PR_ASSERT(status == SECSuccess);
	DBG(DBG_CRYPT, DBG_log("NSS: sha384 init end"));
}

void sha384_hash_buffer(unsigned char *ib, int ile, unsigned char *ob, unsigned int ole)
{
	sha512_context ctx;
	unsigned int length;

	if (ole < 1)
		return;

	memset(ob, 0, ole);
	if (ole > 48)
		ole = 48;
	sha384_init(&ctx);
	SECStatus status = PK11_DigestOp(ctx.ctx_nss, ib, ile);
	PR_ASSERT(status == SECSuccess);
	status = PK11_DigestFinal(ctx.ctx_nss, ob, &length, ole);
	PR_ASSERT(length == ole);
	PR_ASSERT(status == SECSuccess);
	PK11_DestroyContext(ctx.ctx_nss, PR_TRUE);
	DBG(DBG_CRYPT, DBG_log("NSS: sha384 init end"));
}
