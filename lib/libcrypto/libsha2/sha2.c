/*
 * (C)opyright 2005 Michael Richardson <mcr@xelerance.com>
 * (C)opyright 2008-2009 Avesh Agarwal <avagarwa@redhat.com>
 * (C)opyright 2012-2014 Paul Wouters <paul@libreswan.org>
 */

#include <sha2.h>
#include <pk11pub.h>
#include "lswlog.h"

void sha256_init(sha256_context *ctx)
{
	SECStatus status;

	ctx->ctx_nss = PK11_CreateDigestContext(SEC_OID_SHA256);
	passert(ctx->ctx_nss != NULL);
	status = PK11_DigestBegin(ctx->ctx_nss);
	passert(status == SECSuccess);
}

void sha256_write(sha256_context *ctx, const unsigned char *datap, size_t length)
{
	SECStatus status = PK11_DigestOp(ctx->ctx_nss, datap, length);
	passert(status == SECSuccess);
}
void sha256_final(u_char *hash, sha256_context *ctx)
{
	unsigned int len;
	SECStatus s;

	s = PK11_DigestFinal(ctx->ctx_nss, hash, &len, SHA2_256_DIGEST_SIZE);
	passert(s == SECSuccess);
	passert(len == SHA2_256_DIGEST_SIZE);
	PK11_DestroyContext(ctx->ctx_nss, PR_TRUE);
}

void sha384_init(sha384_context *ctx)
{
	SECStatus status;

	ctx->ctx_nss = PK11_CreateDigestContext(SEC_OID_SHA384);
	passert(ctx->ctx_nss != NULL);
	status = PK11_DigestBegin(ctx->ctx_nss);
	passert(status == SECSuccess);
}

void sha384_write(sha384_context *ctx, const unsigned char *datap, size_t length)
{
	SECStatus status = PK11_DigestOp(ctx->ctx_nss, datap, length);
	passert(status == SECSuccess);
}

void sha384_final(u_char *hash, sha384_context *ctx)
{
	unsigned int len;
	SECStatus s;

	s = PK11_DigestFinal(ctx->ctx_nss, hash, &len, SHA2_384_DIGEST_SIZE);
	passert(s == SECSuccess);
	passert(len == SHA2_384_DIGEST_SIZE);
	PK11_DestroyContext(ctx->ctx_nss, PR_TRUE);
}

void sha512_init(sha512_context *ctx)
{
	SECStatus status;

	ctx->ctx_nss = PK11_CreateDigestContext(SEC_OID_SHA512);
	passert(ctx->ctx_nss != NULL);
	status = PK11_DigestBegin(ctx->ctx_nss);
	passert(status == SECSuccess);
}

void sha512_write(sha512_context *ctx, const unsigned char *datap, size_t length)
{
	SECStatus status = PK11_DigestOp(ctx->ctx_nss, datap, length);
	passert(status == SECSuccess);
}

void sha512_final(u_char *hash, sha512_context *ctx)
{
	unsigned int len;
	SECStatus s;

	s = PK11_DigestFinal(ctx->ctx_nss, hash, &len, SHA2_512_DIGEST_SIZE);
	passert(s == SECSuccess);
	passert(len == SHA2_512_DIGEST_SIZE);
	PK11_DestroyContext(ctx->ctx_nss, PR_TRUE);
}
