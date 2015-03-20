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

void sha256_write(sha256_context *ctx, const unsigned char *datap, int length)
{
	SECStatus status = PK11_DigestOp(ctx->ctx_nss, datap, length);
	passert(status == SECSuccess);
}

void sha256_hash_buffer(unsigned char *ib, int ile, unsigned char *ob, unsigned int ole)
{
	sha256_context ctx;
	unsigned int length;
	SECStatus status;

	if (ole < 1)
		return;

	memset(ob, 0, ole);
	if (ole > 32)
		ole = 32;
	sha256_init(&ctx);
	sha256_write(&ctx, ib, ile);
	status = PK11_DigestFinal(ctx.ctx_nss, ob, &length, ole);
	passert(status == SECSuccess);
	passert(length == ole);
	PK11_DestroyContext(ctx.ctx_nss, PR_TRUE);
}

void sha512_init(sha512_context *ctx)
{
	SECStatus status;

	ctx->ctx_nss = PK11_CreateDigestContext(SEC_OID_SHA512);
	passert(ctx->ctx_nss != NULL);
	status = PK11_DigestBegin(ctx->ctx_nss);
	passert(status == SECSuccess);
}

void sha512_write(sha512_context *ctx, const unsigned char *datap, int length)
{
	SECStatus status = PK11_DigestOp(ctx->ctx_nss, datap, length);
	passert(status == SECSuccess);
}

void sha512_hash_buffer(unsigned char *ib, int ile, unsigned char *ob, unsigned int ole)
{
	sha512_context ctx;
	unsigned int length;
	SECStatus status;

	if (ole < 1)
		return;

	memset(ob, 0, ole);
	if (ole > 64)
		ole = 64;
	sha512_init(&ctx);
	sha512_write(&ctx, ib, ile);
	status = PK11_DigestFinal(ctx.ctx_nss, ob, &length, ole);
	passert(status == SECSuccess);
	passert(length == ole);
	PK11_DestroyContext(ctx.ctx_nss, PR_TRUE);
}

void sha384_init(sha512_context *ctx)
{
	SECStatus status;

	ctx->ctx_nss = PK11_CreateDigestContext(SEC_OID_SHA384);
	passert(ctx->ctx_nss != NULL);
	status = PK11_DigestBegin(ctx->ctx_nss);
	passert(status == SECSuccess);
}

void sha384_hash_buffer(unsigned char *ib, int ile, unsigned char *ob, unsigned int ole)
{
	sha512_context ctx;
	unsigned int length;
	SECStatus status;

	if (ole < 1)
		return;

	memset(ob, 0, ole);
	if (ole > 48)
		ole = 48;
	sha384_init(&ctx);
	status = PK11_DigestOp(ctx.ctx_nss, ib, ile);
	passert(status == SECSuccess);
	status = PK11_DigestFinal(ctx.ctx_nss, ob, &length, ole);
	passert(status == SECSuccess);
	passert(length == ole);
	PK11_DestroyContext(ctx.ctx_nss, PR_TRUE);
}
