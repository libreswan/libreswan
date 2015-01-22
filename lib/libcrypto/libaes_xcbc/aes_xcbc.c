/*
 * (C)opyright 2008-2009 Avesh Agarwal <avagarwa@redhat.com>
 * (C)opyright 2012-2014 Paul Wouters <paul@libreswan.org>
 */

#include <aes_xcbc.h>
#include <pk11pub.h>
#include "lswlog.h"

void aes_xcbc_init(aes_xcbc_context *ctx)
{
	SECStatus status;

	/* does this OID point to the right version used in RFC-3566? */
	ctx->ctx_nss = PK11_CreateDigestContext(SEC_OID_AES_128_CBC); /* not recognised as valid hash OID! */
	passert(ctx->ctx_nss != NULL);
	status = PK11_DigestBegin(ctx->ctx_nss);
	passert(status == SECSuccess);
}

void aes_xcbc_write(aes_xcbc_context *ctx, const unsigned char *datap, size_t length)
{
	SECStatus status = PK11_DigestOp(ctx->ctx_nss, datap, length);

	passert(status == SECSuccess);
}

void aes_xcbc_final(u_char *hash, aes_xcbc_context *ctx)
{
	unsigned int len;
	SECStatus s = PK11_DigestFinal(ctx->ctx_nss, hash, &len, AES_XCBC_DIGEST_SIZE);

	passert(s == SECSuccess);
	passert(len == AES_XCBC_DIGEST_SIZE);
	PK11_DestroyContext(ctx->ctx_nss, PR_TRUE);
}
