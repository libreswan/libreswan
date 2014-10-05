/*
 * (C)opyright 2005 Michael Richardson <mcr@xelerance.com>
 * (C)opyright 2008-2009 Avesh Agarwal <avagarwa@redhat.com>
 * (C)opyright 2012-2014 Paul Wouters <paul@libreswan.org>
 */

#include "sha1.h"
#include <pk11pub.h>
#include "lswlog.h"

void SHA1Init(SHA1_CTX *context)
{
	SECStatus status;

	context->ctx_nss = PK11_CreateDigestContext(SEC_OID_SHA1);
	passert(context->ctx_nss != NULL);
	status = PK11_DigestBegin(context->ctx_nss);
	passert(status == SECSuccess);
}

void SHA1Update(SHA1_CTX *context, const unsigned char *data, size_t len)
{
	SECStatus status = PK11_DigestOp(context->ctx_nss, data, len);
	passert(status == SECSuccess);
}

void SHA1Final(unsigned char digest[SHA1_DIGEST_SIZE], SHA1_CTX *context)
{
	unsigned int length;
	SECStatus status = PK11_DigestFinal(context->ctx_nss, digest, &length,
				  SHA1_DIGEST_SIZE );

	passert(status == SECSuccess);
	passert(length == SHA1_DIGEST_SIZE);
	PK11_DestroyContext(context->ctx_nss, PR_TRUE);
}
