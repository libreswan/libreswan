/*
 * (C)opyright 2005 Michael Richardson <mcr@xelerance.com>
 * (C)opyright 2007 Paul Wouters <paul@xelerance.com>
 * (C)opyright 2009 Avesh Agarwal <avagarwa@redhat.com>
 * (C)opyright 2012-2014 Paul Wouters <paul@libreswan.org>
 */


#include <pk11pub.h>
#include "lswlog.h"
#include "md5.h"

/* MD5 initialization. Begins an MD5 operation, writing a new context.
 */
void lsMD5Init(lsMD5_CTX *context)
{
	SECStatus status;

	context->ctx_nss = PK11_CreateDigestContext(SEC_OID_MD5);
	passert(context->ctx_nss != NULL);
	status = PK11_DigestBegin(context->ctx_nss);
	passert(status == SECSuccess);
}

/* MD5 block update operation. Continues an MD5 message-digest
 * operation, processing another message block, and updating the
 * context.
 */
void lsMD5Update(lsMD5_CTX *context, const unsigned char *input, size_t inputLen)
{
	SECStatus status = PK11_DigestOp(context->ctx_nss, input, inputLen);
	passert(status == SECSuccess);
}

/* MD5 finalization. Ends an MD5 message-digest operation, writing the
 * the message digest and zeroing the context.
 */
void lsMD5Final(unsigned char digest[MD5_DIGEST_SIZE], lsMD5_CTX *context)
{
	unsigned int length;
	SECStatus status = PK11_DigestFinal(context->ctx_nss, digest, &length,
				  MD5_DIGEST_SIZE);

	passert(status == SECSuccess);
	passert(length == MD5_DIGEST_SIZE);
	PK11_DestroyContext(context->ctx_nss, PR_TRUE);
}
