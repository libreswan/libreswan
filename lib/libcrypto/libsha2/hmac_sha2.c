/*
 * (C)opyright 2005 Michael Richardson <mcr@xelerance.com>
 * (C)opyright 2008-2009 Avesh Agarwal <avagarwa@redhat.com>
 * (C)opyright 2012 Paul Wouters <paul@libreswan.org>
 */

#ifdef __KERNEL__
# include <linux/types.h>
# include <linux/string.h>
#else
# include <sys/types.h>
# include <string.h>
# include <pk11pub.h>
#endif
#include "hmac_generic.h"
#include "sha2.h"
#include "hmac_sha2.h"

inline void sha256_result(sha256_context *ctx, u_int8_t * hash, int hashlen) {
	unsigned int len;
	SECStatus s = PK11_DigestFinal(ctx->ctx_nss, hash, &len, hashlen);
	PR_ASSERT(len==hashlen);
	PR_ASSERT(s==SECSuccess);
	PK11_DestroyContext(ctx->ctx_nss, PR_TRUE);
}

inline void sha512_result(sha512_context *ctx, u_int8_t * hash, int hashlen) {
	unsigned int len;
	SECStatus s = PK11_DigestFinal(ctx->ctx_nss, hash, &len, hashlen);
	PR_ASSERT(len==hashlen);
	PR_ASSERT(s==SECSuccess);
	PK11_DestroyContext(ctx->ctx_nss, PR_TRUE);
}
