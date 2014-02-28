/*
 * The rest of the code is derived from MD5C.C by RSADSI. Minor cosmetic
 * changes to accomodate it in the kernel by ji.
 * Minor changes to make 64 bit clean by Peter Onion (i.e. using u_int*_t).
 * Changes by Avesh Agarwal to use NSS.
 */

/* MD5C.C - RSA Data Security, Inc., MD5 message-digest algorithm
 */

/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991.
 *
 * http://www.ietf.org/ietf-ftp/IPR/RSA-MD-all
 */

/*
 * Additions by JI
 *
 * HAVEMEMCOPY is defined if mem* routines are available
 *
 * HAVEHTON is defined if htons() and htonl() can be used
 * for big/little endian conversions
 *
 */

/*
 * (C)opyright 2005 Michael Richardson <mcr@xelerance.com>
 * (C)opyright 2007 Paul Wouters <paul@xelerance.com>
 * (C)opyright 2009 Avesh Agarwal <avagarwa@redhat.com>
 * (C)opyright 2012-2013 Paul Wouters <paul@libreswan.org>
 */

#include <stddef.h>
#include <string.h>
#include <sys/types.h>  /* for u_int*_t */

#include "md5.h"
#include "lswendian.h" /* sets BYTE_ORDER, LITTLE_ENDIAN, and BIG_ENDIAN */

#include <pk11pub.h>
#include "lswlog.h"

#define HAVEMEMCOPY 1   /* use ISO C's memcpy and memset */

/* Constants for MD5Transform routine.
 */

#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

#define MD5Transform _MD5Transform

#if BYTE_ORDER == LITTLE_ENDIAN
#define Encode MD5_memcpy
#define Decode MD5_memcpy
#else
static void Encode(unsigned char *, UINT4 *, unsigned int);
static void Decode(UINT4 *, const unsigned char *, unsigned int);
#endif

#ifdef HAVEMEMCOPY
#include <memory.h>
#define MD5_memcpy      memcpy
#define MD5_memset      memset
#else
#ifdef HAVEBCOPY
#define MD5_memcpy(_a, _b, _c) memcpy((_a), (_b), (_c))
#define MD5_memset(_a, _b, _c) memset((_a), '\0', (_c))
#else
static void MD5_memcpy(POINTER, POINTER, unsigned int);
static void MD5_memset(POINTER, int, unsigned int);
#endif
#endif

/* F, G, H and I are basic MD5 functions.
 */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/* ROTATE_LEFT rotates x left n bits.
 */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
   Rotation is separate from addition to prevent recomputation.
 */
#define FF(a, b, c, d, x, s, ac) { \
		(a) += F((b), (c), (d)) + (x) + (UINT4)(ac); \
		(a) = ROTATE_LEFT((a), (s)); \
		(a) += (b); \
}
#define GG(a, b, c, d, x, s, ac) { \
		(a) += G((b), (c), (d)) + (x) + (UINT4)(ac); \
		(a) = ROTATE_LEFT((a), (s)); \
		(a) += (b); \
}
#define HH(a, b, c, d, x, s, ac) { \
		(a) += H((b), (c), (d)) + (x) + (UINT4)(ac); \
		(a) = ROTATE_LEFT((a), (s)); \
		(a) += (b); \
}
#define II(a, b, c, d, x, s, ac) { \
		(a) += I((b), (c), (d)) + (x) + (UINT4)(ac); \
		(a) = ROTATE_LEFT((a), (s)); \
		(a) += (b); \
}

/* MD5 initialization. Begins an MD5 operation, writing a new context.
 */
void osMD5Init(context)
MD5_CTX * context;                                        /* context */
{
	SECStatus status;

	context->ctx_nss = PK11_CreateDigestContext(SEC_OID_MD5);
	passert(context->ctx_nss != NULL);
	status = PK11_DigestBegin(context->ctx_nss);
	passert(status == SECSuccess);
}

/* MD5 block update operation. Continues an MD5 message-digest
   operation, processing another message block, and updating the
   context.
 */
void osMD5Update(context, input, inputLen)
MD5_CTX * context;                              /* context */
const unsigned char *input;                     /* input block */
UINT4 inputLen;                                 /* length of input block */
{
	SECStatus status = PK11_DigestOp(context->ctx_nss, input, inputLen);

	passert(status == SECSuccess);
}

/* MD5 finalization. Ends an MD5 message-digest operation, writing the
   the message digest and zeroizing the context.
 */
void osMD5Final(digest, context)
unsigned char digest[16];                               /* message digest */
MD5_CTX *context;                                       /* context */
{
	unsigned int length;
	SECStatus status = PK11_DigestFinal(context->ctx_nss, digest, &length,
				  MD5_DIGEST_SIZE);

	passert(status == SECSuccess);
	passert(length == MD5_DIGEST_SIZE);
	PK11_DestroyContext(context->ctx_nss, PR_TRUE);
}

/* MD5 basic transformation. Transforms state based on block.
 */

#if BYTE_ORDER != LITTLE_ENDIAN

/* Encodes input (UINT4) into output (unsigned char). Assumes len is
   a multiple of 4.
 */
static void Encode(output, input, len)
unsigned char *output;
UINT4 *input;
unsigned int len;
{
	unsigned int i, j;

	for (i = 0, j = 0; j < len; i++, j += 4) {
		output[j] = (unsigned char)(input[i] & 0xff);
		output[j + 1] = (unsigned char)((input[i] >> 8) & 0xff);
		output[j + 2] = (unsigned char)((input[i] >> 16) & 0xff);
		output[j + 3] = (unsigned char)((input[i] >> 24) & 0xff);
	}
}

/* Decodes input (unsigned char) into output (UINT4). Assumes len is
   a multiple of 4.
 */
static void Decode(output, input, len)
UINT4 * output;
const unsigned char *input;
unsigned int len;
{
	unsigned int i, j;

	for (i = 0, j = 0; j < len; i++, j += 4)
		output[i] = ((UINT4)input[j]) | (((UINT4)input[j + 1]) << 8) |
			    (((UINT4)input[j +
					   2]) <<
			     16) | (((UINT4)input[j + 3]) << 24);
}

#endif

#ifndef HAVEMEMCOPY
#ifndef HAVEBCOPY
/* Note: Replace "for loop" with standard memcpy if possible.
 */

static void MD5_memcpy(output, input, len)
POINTER output;
POINTER input;
unsigned int len;
{
	unsigned int i;

	for (i = 0; i < len; i++)

		output[i] = input[i];
}

/* Note: Replace "for loop" with standard memset if possible.
 */
static void MD5_memset(output, value, len)
POINTER output;
int value;
unsigned int len;
{
	unsigned int i;

	for (i = 0; i < len; i++)
		((char *)output)[i] = (char)value;
}
#endif
#endif
