#ifndef _SHA2_H
#define _SHA2_H
/*
 *  sha512.h
 *
 *  Written by Jari Ruusu, April 16 2001
 *
 *  Copyright 2001 by Jari Ruusu.
 *  Redistribution of this file is permitted under the GNU Public License.
 *
 * (C)opyright 2005 Michael Richardson <mcr@xelerance.com>
 * (C)opyright 2008-2009 Avesh Agarwal <avagarwa@redhat.com>
 * (C)opyright 2012 Paul Wouters <paul@libreswan.org>
 */

#ifdef __KERNEL__
# include <linux/types.h>
#else
# include <sys/types.h>
# include <nss.h>
# include <pk11pub.h>
#endif

typedef struct {
	PK11Context     *ctx_nss;
} sha256_context;

typedef struct {
	PK11Context     *ctx_nss;
} sha512_context;

/* no sha384_context, use sha512_context */

/* 256 bit hash, provides 128 bits of security against collision attacks */
extern void sha256_init(sha256_context *);
extern void sha256_write(sha256_context *, const unsigned char *, int);
extern void sha256_final(sha256_context *);
extern void sha256_hash_buffer(unsigned char *, int, unsigned char *, int);

/* 512 bit hash, provides 256 bits of security against collision attacks */
extern void sha512_init(sha512_context *);
extern void sha512_write(sha512_context *, const unsigned char *, int);
extern void sha512_final(sha512_context *);
extern void sha512_hash_buffer(unsigned char *, int, unsigned char *, int);

/* 384 bit hash, provides 192 bits of security against collision attacks */
extern void sha384_init(sha512_context *);
/* no sha384_write(), use sha512_write() */
/* no sha384_final(), use sha512_final(), result in ctx->sha_out[0...47]  */
extern void sha384_hash_buffer(unsigned char *, int, unsigned char *, int);
#endif /* _SHA2_H */
