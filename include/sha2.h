#ifndef _SHA2_H
#define _SHA2_H

#include <nss.h>
#include <pk11pub.h>

typedef struct {
	PK11Context     *ctx_nss;
} sha256_context;

typedef struct {
	PK11Context     *ctx_nss;
} sha512_context;

/* no sha384_context, use sha512_context */

extern void sha256_init(sha256_context *);
extern void sha256_write(sha256_context *, const unsigned char *, int);
extern void sha256_final(sha256_context *);
extern void sha256_hash_buffer(unsigned char *, int, unsigned char *, unsigned int);

extern void sha512_init(sha512_context *);
extern void sha512_write(sha512_context *, const unsigned char *, int);
extern void sha512_final(sha512_context *);
extern void sha512_hash_buffer(unsigned char *, int, unsigned char *, unsigned int);

extern void sha384_init(sha512_context *);
/* no sha384_write(), use sha512_write() */
/* no sha384_final(), use sha512_final(), result in ctx->sha_out[0...47]  */
extern void sha384_hash_buffer(unsigned char *, int, unsigned char *, unsigned int);

#endif /* _SHA2_H */
