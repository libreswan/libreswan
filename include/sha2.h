#ifndef _SHA2_H
#define _SHA2_H

#include <nss.h>
#include <pk11pub.h>

typedef struct {
	PK11Context     *ctx_nss;
} sha256_context;

typedef struct {
	PK11Context     *ctx_nss;
} sha384_context;

typedef struct {
	PK11Context     *ctx_nss;
} sha512_context;

extern void sha256_init(sha256_context *);
extern void sha256_write(sha256_context *, const unsigned char *, size_t);
extern void sha256_final(unsigned char *, sha256_context *);

extern void sha384_init(sha384_context *);
extern void sha384_write(sha384_context *, const unsigned char *, size_t);
extern void sha384_final(unsigned char *, sha384_context *);

extern void sha512_init(sha512_context *);
extern void sha512_write(sha512_context *, const unsigned char *, size_t);
extern void sha512_final(unsigned char *, sha512_context *);

#endif /* _SHA2_H */
