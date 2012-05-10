#ifndef _SHA1_H_
#define _SHA1_H_

/*
SHA-1 in C
By Steve Reid <steve@edmweb.com>
100% Public Domain
*/

#include <nss.h>
#include <pk11pub.h>

typedef struct {
    PK11Context* ctx_nss;
} SHA1_CTX;

void SHA1Transform(u_int32_t state[5], const unsigned char buffer[64]);
void SHA1Init(SHA1_CTX* context);
void SHA1Update(SHA1_CTX* context, const unsigned char* data, u_int32_t len);
void SHA1Final(unsigned char digest[20], SHA1_CTX* context);

#endif /* _SHA1_H_ */
