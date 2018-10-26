/*
 * Here is the original comment from the distribution:

   SHA-1 in C
   By Steve Reid <steve@edmweb.com>
   100% Public Domain

 * Adapted for use by the IPSEC code by John Ioannidis
 */

#ifndef _IPSEC_SHA1_H_
#define _IPSEC_SHA1_H_

#ifdef __KERNEL__
# include <crypto/sha.h>
#endif

typedef struct {
	__u32 state[SHA1_DIGEST_SIZE / 4];
	__u32 count[2];
	__u8 buffer[SHA1_BLOCK_SIZE];
} SHA1_CTX;

void SHA1Transform(__u32 state[5], __u8 buffer[SHA1_BLOCK_SIZE]);
void SHA1Init(void *context);
void SHA1Update(void *context, unsigned char *data, __u32 len);
void SHA1Final(unsigned char digest[SHA1_DIGEST_SIZE], void *context);

#endif /* _IPSEC_SHA1_H_ */

