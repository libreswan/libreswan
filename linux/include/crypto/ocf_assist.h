#ifndef _OCF_ASSIST_H
#define _OCF_ASSIST_H 1
/****************************************************************************/
/* The various hw_assist functions return these bits */

#define OCF_PROVIDES_AES		0x0001
#define OCF_PROVIDES_DES_3DES	0x0002

/****************************************************************************/
#if !defined(OCF_ASSIST)
/****************************************************************************/
/*
 *	stub it all out just in case
 */

#define ocf_aes_assist() (0)
#define ocf_aes_set_key(a1,a2,a3,a4) 
#define ocf_aes_cbc_encrypt(a1,a2,a3,a4,a5,a6)

#define ocf_des_assist() (0)
#define ocf_des_set_key(a, b)
#define ocf_des_cbc_encrypt(a1,a2,a3,a4,a5,a6)
#define ocf_des_encrypt(a1,a2,a3)
#define ocf_des_ede3_cbc_encrypt(a1,a2,a3,a4,a5,a6,a7,a8)
#define ocf_des_ncbc_encrypt(a1,a2,a3,a4,a5,a6)
#define ocf_des_ecb_encrypt(a1,a2,a3,a4)

/****************************************************************************/
#else
/****************************************************************************/

#include <sys/types.h>
#include "aes.h"
#include "des.h"

extern int	ocf_aes_assist(void);
extern void	ocf_aes_set_key(aes_context *cx, const unsigned char in_key[],
								int n_bytes, const int f);
extern int	ocf_aes_cbc_encrypt(aes_context *ctx, unsigned char *input,
				    unsigned char *output,
				    long length,
				    unsigned char *ivec, int enc);

extern int	ocf_des_assist(void);
extern int	ocf_des_set_key(des_cblock *key, des_key_schedule schedule);
extern void	ocf_des_cbc_encrypt(des_cblock *input, des_cblock *output,
								long length, des_key_schedule schedule,
								des_cblock *ivec, int enc);
extern void	ocf_des_encrypt(DES_LONG *data, des_key_schedule ks, int enc);
extern void	ocf_des_ede3_cbc_encrypt(des_cblock *input, des_cblock *output,
								long length, des_key_schedule ks1,
								des_key_schedule ks2, des_key_schedule ks3,
								des_cblock *ivec, int enc);
extern void	ocf_des_ncbc_encrypt(des_cblock *input, des_cblock *output,
								long length, des_key_schedule schedule,
								des_cblock *ivec, int enc);
extern void	ocf_des_ecb_encrypt(des_cblock *input, des_cblock *output,
								des_key_schedule ks, int enc);

/****************************************************************************/
#endif /* !defined(OCF_ASSIST) */
/****************************************************************************/
#endif /* _OCF_ASSIST_H */
