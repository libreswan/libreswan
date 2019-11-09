/*
 * The rest of this file is Copyright RSA DSI. See the following comments
 * for the full Copyright notice.
 */

#ifndef _IPSEC_MD5H_H_
#define _IPSEC_MD5H_H_

/* GLOBAL.H - RSAREF types and constants
 */

/* POINTER defines a generic pointer type */
typedef __u8 *POINTER;

/* UINT4 defines a four byte word */
typedef __u32 UINT4;

/* MD5.H - header file for MD5C.C
 */

/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991.
 *
 * http://www.ietf.org/ietf-ftp/IPR/RSA-MD-all
 */

/* MD5 context. */
typedef struct {
	UINT4 state[4];                 /* state (ABCD) */
	UINT4 count[2];                 /* number of bits, modulo 2^64 (lsb first) */
	unsigned char buffer[64];       /* input buffer */
} MD5_CTX;

void osMD5Init(void *);
void osMD5Update(void *, unsigned char *, __u32);
void osMD5Final(unsigned char [16], void *);

#endif /* _IPSEC_MD5H_H_ */
