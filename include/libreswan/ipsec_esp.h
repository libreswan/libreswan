/*
 * Copyright (C) 1996, 1997  John Ioannidis.
 * Copyright (C) 1998, 1999, 2000, 2001  Richard Guy Briggs.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#include "libreswan/ipsec_md5h.h"
#include "libreswan/ipsec_sha1.h"

#include "klips-crypto/des.h"

#ifndef IPPROTO_ESP
#define IPPROTO_ESP 50
#endif /* IPPROTO_ESP */

#define ESP_HEADER_LEN          8       /* 64 bits header (spi+rpl)*/

#define EMT_ESPDESCBC_ULEN      20      /* coming from user mode */
#define EMT_ESPDES_KMAX         64      /* 512 bit secret key enough? */
#define EMT_ESPDES_KEY_SZ       8       /* 56 bit secret key with parity = 64 bits */
#define EMT_ESP3DES_KEY_SZ      24      /* 168 bit secret key with parity = 192 bits */
#define EMT_ESPDES_IV_SZ        8       /* IV size */
#define ESP_DESCBC_BLKLEN       8       /* DES-CBC block size */

#define ESP_IV_MAXSZ            16      /* This is _critical_ */
#define ESP_IV_MAXSZ_INT        (ESP_IV_MAXSZ / sizeof(int))

#define DB_ES_PKTRX     0x0001
#define DB_ES_PKTRX2    0x0002
#define DB_ES_IPSA      0x0010
#define DB_ES_XF        0x0020
#define DB_ES_IPAD      0x0040
#define DB_ES_INAU      0x0080
#define DB_ES_OINFO     0x0100
#define DB_ES_OINFO2    0x0200
#define DB_ES_OH        0x0400
#define DB_ES_REPLAY    0x0800

#ifdef __KERNEL__
struct des_eks {
	des_key_schedule ks;
};

#ifndef CONFIG_XFRM_ALTERNATE_STACK
extern struct inet_protocol esp_protocol;
extern struct inet6_protocol esp6_protocol;
#endif /* CONFIG_XFRM_ALTERNATE_STACK */

struct options;

struct esphdr {
	__u32 esp_spi;                  /* Security Parameters Index */
	__u32 esp_rpl;                  /* Replay counter */
	__u8 esp_iv[8];                 /* iv */
};

extern struct xform_functions esp_xform_funcs[];

extern enum ipsec_rcv_value ipsec_rcv_esp_post_decrypt(
	struct ipsec_rcv_state *irs);

extern int debug_esp;
#endif /* __KERNEL__ */

