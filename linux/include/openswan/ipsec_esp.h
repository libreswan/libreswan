/*
 * Copyright (C) 1996, 1997  John Ioannidis.
 * Copyright (C) 1998, 1999, 2000, 2001  Richard Guy Briggs.
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * RCSID $Id: ipsec_esp.h,v 1.28 2004/09/13 02:22:10 mcr Exp $
 */

#include "openswan/ipsec_md5h.h"
#include "openswan/ipsec_sha1.h"

#include "crypto/des.h"

#ifndef IPPROTO_ESP
#define IPPROTO_ESP 50
#endif /* IPPROTO_ESP */

#define ESP_HEADER_LEN		8	/* 64 bits header (spi+rpl)*/

#define EMT_ESPDESCBC_ULEN	20	/* coming from user mode */
#define EMT_ESPDES_KMAX		64	/* 512 bit secret key enough? */
#define EMT_ESPDES_KEY_SZ	8	/* 56 bit secret key with parity = 64 bits */
#define EMT_ESP3DES_KEY_SZ	24	/* 168 bit secret key with parity = 192 bits */
#define EMT_ESPDES_IV_SZ	8	/* IV size */
#define ESP_DESCBC_BLKLEN       8       /* DES-CBC block size */

#define ESP_IV_MAXSZ		16	/* This is _critical_ */
#define ESP_IV_MAXSZ_INT	(ESP_IV_MAXSZ/sizeof(int))

#define DB_ES_PKTRX	0x0001
#define DB_ES_PKTRX2	0x0002
#define DB_ES_IPSA	0x0010
#define DB_ES_XF	0x0020
#define DB_ES_IPAD	0x0040
#define DB_ES_INAU	0x0080
#define DB_ES_OINFO	0x0100
#define DB_ES_OINFO2	0x0200
#define DB_ES_OH	0x0400
#define DB_ES_REPLAY	0x0800

#ifdef __KERNEL__
struct des_eks {
	des_key_schedule ks;
};

#ifndef CONFIG_XFRM_ALTERNATE_STACK
extern struct inet_protocol esp_protocol;
#endif /* CONFIG_XFRM_ALTERNATE_STACK */

struct options;

struct esphdr
{
	__u32	esp_spi;		/* Security Parameters Index */
        __u32   esp_rpl;                /* Replay counter */
	__u8	esp_iv[8];		/* iv */
};

extern struct xform_functions esp_xform_funcs[];

#ifdef CONFIG_KLIPS_DEBUG
extern int debug_esp;
#endif /* CONFIG_KLIPS_DEBUG */
#endif /* __KERNEL__ */

/*
 * $Log: ipsec_esp.h,v $
 * Revision 1.28  2004/09/13 02:22:10  mcr
 * 	#define inet_protocol if necessary.
 *
 * Revision 1.27  2004/09/06 18:35:41  mcr
 * 	2.6.8.1 gets rid of inet_protocol->net_protocol compatibility,
 * 	so adjust for that.
 *
 * Revision 1.26  2004/07/10 19:08:41  mcr
 * 	CONFIG_IPSEC -> CONFIG_KLIPS.
 *
 * Revision 1.25  2004/04/06 02:49:08  mcr
 * 	pullup of algo code from alg-branch.
 *
 * Revision 1.24  2004/04/05 19:55:05  mcr
 * Moved from linux/include/freeswan/ipsec_esp.h,v
 *
 * Revision 1.23  2004/04/05 19:41:05  mcr
 * 	merged alg-branch code.
 *
 * Revision 1.22  2003/12/13 19:10:16  mcr
 * 	refactored rcv and xmit code - same as FS 2.05.
 *
 * Revision 1.23  2003/12/11 20:14:58  mcr
 * 	refactored the xmit code, to move all encapsulation
 * 	code into protocol functions. Note that all functions
 * 	are essentially done by a single function, which is probably
 * 	wrong.
 * 	the rcv_functions structures are renamed xform_functions.
 *
 * Revision 1.22  2003/12/06 21:21:19  mcr
 * 	split up receive path into per-transform files, for
 * 	easier later removal.
 *
 * Revision 1.21.8.1  2003/12/22 15:25:52  jjo
 *      Merged algo-0.8.1-rc11-test1 into alg-branch
 *
 * Revision 1.21  2003/02/06 02:21:34  rgb
 *
 * Moved "struct auth_alg" from ipsec_rcv.c to ipsec_ah.h .
 * Changed "struct ah" to "struct ahhdr" and "struct esp" to "struct esphdr".
 * Removed "#ifdef INBOUND_POLICY_CHECK_eroute" dead code.
 *
 * Revision 1.20  2002/05/14 02:37:02  rgb
 * Change reference from _TDB to _IPSA.
 *
 * Revision 1.19  2002/04/24 07:55:32  mcr
 * 	#include patches and Makefiles for post-reorg compilation.
 *
 * Revision 1.18  2002/04/24 07:36:46  mcr
 * Moved from ./klips/net/ipsec/ipsec_esp.h,v
 *
 * Revision 1.17  2002/02/20 01:27:07  rgb
 * Ditched a pile of structs only used by the old Netlink interface.
 *
 * Revision 1.16  2001/12/11 02:35:57  rgb
 * Change "struct net_device" to "struct device" for 2.2 compatibility.
 *
 * Revision 1.15  2001/11/26 09:23:48  rgb
 * Merge MCR's ipsec_sa, eroute, proc and struct lifetime changes.
 *
 * Revision 1.14.2.3  2001/10/23 04:16:42  mcr
 * 	get definition of des_key_schedule from des.h
 *
 * Revision 1.14.2.2  2001/10/22 20:33:13  mcr
 * 	use "des_key_schedule" structure instead of cooking our own.
 *
 * Revision 1.14.2.1  2001/09/25 02:18:25  mcr
 * 	replace "struct device" with "struct netdevice"
 *
 * Revision 1.14  2001/06/14 19:35:08  rgb
 * Update copyright date.
 *
 * Revision 1.13  2000/09/08 19:12:56  rgb
 * Change references from DEBUG_IPSEC to CONFIG_IPSEC_DEBUG.
 *
 * Revision 1.12  2000/08/01 14:51:50  rgb
 * Removed _all_ remaining traces of DES.
 *
 * Revision 1.11  2000/01/10 16:36:20  rgb
 * Ditch last of EME option flags, including initiator.
 *
 *
 */
