/*
 * Definitions relevant to IPSEC transformations
 * Copyright (C) 1996, 1997  John Ioannidis.
 * Copyright (C) 1998, 1999, 2000, 2001  Richard Guy Briggs.
 * COpyright (C) 2003  Michael Richardson <mcr@sandelman.ottawa.on.ca>
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
 * RCSID $Id: ipsec_xform.h,v 1.41 2004/07/10 19:08:41 mcr Exp $
 */

#ifndef _IPSEC_XFORM_H_

#include <openswan.h>

#define XF_NONE			0	/* No transform set */
#define XF_IP4			1	/* IPv4 inside IPv4 */
#define XF_AHMD5		2	/* AH MD5 */
#define XF_AHSHA		3	/* AH SHA */
#define XF_ESP3DES		5	/* ESP DES3-CBC */
#define XF_AHHMACMD5		6	/* AH-HMAC-MD5 with opt replay prot */
#define XF_AHHMACSHA1		7	/* AH-HMAC-SHA1 with opt replay prot */
#define XF_ESP3DESMD5		9	/* triple DES, HMAC-MD-5, 128-bits of authentication */
#define	XF_ESP3DESMD596		10	/* triple DES, HMAC-MD-5, 96-bits of authentication */
#define	XF_ESPNULLMD596		12	/* NULL, HMAC-MD-5 with 96-bits of authentication */
#define	XF_ESPNULLSHA196	13	/* NULL, HMAC-SHA-1 with 96-bits of authentication */
#define	XF_ESP3DESSHA196	14	/* triple DES, HMAC-SHA-1, 96-bits of authentication */
#define XF_IP6			15	/* IPv6 inside IPv6 */
#define XF_COMPDEFLATE		16	/* IPCOMP deflate */

#define XF_CLR			126	/* Clear SA table */
#define XF_DEL			127	/* Delete SA */

/* IPsec AH transform values
 * RFC 2407
 * draft-ietf-ipsec-doi-tc-mib-02.txt
 */

#define AH_NONE			0
#define AH_MD5			2
#define AH_SHA			3
/* draft-ietf-ipsec-ciph-aes-cbc-03.txt */
#define AH_SHA2_256		5
#define AH_SHA2_384		6
#define AH_SHA2_512		7
#define AH_RIPEMD		8
#define AH_MAX			15

/* IPsec ESP transform values */

#define ESP_NONE		0
#define ESP_DES			2
#define ESP_3DES		3
#define ESP_RC5			4
#define ESP_IDEA		5
#define ESP_CAST		6
#define ESP_BLOWFISH		7
#define ESP_3IDEA		8
#define ESP_RC4			10
#define ESP_NULL		11
#define ESP_AES			12

/* as draft-ietf-ipsec-ciph-aes-cbc-02.txt */
#define ESP_MARS		249
#define	ESP_RC6			250
#define ESP_SERPENT		252
#define ESP_TWOFISH		253
			 
/* IPCOMP transform values */

#define IPCOMP_NONE		0
#define IPCOMP_OUI		1
#define IPCOMP_DEFLAT		2
#define IPCOMP_LZS		3
#define IPCOMP_V42BIS		4

#define XFT_AUTH		0x0001
#define XFT_CONF		0x0100

/* available if CONFIG_KLIPS_DEBUG is defined */
#define DB_XF_INIT		0x0001

#define PROTO2TXT(x) \
	(x) == IPPROTO_AH ? "AH" : \
	(x) == IPPROTO_ESP ? "ESP" : \
	(x) == IPPROTO_IPIP ? "IPIP" : \
	(x) == IPPROTO_COMP ? "COMP" : \
	"UNKNOWN_proto"
static inline const char *enc_name_id (unsigned id) {
	static char buf[16];
	snprintf(buf, sizeof(buf), "_ID%d", id);
	return buf;
}
static inline const char *auth_name_id (unsigned id) {
	static char buf[16];
	snprintf(buf, sizeof(buf), "_ID%d", id);
	return buf;
}
#define IPS_XFORM_NAME(x) \
	PROTO2TXT((x)->ips_said.proto), \
	(x)->ips_said.proto == IPPROTO_COMP ? \
		((x)->ips_encalg == SADB_X_CALG_DEFLATE ? \
		 "_DEFLATE" : "_UNKNOWN_comp") : \
	(x)->ips_encalg == ESP_NONE ? "" : \
	(x)->ips_encalg == ESP_3DES ? "_3DES" : \
	(x)->ips_encalg == ESP_AES ? "_AES" : \
	(x)->ips_encalg == ESP_SERPENT ? "_SERPENT" : \
	(x)->ips_encalg == ESP_TWOFISH ? "_TWOFISH" : \
	enc_name_id(x->ips_encalg)/* "_UNKNOWN_encr" */, \
	(x)->ips_authalg == AH_NONE ? "" : \
	(x)->ips_authalg == AH_MD5 ? "_HMAC_MD5" : \
	(x)->ips_authalg == AH_SHA ? "_HMAC_SHA1" : \
	(x)->ips_authalg == AH_SHA2_256 ? "_HMAC_SHA2_256" : \
	(x)->ips_authalg == AH_SHA2_384 ? "_HMAC_SHA2_384" : \
	(x)->ips_authalg == AH_SHA2_512 ? "_HMAC_SHA2_512" : \
	auth_name_id(x->ips_authalg) /* "_UNKNOWN_auth" */ \

#ifdef __KERNEL__
struct ipsec_rcv_state;
struct ipsec_xmit_state;

struct xform_functions {
	enum ipsec_rcv_value (*rcv_checks)(struct ipsec_rcv_state *irs,
				       struct sk_buff *skb);
        enum ipsec_rcv_value (*rcv_decrypt)(struct ipsec_rcv_state *irs);

	enum ipsec_rcv_value (*rcv_setup_auth)(struct ipsec_rcv_state *irs,
					   struct sk_buff *skb,
					   __u32          *replay,
					   unsigned char **authenticator);
	enum ipsec_rcv_value (*rcv_calc_auth)(struct ipsec_rcv_state *irs,
					struct sk_buff *skb);

  	enum ipsec_xmit_value (*xmit_setup)(struct ipsec_xmit_state *ixs);
        enum ipsec_xmit_value (*xmit_encrypt)(struct ipsec_xmit_state *ixs);

	enum ipsec_xmit_value (*xmit_setup_auth)(struct ipsec_xmit_state *ixs,
					   struct sk_buff *skb,
					   __u32          *replay,
					   unsigned char **authenticator);
	enum ipsec_xmit_value (*xmit_calc_auth)(struct ipsec_xmit_state *ixs,
					struct sk_buff *skb);
        int  xmit_headroom;
	int  xmit_needtailroom;
};

#endif /* __KERNEL__ */

#ifdef CONFIG_KLIPS_DEBUG
extern void ipsec_dmp(char *s, caddr_t bb, int len);
#else /* CONFIG_KLIPS_DEBUG */
#define ipsec_dmp(_x, _y, _z) 
#endif /* CONFIG_KLIPS_DEBUG */


#define _IPSEC_XFORM_H_
#endif /* _IPSEC_XFORM_H_ */

/*
 * $Log: ipsec_xform.h,v $
 * Revision 1.41  2004/07/10 19:08:41  mcr
 * 	CONFIG_IPSEC -> CONFIG_KLIPS.
 *
 * Revision 1.40  2004/04/06 02:49:08  mcr
 * 	pullup of algo code from alg-branch.
 *
 * Revision 1.39  2004/04/05 19:55:07  mcr
 * Moved from linux/include/freeswan/ipsec_xform.h,v
 *
 * Revision 1.38  2004/04/05 19:41:05  mcr
 * 	merged alg-branch code.
 *
 * Revision 1.37  2003/12/13 19:10:16  mcr
 * 	refactored rcv and xmit code - same as FS 2.05.
 *
 * Revision 1.36.34.1  2003/12/22 15:25:52  jjo
 *      Merged algo-0.8.1-rc11-test1 into alg-branch
 *
 * Revision 1.36  2002/04/24 07:36:48  mcr
 * Moved from ./klips/net/ipsec/ipsec_xform.h,v
 *
 * Revision 1.35  2001/11/26 09:23:51  rgb
 * Merge MCR's ipsec_sa, eroute, proc and struct lifetime changes.
 *
 * Revision 1.33.2.1  2001/09/25 02:24:58  mcr
 * 	struct tdb -> struct ipsec_sa.
 * 	sa(tdb) manipulation functions renamed and moved to ipsec_sa.c
 * 	ipsec_xform.c removed. header file still contains useful things.
 *
 * Revision 1.34  2001/11/06 19:47:17  rgb
 * Changed lifetime_packets to uint32 from uint64.
 *
 * Revision 1.33  2001/09/08 21:13:34  rgb
 * Added pfkey ident extension support for ISAKMPd. (NetCelo)
 *
 * Revision 1.32  2001/07/06 07:40:01  rgb
 * Reformatted for readability.
 * Added inbound policy checking fields for use with IPIP SAs.
 *
 * Revision 1.31  2001/06/14 19:35:11  rgb
 * Update copyright date.
 *
 * Revision 1.30  2001/05/30 08:14:03  rgb
 * Removed vestiges of esp-null transforms.
 *
 * Revision 1.29  2001/01/30 23:42:47  rgb
 * Allow pfkey msgs from pid other than user context required for ACQUIRE
 * and subsequent ADD or UDATE.
 *
 * Revision 1.28  2000/11/06 04:30:40  rgb
 * Add Svenning's adaptive content compression.
 *
 * Revision 1.27  2000/09/19 00:38:25  rgb
 * Fixed algorithm name bugs introduced for ipcomp.
 *
 * Revision 1.26  2000/09/17 21:36:48  rgb
 * Added proto2txt macro.
 *
 * Revision 1.25  2000/09/17 18:56:47  rgb
 * Added IPCOMP support.
 *
 * Revision 1.24  2000/09/12 19:34:12  rgb
 * Defined XF_IP6 from Gerhard for ipv6 tunnel support.
 *
 * Revision 1.23  2000/09/12 03:23:14  rgb
 * Cleaned out now unused tdb_xform and tdb_xdata members of struct tdb.
 *
 * Revision 1.22  2000/09/08 19:12:56  rgb
 * Change references from DEBUG_IPSEC to CONFIG_IPSEC_DEBUG.
 *
 * Revision 1.21  2000/09/01 18:32:43  rgb
 * Added (disabled) sensitivity members to tdb struct.
 *
 * Revision 1.20  2000/08/30 05:31:01  rgb
 * Removed all the rest of the references to tdb_spi, tdb_proto, tdb_dst.
 * Kill remainder of tdb_xform, tdb_xdata, xformsw.
 *
 * Revision 1.19  2000/08/01 14:51:52  rgb
 * Removed _all_ remaining traces of DES.
 *
 * Revision 1.18  2000/01/21 06:17:45  rgb
 * Tidied up spacing.
 *
 *
 * Local variables:
 * c-file-style: "linux"
 * End:
 *
 */
