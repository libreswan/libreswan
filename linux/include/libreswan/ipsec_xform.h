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
 */

#ifndef _IPSEC_XFORM_H_

#include <libreswan.h>

#define XF_NONE                 0       /* No transform set */
#define XF_IP4                  1       /* IPv4 inside IPv4 */
#define XF_AHMD5                2       /* AH MD5 */
#define XF_AHSHA                3       /* AH SHA */
#define XF_ESP3DES              5       /* ESP DES3-CBC */
#define XF_AHHMACMD5            6       /* AH-HMAC-MD5 with opt replay prot */
#define XF_AHHMACSHA1           7       /* AH-HMAC-SHA1 with opt replay prot */
#define XF_ESP3DESMD5           9       /* triple DES, HMAC-MD-5, 128-bits of authentication */
#define XF_ESP3DESMD596         10      /* triple DES, HMAC-MD-5, 96-bits of authentication */
#define XF_ESPNULLMD596         12      /* NULL, HMAC-MD-5 with 96-bits of authentication */
#define XF_ESPNULLSHA196        13      /* NULL, HMAC-SHA-1 with 96-bits of authentication */
#define XF_ESP3DESSHA196        14      /* triple DES, HMAC-SHA-1, 96-bits of authentication */
#define XF_IP6                  15      /* IPv6 inside IPv6 */
#define XF_COMPDEFLATE          16      /* IPCOMP deflate */
#define XF_COMPLZS              17      /* IPCOMP LZS */

#define XF_CLR                  126     /* Clear SA table */
#define XF_DEL                  127     /* Delete SA */

/* IPsec AH transform values
 * RFC 2407
 * draft-ietf-ipsec-doi-tc-mib-02.txt
 */

/* why are these hardcoded here? See ipsec_policy.h for their enums -- Paul*/
/* ---------- These really need to go from here ------------------ */
#define AH_NONE                 0
#define AH_MD5                  2
#define AH_SHA                  3
/* draft-ietf-ipsec-ciph-aes-cbc-03.txt */
#define AH_SHA2_256             5
#define AH_SHA2_384             6
#define AH_SHA2_512             7
#define AH_RIPEMD               8
#define AH_AES                  9
#define AH_RSA                  10      /* RFC4359 */
#define AH_AES_128_GMAC         11      /* RFC4543 [Errata1821] */
#define AH_AES_192_GMAC         12      /* RFC4543 [Errata1821] */
#define AH_AES_256_GMAC         13      /* RFC4543 [Errata1821] */
#define AH_NULL                 251
#define AH_SHA2_256_TRUNC       252     /* used for broken linux kernel behaviour */
#define AH_MAX                  255     /* note Authentication Algorithm (Value 5) Reference: [RFC2407] has
					 * two octets but IPSEC AH Transform Identifiers has one octet!
					 */

/* IPsec ESP transform values */

#define ESP_NONE                0
#define ESP_DES_IV64            1
#define ESP_DES                 2 /* obsoleted */
#define ESP_3DES                3
#define ESP_RC5                 4
#define ESP_IDEA                5
#define ESP_CAST                6
#define ESP_BLOWFISH            7 /* obsoleted */
#define ESP_3IDEA               8
#define ESP_DES_IV32            9
#define ESP_RC4                 10
#define ESP_NULL                11
#define ESP_AES                 12 /* was draft-ietf-ipsec-ciph-aes-cbc-02.txt, now RFC-3602 */
#define ESP_AES_CTR             13
#define ESP_AES_CCM_A           14
#define ESP_AES_CCM_B           15
#define ESP_AES_CCM_C           16
#define ESP_ID17_UNASSIGNED     17
#define ESP_AES_GCM_A           18
#define ESP_AES_GCM_B           19
#define ESP_AES_GCM_C           20
#define ESP_SEED_CBC            21
#define ESP_CAMELLIA            22
#define ESP_NULL_AUTH_AES_GMAC  23 /* [RFC4543][Errata1821] */
/* 24 - 248 Unassigned */
#define ESP_MARS                249
#define ESP_RC6                 250
#define ESP_SERPENT             252
#define ESP_TWOFISH             253

#define ESP_MAX                 255 /* one octet, not two */

/* IPCOMP transform values */

#define IPCOMP_NONE             0
#define IPCOMP_OUI              1
#define IPCOMP_DEFLATE          2
#define IPCOMP_LZS              3
#define IPCOMP_V42BIS           4

#define XFT_AUTH                0x0001
#define XFT_CONF                0x0100

#define PROTO2TXT(x) \
	(x) == IPPROTO_AH ? "AH" : \
	(x) == IPPROTO_ESP ? "ESP" : \
	(x) == IPPROTO_IPIP ? "IPIP" : \
	(x) == IPPROTO_COMP ? "COMP" : \
	"UNKNOWN_proto"

/* BEWARE: result may be in a static buffer */
static inline const char *enc_name_id(unsigned id)
{
	static char buf[16];

	snprintf(buf, sizeof(buf), "_ID%d", id);
	return buf;
}

/* BEWARE: result may be in a static buffer */
static inline const char *auth_name_id(unsigned id)
{
	static char buf[16];

	snprintf(buf, sizeof(buf), "_ID%d", id);
	return buf;
}
#define IPS_XFORM_NAME(x) \
	PROTO2TXT((x)->ips_said.proto), \
	(x)->ips_said.proto == IPPROTO_COMP ? \
	((x)->ips_encalg == SADB_X_CALG_NONE ? "_NONE" :       \
	 (x)->ips_encalg == SADB_X_CALG_DEFLATE ? "_DEFLATE" :  \
	 (x)->ips_encalg == SADB_X_CALG_LZS ? "_LZS" :         \
	 "_UNKNOWN_comp") :                                     \
	(x)->ips_encalg == ESP_NONE ? "" : \
	(x)->ips_encalg == ESP_NULL ? "_NULL" : \
	/* ESP_DES left out on purpose */ \
	(x)->ips_encalg == ESP_3DES ? "_3DES" : \
	(x)->ips_encalg == ESP_AES ? "_AES" : \
	(x)->ips_encalg == ESP_SERPENT ? "_SERPENT" : \
	(x)->ips_encalg == ESP_TWOFISH ? "_TWOFISH" : \
	enc_name_id((x)->ips_encalg) /* "_UNKNOWN_encr" */, \
	(x)->ips_authalg == AH_NONE ? "" : \
	(x)->ips_authalg == AH_MD5 ? "_HMAC_MD5" : \
	(x)->ips_authalg == AH_SHA ? "_HMAC_SHA1" : \
	(x)->ips_authalg == AH_SHA2_256 ? "_HMAC_SHA2_256" : \
	(x)->ips_authalg == AH_SHA2_384 ? "_HMAC_SHA2_384" : \
	(x)->ips_authalg == AH_SHA2_512 ? "_HMAC_SHA2_512" : \
	auth_name_id((x)->ips_authalg) /* "_UNKNOWN_auth" */ \

#ifdef __KERNEL__
#include <linux/skbuff.h>

struct ipsec_rcv_state;
struct ipsec_xmit_state;

struct xform_functions {
	u8 protocol;
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
	int xmit_headroom;
	int xmit_needtailroom;
};

#endif /* __KERNEL__ */

extern void ipsec_dmp(char *s, caddr_t bb, int len);

#define _IPSEC_XFORM_H_
#endif /* _IPSEC_XFORM_H_ */
