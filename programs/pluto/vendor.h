/* Libreswan ISAKMP VendorID
 *
 * Copyright (C) 2002-2003 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2005-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007 Ken Bantoft <ken@xelerance.com>
 * Copyright (C) 2008-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 Wolfgang Nothdurft <wolfgang@linogate.de>
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

#ifndef _VENDOR_H_
#define _VENDOR_H_

enum known_vendorid {
	/* 1 - 100 : Implementation names */
	VID_OPENPGP                 =1,
	VID_KAME_RACOON             =2,
	VID_MS_NT5                  =3,
	VID_SSH_SENTINEL            =4,
	VID_SSH_SENTINEL_1_1        =5,
	VID_SSH_SENTINEL_1_2        =6,
	VID_SSH_SENTINEL_1_3        =7,
	VID_SSH_IPSEC_1_1_0         =8,
	VID_SSH_IPSEC_1_1_1         =9,
	VID_SSH_IPSEC_1_1_2         =10,
	VID_SSH_IPSEC_1_2_1         =11,
	VID_SSH_IPSEC_1_2_2         =12,
	VID_SSH_IPSEC_2_0_0         =13,
	VID_SSH_IPSEC_2_1_0         =14,
	VID_SSH_IPSEC_2_1_1         =15,
	VID_SSH_IPSEC_2_1_2         =16,
	VID_SSH_IPSEC_3_0_0         =17,
	VID_SSH_IPSEC_3_0_1         =18,
	VID_SSH_IPSEC_4_0_0         =19,
	VID_SSH_IPSEC_4_0_1         =20,
	VID_SSH_IPSEC_4_1_0         =21,
	VID_SSH_IPSEC_4_2_0         =22,
	VID_CISCO_UNITY             =23,
	VID_SSH_SENTINEL_1_4        =24,
	VID_SSH_SENTINEL_1_4_1      =25,
	VID_TIMESTEP                =26,
	VID_FSWAN_2_00_VID          =27,
	VID_FSWAN_2_00_X509_1_3_1_VID =28,
	VID_FSWAN_2_00_X509_1_3_1_LDAP_VID =29,
	VID_SAFENET               =30,
	VID_NORTEL                =31,
	VID_LIBRESWAN1                    =32,
	VID_LIBRESWAN2                    =33,
	VID_MACOSX                =34,
	VID_CISCO3K               =35,
	VID_LIBRESWANSELF         =36,
	VID_NCP                   =37,
	VID_CISCO_IOS             =38,
	VID_SONICWALL_1           =39,
	VID_SONICWALL_2           =40,
	VID_CISCO_IKE_FRAGMENTATION=41,
	VID_SHREWSOFT             =42,
	VID_NETSCREEN_01          =43,
	VID_NETSCREEN_02          =44,
	VID_NETSCREEN_03          =45,
	VID_NETSCREEN_04          =46,
	VID_NETSCREEN_05          =47,
	VID_NETSCREEN_06          =48,
	VID_NETSCREEN_07          =49,
	VID_NETSCREEN_08          =50,
	VID_NETSCREEN_09          =51,
	VID_NETSCREEN_10          =52,
	VID_NETSCREEN_11          =53,
	VID_NETSCREEN_12          =54,
	VID_NETSCREEN_13          =55,
	VID_NETSCREEN_14          =56,
	VID_NETSCREEN_15          =57,
	VID_NETSCREEN_16          =58,
	VID_ZYWALL                =59,
	VID_SIDEWINDER            =60,
	VID_WATCHGUARD            =61,
	VID_LUCENT_GW9            =62,
	VID_LUCENT_CL7            =63,
	VID_CISCO_UNITY_FWTYPE    =64,
	VID_CHECKPOINT            =65,
	VID_GSSAPI                =66,
	VID_GSSAPILONG            =67,

	/* 101 - 150 : NAT-Traversal */
	VID_NATT_STENBERG_01       =101,
	VID_NATT_STENBERG_02       =102,
	VID_NATT_HUTTUNEN          =103,
	VID_NATT_HUTTUNEN_ESPINUDP =104,
	VID_NATT_IETF_00           =105,
	VID_NATT_IETF_01           =106,
	VID_NATT_IETF_02_N         =107,
	VID_NATT_IETF_02           =108,
	VID_NATT_IETF_03           =109,
	VID_NATT_IETF_04           =110,
	VID_NATT_IETF_05           =111,
	VID_NATT_IETF_06           =112,
	VID_NATT_IETF_07           =113,
	VID_NATT_IETF_08           =114,
	VID_NATT_DRAFT_IETF_IPSEC_NAT_T_IKE =115,
	VID_NATT_RFC               =116,

/* World of Microsoft */
	VID_VISTA_AUTHIP          =125,
	VID_VISTA_AUTHIP2         =126,
	VID_VISTA_AUTHIP3         =127,

/* 125 - 200 Strongswan */

	VID_STRONGSWAN                = 126,
	VID_STRONGSWAN_2_2_0          = 127,
	VID_STRONGSWAN_2_2_1          = 128,
	VID_STRONGSWAN_2_2_2          = 129,
	VID_STRONGSWAN_2_3_0          = 130,
	VID_STRONGSWAN_2_3_1          = 131,
	VID_STRONGSWAN_2_3_2          = 132,
	VID_STRONGSWAN_2_4_0          = 133,
	VID_STRONGSWAN_2_4_1          = 134,
	VID_STRONGSWAN_2_4_2          = 135,
	VID_STRONGSWAN_2_4_3          = 136,
	VID_STRONGSWAN_2_4_4          = 137,
	VID_STRONGSWAN_2_5_0          = 138,
	VID_STRONGSWAN_2_5_1          = 139,
	VID_STRONGSWAN_2_5_2          = 140,
	VID_STRONGSWAN_2_5_3          = 141,
	VID_STRONGSWAN_2_5_4          = 142,
	VID_STRONGSWAN_2_5_5          = 143,
	VID_STRONGSWAN_2_5_6          = 144,
	VID_STRONGSWAN_2_5_7          = 145,
	VID_STRONGSWAN_2_6_0          = 146,
	VID_STRONGSWAN_2_6_1          = 147,
	VID_STRONGSWAN_2_6_2          = 148,
	VID_STRONGSWAN_2_6_3          = 149,
	VID_STRONGSWAN_2_6_4          = 150,
	VID_STRONGSWAN_2_7_0          = 151,
	VID_STRONGSWAN_2_7_1          = 152,
	VID_STRONGSWAN_2_7_2          = 153,
	VID_STRONGSWAN_2_7_3          = 154,
	VID_STRONGSWAN_2_8_0          = 155,
	VID_STRONGSWAN_2_8_1          = 156,
	VID_STRONGSWAN_2_8_2          = 157,
	VID_STRONGSWAN_2_8_3          = 158,
	VID_STRONGSWAN_2_8_4          = 159,
	VID_STRONGSWAN_2_8_5          = 160,
	VID_STRONGSWAN_2_8_6          = 161,
	VID_STRONGSWAN_2_8_7          = 162,
	VID_STRONGSWAN_2_8_8          = 163,

	VID_STRONGSWAN_4_0_0          = 170,
	VID_STRONGSWAN_4_0_1          = 171,
	VID_STRONGSWAN_4_0_2          = 172,
	VID_STRONGSWAN_4_0_3          = 173,
	VID_STRONGSWAN_4_0_4          = 174,
	VID_STRONGSWAN_4_0_5          = 175,
	VID_STRONGSWAN_4_0_6          = 176,
	VID_STRONGSWAN_4_0_7          = 177,
	VID_STRONGSWAN_4_1_0          = 178,
	VID_STRONGSWAN_4_1_1          = 179,
	VID_STRONGSWAN_4_1_2          = 180,
	VID_STRONGSWAN_4_1_3          = 181,
	VID_STRONGSWAN_4_1_4          = 182,
	VID_STRONGSWAN_4_1_5          = 183,
	VID_STRONGSWAN_4_1_6          = 184,
	VID_STRONGSWAN_4_1_7          = 185,
	VID_STRONGSWAN_4_1_8          = 186,
	VID_STRONGSWAN_4_1_9          = 187,
	VID_STRONGSWAN_4_1_10         = 188,
	VID_STRONGSWAN_4_1_11         = 189,
	VID_STRONGSWAN_4_2_0          = 190,
	VID_STRONGSWAN_4_2_1          = 191,
	VID_STRONGSWAN_4_2_2          = 192,
	VID_STRONGSWAN_4_2_3          = 193,
/*
   While searching (strings) in /usr/sbin/racoon on Max OS X 10.3.3, I found it :
 # echo -n "draft-ietf-ipsec-nat-t-ike" | md5sum
   4df37928e9fc4fd1b3262170d515c662
   But this VID has not been seen in any IETF drafts. (mlafon)

 */

	/* 201 - 300 : Misc */
	VID_MISC_XAUTH             =201,
	VID_MISC_DPD               =202,
	VID_MISC_HEARTBEAT_NOTIFY  =203,
	VID_IKE_FRAGMENTATION      =204,
	VID_INITIAL_CONTACT        =205,
	VID_MISC_IKEv2             =206,
	VID_DPD1_NG                =207,
};

void init_vendorid(void);

struct msg_digest;
void handle_vendorid(struct msg_digest *md, const char *vid, size_t len,
		     struct state *st);

bool out_vid(u_int8_t np, pb_stream *outs, unsigned int vid);

#endif /* _VENDOR_H_ */

