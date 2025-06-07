/* Libreswan ISAKMP VendorID Handling
 *
 * Copyright (C) 2002-2003 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2004 Xelerance Corporation
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Wolfgang Nothdurft <wolfgang@linogate.de>
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
 *
 * See also https://github.com/royhills/ike-scan/blob/master/ike-vendor-ids
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

#include <stdlib.h>	/* for NULL et.al. */

#include "lswversion.h"		/* for libreswan_vendorid */
#include "crypt_hash.h"
#include "ike_alg_hash.h"

#include "vendorid.h"
#include "lswlog.h"
#include "lswalloc.h"

/**
 * Listing of interesting but details unknown Vendor IDs:
 *
 * SafeNet SoftRemote 8.0.0:
 *  47bbe7c993f1fc13b4e6d0db565c68e5010201010201010310382e302e3020284275696c6420313029000000
 *  >> 382e302e3020284275696c6420313029 = '8.0.0 (Build 10)'
 *  da8e937880010000
 *
 * SafeNet SoftRemote 9.0.1
 *  47bbe7c993f1fc13b4e6d0db565c68e5010201010201010310392e302e3120284275696c6420313229000000
 *  >> 392e302e3120284275696c6420313229 = '9.0.1 (Build 12)'
 *  da8e937880010000
 *
 * Netscreen:
 *  d6b45f82f24bacb288af59a978830ab7
 *  cf49908791073fb46439790fdeb6aeed981101ab0000000500000300
 *
 * Cisco:
 *  1f07f70eaa6514d3b0fa96542a500100 (Cisco VPN Concentrator)
 *  1f07f70eaa6514d3b0fa96542a500300 (VPN 3000 version 3.0.0)
 *  1f07f70eaa6514d3b0fa96542a500301 (VPN 3000 version 3.0.1)
 *  1f07f70eaa6514d3b0fa96542a500305 (VPN 3000 version 3.0.5)
 *  1f07f70eaa6514d3b0fa96542a500407 (VPN 3000 version 4.0.7)
 *  (Can you see the pattern?)
 *  afcad71368a1f1c96b8696fc77570100 (Non-RFC Dead Peer Detection ?)
 *  c32364b3b4f447eb17c488ab2a480a57
 *  6d761ddc26aceca1b0ed11fabbb860c4
 *  5946c258f99a1a57b03eb9d1759e0f24 (From a Cisco VPN 3k)
 *  ebbc5b00141d0c895e11bd395902d690 (From a Cisco VPN 3k)
 *  3e984048101e66cc659fd002b0ed3655 (From a Cisco 1800 IOS device)
 *  ade1e70e9953c1328373ebf0257b85ed (From a Cisco PIX)
 *
 * Microsoft L2TP (???):
 * (This could be the MSL2TP client, which is a stripped version of SafeNet)
 *
 *  47bbe7c993f1fc13b4e6d0db565c68e5010201010201010310382e312e3020284275696c6420313029000000
 *  >> 382e312e3020284275696c6420313029 = '8.1.0 (Build 10)'
 *  3025dbd21062b9e53dc441c6aab5293600000000
 *  da8e937880010000
 *
 * 3COM-superstack
 *    da8e937880010000
 *    404bf439522ca3f6
 *
 * Nortel contivity 251 (RAS F/W Version: VA251_2.0.0.0.013 | 12/3/2003
 *   DSL FW Version: Alcatel, Version 3.9.122)
 * 4485152d18b6bbcd0be8a8469579ddcc
 * 625027749d5ab97f5616c1602765cf480a3b7d0b)
 * 424e455300000009 (Nortel Contivity)
 *
 * Zyxel Zywall 2 / Zywall 30w
 * 625027749d5ab97f5616c1602765cf480a3b7d0b
 *
 * Astaro ?
 * 7f50cc4ebf04c2d9da73abfd69b77aa2
 *
 * Solaris 10 has RF 3974 but also md5('RFC XXXX') which is 810fa565f8ab14369105d706fbd57279
 * (yes, the 'XXXX' are _really_ four times the letter X)
 *
 * Juniper, unknown vid:
 * 699369228741c6d4ca094c93e242c9de19e7b7c60000000500000500
 * 166f932d55eb64d8e4df4fd37e2313f0d0fd8451000000000000
 *
 * KAME / Apple / Mac OSX?
 *  While searching (strings) in /usr/sbin/racoon on Mac OS X 10.3.3, I found it :
 * # echo -n "draft-ietf-ipsec-nat-t-ike" | md5sum
 *  4df37928e9fc4fd1b3262170d515c662
 *  But this VID has not been seen in any IETF drafts. (mlafon)
 */

enum vid_kind {
	VID_KEEP,
	VID_MD5HASH,
	VID_STRING,
	VID_FSWAN_HASH,
	VID_SUBSTRING,
};

struct vid_struct {
	const enum known_vendorid id;
	const enum vid_kind kind;
	const char *const data;

	/* filled in at runtime: */
	const char *descr;
	shunk_t vid;
};

#define DEC_MD5_VID(ID, DATA)			\
	VID(ID, VID_MD5HASH, NULL, DATA)

#define VID(ID, KIND, DESCR, DATA)					\
	[ID] = { .id = ID, .kind = KIND, .descr = DESCR, .data = DATA, }

#define RAW(ID, KIND, DESCR, RAW_VID)					\
	[ID] = {							\
		.id = ID,						\
		.kind = KIND,						\
		.descr = DESCR,						\
		.vid = {						\
			.ptr = RAW_VID,					\
			.len = sizeof(RAW_VID) - 1 /*don't count NUL*/, \
		},							\
	}

static struct vid_struct vid_tab[] = {

	/* Implementation names */

	VID(VID_OPPORTUNISTIC, VID_STRING, NULL, "Opportunistic IPsec"),

	VID(VID_OPENPGP, VID_STRING, "OpenPGP", "OpenPGP10171"),

	VID(VID_KAME_RACOON, VID_MD5HASH, NULL, "KAME/racoon"),

	/*
	 * https://msdn.microsoft.com/en-us/library/cc233476.aspx
	 * The first few are "MS NT5 ISAKMPOAKLEY" with a version number appended
	 */
	RAW(VID_MS_WIN2K, VID_KEEP, "Windows 2000",
	    "\x1E\x2B\x51\x69\x05\x99\x1C\x7D\x7C\x96\xFC\xBF\xB5\x87\xE4\x61\x00\x00\x00\x02"),
	RAW(VID_MS_WINXP, VID_KEEP, "Windows XP",
	    "\x1E\x2B\x51\x69\x05\x99\x1C\x7D\x7C\x96\xFC\xBF\xB5\x87\xE4\x61\x00\x00\x00\x03"),
	RAW(VID_MS_WIN2003, VID_KEEP, "Windows Server 2003",
	    "\x1E\x2B\x51\x69\x05\x99\x1C\x7D\x7C\x96\xFC\xBF\xB5\x87\xE4\x61\x00\x00\x00\x04"),
	RAW(VID_MS_WINVISTA, VID_KEEP, "Windows Vista",
	    "\x1E\x2B\x51\x69\x05\x99\x1C\x7D\x7C\x96\xFC\xBF\xB5\x87\xE4\x61\x00\x00\x00\x05"),
	RAW(VID_MS_WIN2008, VID_KEEP, "Windows Server 2008",
	    "\x1E\x2B\x51\x69\x05\x99\x1C\x7D\x7C\x96\xFC\xBF\xB5\x87\xE4\x61\x00\x00\x00\x06"),
	RAW(VID_MS_WIN7, VID_KEEP, "Windows 7",
	    "\x1E\x2B\x51\x69\x05\x99\x1C\x7D\x7C\x96\xFC\xBF\xB5\x87\xE4\x61\x00\x00\x00\x07"),
	RAW(VID_MS_WIN2008R2, VID_KEEP, "Windows Server 2008 R2",
	    "\x1E\x2B\x51\x69\x05\x99\x1C\x7D\x7C\x96\xFC\xBF\xB5\x87\xE4\x61\x00\x00\x00\x08"),
	RAW(VID_MS_WINKSINK09, VID_KEEP, "Windows 8, 8.1, 10, Server 2012 R2, Server 2016",
	    "\x1E\x2B\x51\x69\x05\x99\x1C\x7D\x7C\x96\xFC\xBF\xB5\x87\xE4\x61\x00\x00\x00\x09"),
	RAW(VID_MS_WINKEYMODS_IKE, VID_KEEP, "Windows KEY_MODS (IKE)",
	    "\x01\x52\x8b\xbb\xc0\x06\x96\x12\x18\x49\xab\x9a\x1c\x5b\x2a\x51\x00\x00\x00\x00"),
	RAW(VID_MS_WINKEYMODS_AUTHIP, VID_KEEP, "Windows KEY_MODS (AUTHIP)",
	    "\x01\x52\x8b\xbb\xc0\x06\x96\x12\x18\x49\xab\x9a\x1c\x5b\x2a\x51\x00\x00\x00\x01"),
	RAW(VID_MS_WINKEYMODS_IKEv2, VID_KEEP, "Windows KEY_MODS (IKEv2)",
	    "\x01\x52\x8b\xbb\xc0\x06\x96\x12\x18\x49\xab\x9a\x1c\x5b\x2a\x51\x00\x00\x00\x02"),
	RAW(VID_MS_AUTHIP_KE_DH_NONE, VID_KEEP, "AUTHIP INIT KE DH NONE",
	    "\x7B\xB9\x38\x67\xD7\x6C\x8D\x80\xDF\x0F\x40\xFA\xE8\xFC\x3B\x19\x00\x00\x00\x00"),
	RAW(VID_MS_AUTHIP_KE_DH1, VID_KEEP, "AUTHIP INIT KE DH1",
	    "\x7B\xB9\x38\x67\xD7\x6C\x8D\x80\xDF\x0F\x40\xFA\xE8\xFC\x3B\x19\x00\x00\x00\x01"),
	RAW(VID_MS_AUTHIP_KE_DH2, VID_KEEP, "AUTHIP INIT KE DH2",
	    "\x7B\xB9\x38\x67\xD7\x6C\x8D\x80\xDF\x0F\x40\xFA\xE8\xFC\x3B\x19\x00\x00\x00\x02"),
	RAW(VID_MS_AUTHIP_KE_DH14, VID_KEEP, "AUTHIP INIT KE DH14",
	    "\x7B\xB9\x38\x67\xD7\x6C\x8D\x80\xDF\x0F\x40\xFA\xE8\xFC\x3B\x19\x00\x00\x00\x03"),
	RAW(VID_MS_AUTHIP_KE_DH19, VID_KEEP, "AUTHIP INIT KE DH19(ECP 256)",
	    "\x7B\xB9\x38\x67\xD7\x6C\x8D\x80\xDF\x0F\x40\xFA\xE8\xFC\x3B\x19\x00\x00\x00\x04"),
	RAW(VID_MS_AUTHIP_KE_DH20, VID_KEEP, "AUTHIP INIT KE DH20(ECP 384)",
	    "\x7B\xB9\x38\x67\xD7\x6C\x8D\x80\xDF\x0F\x40\xFA\xE8\xFC\x3B\x19\x00\x00\x00\x05"),
	RAW(VID_MS_AUTHIP_KE_DH21, VID_KEEP, "AUTHIP INIT KE DH21(ECP 521)",
	    "\x7B\xB9\x38\x67\xD7\x6C\x8D\x80\xDF\x0F\x40\xFA\xE8\xFC\x3B\x19\x00\x00\x00\x06"),
	RAW(VID_MS_AUTHIP_KE_DHMAX, VID_KEEP, "AUTHIP INIT KE DH MAX",
	    "\x7B\xB9\x38\x67\xD7\x6C\x8D\x80\xDF\x0F\x40\xFA\xE8\xFC\x3B\x19\x00\x00\x00\x07"),
	RAW(VID_MS_NLBS_PRESENT, VID_KEEP, "NLB/MSCS fast failover supported",
	    "\x72\x87\x2B\x95\xFC\xDA\x2E\xB7\x08\xEF\xE3\x22\x11\x9B\x49\x71"),
	RAW(VID_MS_AUTHIP_SUPPORTED, VID_KEEP, "AuthIP supported",
	    "\x21\x4C\xA4\xFA\xFF\xA7\xF3\x2D\x67\x48\xE5\x30\x33\x95\xAE\x83"),
	RAW(VID_MS_CGA_SUPPORTED, VID_KEEP, "CGA supported",
	    "\xE3\xA5\x96\x6A\x76\x37\x9F\xE7\x07\x22\x82\x31\xE5\xCE\x86\x52"),
	RAW(VID_MS_NEGOTIATION_DISCOVERY_SUPPORTED, VID_KEEP, "Negotiation discovery supported",
	    "\xFB\x1D\xE3\xCD\xF3\x41\xB7\xEA\x16\xB7\xE5\xBE\x08\x55\xF1\x20"),
	RAW(VID_MS_XBOX_ONE_2013, VID_KEEP, "Microsoft Xbox One 2013",
	    "\x8A\xA3\x94\xCF\x8A\x55\x77\xDC\x31\x10\xC1\x13\xB0\x27\xA4\xF2"),
	RAW(VID_MS_XBOX_IKEv2, VID_KEEP, "Xbox IKEv2 Negotiation",
	    "\x66\x08\x22\xB3\xA7\x3A\x24\x41\x49\x57\x8D\x62\xE0\xEB\x46\xA0"),
	RAW(VID_MS_SEC_REALM_ID, VID_KEEP, "MSFT IPsec Security Realm Id",
	    "\x68\x6A\x8C\xBD\xFE\x63\x4B\x40\x51\x46\xFB\x2B\xAF\x33\xE9\xE8"),

	/* These two VID's plus VID_MS_NT5 trigger GSS-API support on Windows */
	VID(VID_GSSAPILONG, VID_MD5HASH, NULL, "A GSS-API Authentication Method for IKE"),
	VID(VID_GSSAPI, VID_MD5HASH, NULL, "GSSAPI"),


	VID(VID_SSH_SENTINEL, VID_MD5HASH, NULL, "SSH Sentinel"),
	VID(VID_SSH_SENTINEL_1_1, VID_MD5HASH, NULL, "SSH Sentinel 1.1"),
	VID(VID_SSH_SENTINEL_1_2, VID_MD5HASH, NULL, "SSH Sentinel 1.2"),
	VID(VID_SSH_SENTINEL_1_3, VID_MD5HASH, NULL, "SSH Sentinel 1.3"),
	VID(VID_SSH_SENTINEL_1_4, VID_MD5HASH, NULL, "SSH Sentinel 1.4"),
	VID(VID_SSH_SENTINEL_1_4_1, VID_MD5HASH, NULL, "SSH Sentinel 1.4.1"),

	/* These ones come from SSH vendors.txt */
	VID(VID_SSH_IPSEC_1_1_0, VID_MD5HASH, NULL,
	    "Ssh Communications Security IPSEC Express version 1.1.0"),
	VID(VID_SSH_IPSEC_1_1_1, VID_MD5HASH, NULL,
	    "Ssh Communications Security IPSEC Express version 1.1.1"),
	VID(VID_SSH_IPSEC_1_1_2, VID_MD5HASH, NULL,
	    "Ssh Communications Security IPSEC Express version 1.1.2"),
	VID(VID_SSH_IPSEC_1_2_1, VID_MD5HASH, NULL,
	    "Ssh Communications Security IPSEC Express version 1.2.1"),
	VID(VID_SSH_IPSEC_1_2_2, VID_MD5HASH, NULL,
	    "Ssh Communications Security IPSEC Express version 1.2.2"),
	VID(VID_SSH_IPSEC_2_0_0, VID_MD5HASH, NULL,
	    "SSH Communications Security IPSEC Express version 2.0.0"),
	VID(VID_SSH_IPSEC_2_1_0, VID_MD5HASH, NULL,
	    "SSH Communications Security IPSEC Express version 2.1.0"),
	VID(VID_SSH_IPSEC_2_1_1, VID_MD5HASH, NULL,
	    "SSH Communications Security IPSEC Express version 2.1.1"),
	VID(VID_SSH_IPSEC_2_1_2, VID_MD5HASH, NULL,
	    "SSH Communications Security IPSEC Express version 2.1.2"),
	VID(VID_SSH_IPSEC_3_0_0, VID_MD5HASH, NULL,
	    "SSH Communications Security IPSEC Express version 3.0.0"),
	VID(VID_SSH_IPSEC_3_0_1, VID_MD5HASH, NULL,
	    "SSH Communications Security IPSEC Express version 3.0.1"),
	VID(VID_SSH_IPSEC_4_0_0, VID_MD5HASH, NULL,
	    "SSH Communications Security IPSEC Express version 4.0.0"),
	VID(VID_SSH_IPSEC_4_0_1, VID_MD5HASH, NULL,
	    "SSH Communications Security IPSEC Express version 4.0.1"),
	VID(VID_SSH_IPSEC_4_1_0, VID_MD5HASH, NULL,
	    "SSH Communications Security IPSEC Express version 4.1.0"),
	VID(VID_SSH_IPSEC_4_2_0, VID_MD5HASH, NULL,
	    "SSH Communications Security IPSEC Express version 4.2.0"),

	/* The VPN 3000 concentrator VID is a truncated MD5 hash of "ALTIGA GATEWAY" */
	/* Last two bytes are version number, eg 0306 = 3.0.6 */
	RAW(VID_CISCO3K, VID_SUBSTRING, "Cisco VPN 3000 Series",
	    "\x1f\x07\xf7\x0e\xaa\x65\x14\xd3\xb0\xfa\x96\x54\x2a\x50"),

	RAW(VID_CISCO_IOS, VID_SUBSTRING, "Cisco IOS Device",
	    "\x3e\x98\x40\x48"),

	/* note: md5('CISCO-UNITY') = 12f5f28c457168a9702d9fe274cc02d4 */
	/*       last two bytes replaced with 01 00 */
	RAW(VID_CISCO_UNITY, VID_KEEP, "Cisco-Unity",
	    "\x12\xf5\xf2\x8c\x45\x71\x68\xa9\x70\x2d\x9f\xe2\x74\xcc\x01\x00"),

	/* 434953434f56504e2d5245562d3032 */
	VID(VID_CISCO_VPN_REV_02, VID_STRING, NULL, "CISCOVPN-REV-02"),

	RAW(VID_CISCO_UNITY_FWTYPE, VID_KEEP, "Cisco-Unity FW type",
	    "\x80\x01\x00\x01\x80\x02\x00\x01\x80\x03\x00\x02"),

	/* 434953434f2d44454c4554452d524541534f4e */
	VID(VID_CISCO_DELETE_REASON, VID_STRING, NULL, "CISCO-DELETE-REASON"),

	/* 434953434f2d44594e414d49432d524f555445 */
	VID(VID_CISCO_DYNAMIC_ROUTE, VID_STRING, NULL, "CISCO-DYNAMIC-ROUTE"),

	/* 464c455856504e2d535550504f52544544 */
	VID(VID_CISCO_FLEXVPN_SUPPORTED, VID_STRING, NULL, "FLEXVPN-SUPPORTED"),

	/*
	 * Timestep VID seen:
	 *   - 54494d455354455020312053475720313532302033313520322e303145303133
	 *     = 'TIMESTEP 1 SGW 1520 315 2.01E013'
	 */
	RAW(VID_TIMESTEP, VID_SUBSTRING, "TIMESTEP", "TIMESTEP"),

	VID(VID_FSWAN_2_00_VID, VID_FSWAN_HASH,
	    "FreeS/WAN 2.00",
	    "Linux FreeS/WAN 2.00 PLUTO_SENDS_VENDORID"),
	VID(VID_FSWAN_2_00_X509_1_3_1_VID, VID_FSWAN_HASH,
	    "FreeS/WAN 2.00 (X.509-1.3.1)",
	    "Linux FreeS/WAN 2.00 X.509-1.3.1 PLUTO_SENDS_VENDORID"),
	VID(VID_FSWAN_2_00_X509_1_3_1_LDAP_VID, VID_FSWAN_HASH,
	    "FreeS/WAN 2.00 (X.509-1.3.1 + LDAP)",
	    "Linux FreeS/WAN 2.00 X.509-1.3.1 LDAP PLUTO_SENDS_VENDORID"),
	VID(VID_OPENSWAN2, VID_FSWAN_HASH, "Openswan 2.2.0",
	    "Openswan 2.2.0"),

	/* always make sure to include ourself! */
	VID(VID_LIBRESWANSELF, VID_STRING, "Libreswan (this version)", libreswan_vendorid),

	/* NAT-Traversal */
	VID(VID_NATT_STENBERG_01, VID_MD5HASH, NULL, "draft-stenberg-ipsec-nat-traversal-01"),
	VID(VID_NATT_STENBERG_02, VID_MD5HASH, NULL, "draft-stenberg-ipsec-nat-traversal-02"),
	VID(VID_NATT_HUTTUNEN, VID_MD5HASH, NULL, "ESPThruNAT"),
	VID(VID_NATT_HUTTUNEN_ESPINUDP, VID_MD5HASH, NULL,
		    "draft-huttunen-ipsec-esp-in-udp-00.txt"),
	VID(VID_NATT_IETF_00, VID_MD5HASH, NULL, "draft-ietf-ipsec-nat-t-ike-00"),
	VID(VID_NATT_IETF_01, VID_MD5HASH, NULL, "draft-ietf-ipsec-nat-t-ike-01"),
	VID(VID_NATT_IETF_02, VID_MD5HASH, NULL, "draft-ietf-ipsec-nat-t-ike-02"),
	/* hash in draft-ietf-ipsec-nat-t-ike-02 contains '\n'... that as well */
	VID(VID_NATT_IETF_02_N, VID_MD5HASH, "draft-ietf-ipsec-nat-t-ike-02_n",
	    "draft-ietf-ipsec-nat-t-ike-02\n"),
	VID(VID_NATT_IETF_03, VID_MD5HASH, NULL, "draft-ietf-ipsec-nat-t-ike-03"),
	VID(VID_NATT_IETF_04, VID_MD5HASH, NULL, "draft-ietf-ipsec-nat-t-ike-04"),
	VID(VID_NATT_IETF_05, VID_MD5HASH, NULL, "draft-ietf-ipsec-nat-t-ike-05"),
	VID(VID_NATT_IETF_06, VID_MD5HASH, NULL, "draft-ietf-ipsec-nat-t-ike-06"),
	VID(VID_NATT_IETF_07, VID_MD5HASH, NULL, "draft-ietf-ipsec-nat-t-ike-07"),
	VID(VID_NATT_IETF_08, VID_MD5HASH, NULL, "draft-ietf-ipsec-nat-t-ike-08"),
	VID(VID_NATT_DRAFT_IETF_IPSEC_NAT_T_IKE, VID_MD5HASH, NULL, "draft-ietf-ipsec-nat-t-ike"),
	VID(VID_NATT_RFC, VID_MD5HASH, NULL, "RFC 3947"),

	/* SonicWall */
	RAW(VID_SONICWALL_1, VID_KEEP, "Sonicwall 1 (TZ 170 Standard?)",
	    "\x40\x4b\xf4\x39\x52\x2c\xa3\xf6"),
	/* apparently also Watchguard FireBoxs */
	RAW(VID_SONICWALL_2, VID_KEEP, "Sonicwall 2 (3.1.0.12-86s?)",
	    "\xda\x8e\x93\x78\x80\x01\x00\x00"),

	/* MD5("draft-ietf-ipsra-isakmp-xauth-06.txt") */
	RAW(VID_MISC_XAUTH, VID_KEEP, "XAUTH",
	    "\x09\x00\x26\x89\xdf\xd6\xb7\x12"),

	RAW(VID_MISC_DPD, VID_KEEP, "Dead Peer Detection",
	  "\xaf\xca\xd7\x13\x68\xa1\xf1\xc9\x6b\x86\x96\xfc\x77\x57\x01\x00"),

	/* From Shrew Soft source code */
	RAW(VID_DPD1_NG, VID_KEEP, "DPDv1_NG",
	    "\x3b\x90\x31\xdc\xe4\xfc\xf8\x8b\x48\x9a\x92\x39\x63\xdd\x0c\x49"),

	/* Obsolete: Was used by libreswan and openswan to detect bid-down attacks */
	VID(VID_MISC_IKEv2, VID_STRING, "CAN-IKEv2(obsolete)", "IKEv2"),

	/* VID is ASCII "HeartBeat_Notify" plus a few bytes (version?) */
	RAW(VID_MISC_HEARTBEAT_NOTIFY, VID_SUBSTRING, "HeartBeat Notify",
	    "HeartBeat_Notify"),

	/* FRAGMENTATION; Cisco VPN 3000 and strongSwan send extra values */
	RAW(VID_IKE_FRAGMENTATION, VID_SUBSTRING, "FRAGMENTATION",
	    "\x40\x48\xb7\xd5\x6e\xbc\xe8\x85\x25\xe7\xde\x7f\x00\xd6\xc2\xd3"),

	VID(VID_INITIAL_CONTACT, VID_MD5HASH, NULL, "Vid-Initial-Contact"),

	/*
	 * strongSwan
	 */

	VID(VID_STRONGSWAN, VID_MD5HASH, NULL, "strongSwan"),
	VID(VID_STRONGSWAN_4_0_0, VID_MD5HASH, NULL, "strongSwan 4.0.0"),
	VID(VID_STRONGSWAN_4_0_1, VID_MD5HASH, NULL, "strongSwan 4.0.1"),
	VID(VID_STRONGSWAN_4_0_2, VID_MD5HASH, NULL, "strongSwan 4.0.2"),
	VID(VID_STRONGSWAN_4_0_3, VID_MD5HASH, NULL, "strongSwan 4.0.3"),
	VID(VID_STRONGSWAN_4_0_4, VID_MD5HASH, NULL, "strongSwan 4.0.4"),
	VID(VID_STRONGSWAN_4_0_5, VID_MD5HASH, NULL, "strongSwan 4.0.5"),
	VID(VID_STRONGSWAN_4_0_6, VID_MD5HASH, NULL, "strongSwan 4.0.6"),
	VID(VID_STRONGSWAN_4_0_7, VID_MD5HASH, NULL, "strongSwan 4.0.7"),
	VID(VID_STRONGSWAN_4_1_0, VID_MD5HASH, NULL, "strongSwan 4.1.0"),
	VID(VID_STRONGSWAN_4_1_1, VID_MD5HASH, NULL, "strongSwan 4.1.1"),
	VID(VID_STRONGSWAN_4_1_2, VID_MD5HASH, NULL, "strongSwan 4.1.2"),
	VID(VID_STRONGSWAN_4_1_3, VID_MD5HASH, NULL, "strongSwan 4.1.3"),
	VID(VID_STRONGSWAN_4_1_4, VID_MD5HASH, NULL, "strongSwan 4.1.4"),
	VID(VID_STRONGSWAN_4_1_5, VID_MD5HASH, NULL, "strongSwan 4.1.5"),
	VID(VID_STRONGSWAN_4_1_6, VID_MD5HASH, NULL, "strongSwan 4.1.6"),
	VID(VID_STRONGSWAN_4_1_7, VID_MD5HASH, NULL, "strongSwan 4.1.7"),
	VID(VID_STRONGSWAN_4_1_8, VID_MD5HASH, NULL, "strongSwan 4.1.8"),
	VID(VID_STRONGSWAN_4_1_9, VID_MD5HASH, NULL, "strongSwan 4.1.9"),
	VID(VID_STRONGSWAN_4_1_10, VID_MD5HASH, NULL, "strongSwan 4.1.10"),
	VID(VID_STRONGSWAN_4_1_11, VID_MD5HASH, NULL, "strongSwan 4.1.11"),
	VID(VID_STRONGSWAN_4_2_0, VID_MD5HASH, NULL, "strongSwan 4.2.0"),
	VID(VID_STRONGSWAN_4_2_1, VID_MD5HASH, NULL, "strongSwan 4.2.1"),
	VID(VID_STRONGSWAN_4_2_2, VID_MD5HASH, NULL, "strongSwan 4.2.2"),
	VID(VID_STRONGSWAN_4_2_3, VID_MD5HASH, NULL, "strongSwan 4.2.3"),

	VID(VID_STRONGSWAN_2_8_8, VID_MD5HASH, NULL, "strongSwan 2.8.8"),
	VID(VID_STRONGSWAN_2_8_7, VID_MD5HASH, NULL, "strongSwan 2.8.7"),
	VID(VID_STRONGSWAN_2_8_6, VID_MD5HASH, NULL, "strongSwan 2.8.6"),
	VID(VID_STRONGSWAN_2_8_5, VID_MD5HASH, NULL, "strongSwan 2.8.5"),
	VID(VID_STRONGSWAN_2_8_4, VID_MD5HASH, NULL, "strongSwan 2.8.4"),
	VID(VID_STRONGSWAN_2_8_3, VID_MD5HASH, NULL, "strongSwan 2.8.3"),
	VID(VID_STRONGSWAN_2_8_2, VID_MD5HASH, NULL, "strongSwan 2.8.2"),
	VID(VID_STRONGSWAN_2_8_1, VID_MD5HASH, NULL, "strongSwan 2.8.1"),
	VID(VID_STRONGSWAN_2_8_0, VID_MD5HASH, NULL, "strongSwan 2.8.0"),
	VID(VID_STRONGSWAN_2_7_3, VID_MD5HASH, NULL, "strongSwan 2.7.3"),
	VID(VID_STRONGSWAN_2_7_2, VID_MD5HASH, NULL, "strongSwan 2.7.2"),
	VID(VID_STRONGSWAN_2_7_1, VID_MD5HASH, NULL, "strongSwan 2.7.1"),
	VID(VID_STRONGSWAN_2_7_0, VID_MD5HASH, NULL, "strongSwan 2.7.0"),
	VID(VID_STRONGSWAN_2_6_4, VID_MD5HASH, NULL, "strongSwan 2.6.4"),
	VID(VID_STRONGSWAN_2_6_3, VID_MD5HASH, NULL, "strongSwan 2.6.3"),
	VID(VID_STRONGSWAN_2_6_2, VID_MD5HASH, NULL, "strongSwan 2.6.2"),
	VID(VID_STRONGSWAN_2_6_1, VID_MD5HASH, NULL, "strongSwan 2.6.1"),
	VID(VID_STRONGSWAN_2_6_0, VID_MD5HASH, NULL, "strongSwan 2.6.0"),
	VID(VID_STRONGSWAN_2_5_7, VID_MD5HASH, NULL, "strongSwan 2.5.7"),
	VID(VID_STRONGSWAN_2_5_6, VID_MD5HASH, NULL, "strongSwan 2.5.6"),
	VID(VID_STRONGSWAN_2_5_5, VID_MD5HASH, NULL, "strongSwan 2.5.5"),
	VID(VID_STRONGSWAN_2_5_4, VID_MD5HASH, NULL, "strongSwan 2.5.4"),
	VID(VID_STRONGSWAN_2_5_3, VID_MD5HASH, NULL, "strongSwan 2.5.3"),
	VID(VID_STRONGSWAN_2_5_2, VID_MD5HASH, NULL, "strongSwan 2.5.2"),
	VID(VID_STRONGSWAN_2_5_1, VID_MD5HASH, NULL, "strongSwan 2.5.1"),
	VID(VID_STRONGSWAN_2_5_0, VID_MD5HASH, NULL, "strongSwan 2.5.0"),
	VID(VID_STRONGSWAN_2_4_4, VID_MD5HASH, NULL, "strongSwan 2.4.4"),
	VID(VID_STRONGSWAN_2_4_3, VID_MD5HASH, NULL, "strongSwan 2.4.3"),
	VID(VID_STRONGSWAN_2_4_2, VID_MD5HASH, NULL, "strongSwan 2.4.2"),
	VID(VID_STRONGSWAN_2_4_1, VID_MD5HASH, NULL, "strongSwan 2.4.1"),
	VID(VID_STRONGSWAN_2_4_0, VID_MD5HASH, NULL, "strongSwan 2.4.0"),
	VID(VID_STRONGSWAN_2_3_2, VID_MD5HASH, NULL, "strongSwan 2.3.2"),
	VID(VID_STRONGSWAN_2_3_1, VID_MD5HASH, NULL, "strongSwan 2.3.1"),
	VID(VID_STRONGSWAN_2_3_0, VID_MD5HASH, NULL, "strongSwan 2.3.0"),
	VID(VID_STRONGSWAN_2_2_2, VID_MD5HASH, NULL, "strongSwan 2.2.2"),
	VID(VID_STRONGSWAN_2_2_1, VID_MD5HASH, NULL, "strongSwan 2.2.1"),
	VID(VID_STRONGSWAN_2_2_0, VID_MD5HASH, NULL, "strongSwan 2.2.0"),

	/*
	 * NCP.de
	 * Also seen from ncp client:
	 * eb4c1b788afd4a9cb7730a68d56d088b
	 * c61baca1f1a60cc10800000000000000
	 * cbe79444a0870de4224a2c151fbfe099
	 */
	RAW(VID_NCP, VID_KEEP, "NCP client",
	    "\x10\x1f\xb0\xb3\x5c\x5a\x4f\x4c\x08\xb9\x19\xf1\xcb\x97\x77\xb0"),

	RAW(VID_SHREWSOFT, VID_KEEP, "Shrew Soft client",
	    "\xf1\x4b\x94\xb7\xbf\xf1\xfe\xf0\x27\x73\xb8\xc4\x9f\xed\xed\x26"),

	RAW(VID_NETSCREEN_01, VID_KEEP, "Netscreen-01",
	    "\x29\x9e\xe8\x28\x9f\x40\xa8\x97\x3b\xc7\x86\x87\xe2\xe7\x22\x6b\x53\x2c\x3b\x76"),
	RAW(VID_NETSCREEN_02, VID_KEEP, "Netscreen-02",
	    "\x3a\x15\xe1\xf3\xcf\x2a\x63\x58\x2e\x3a\xc8\x2d\x1c\x64\xcb\xe3\xb6\xd7\x79\xe7"),
	RAW(VID_NETSCREEN_03, VID_KEEP, "Netscreen-03",
	    "\x47\xd2\xb1\x26\xbf\xcd\x83\x48\x97\x60\xe2\xcf\x8c\x5d\x4d\x5a\x03\x49\x7c\x15"),
	RAW(VID_NETSCREEN_04, VID_KEEP, "Netscreen-04",
	    "\x4a\x43\x40\xb5\x43\xe0\x2b\x84\xc8\x8a\x8b\x96\xa8\xaf\x9e\xbe\x77\xd9\xac\xcc"),
	RAW(VID_NETSCREEN_05, VID_KEEP, "Netscreen-05",
	    "\x64\x40\x5f\x46\xf0\x3b\x76\x60\xa2\x3b\xe1\x16\xa1\x97\x50\x58\xe6\x9e\x83\x87"),
	RAW(VID_NETSCREEN_06, VID_KEEP, "Netscreen-06",
	    "\x69\x93\x69\x22\x87\x41\xc6\xd4\xca\x09\x4c\x93\xe2\x42\xc9\xde\x19\xe7\xb7\xc6"),
	RAW(VID_NETSCREEN_07, VID_KEEP, "Netscreen-07",
	    "\x8c\x0d\xc6\xcf\x62\xa0\xef\x1b\x5c\x6e\xab\xd1\xb6\x7b\xa6\x98\x66\xad\xf1\x6a"),
	RAW(VID_NETSCREEN_08, VID_KEEP, "Netscreen-08",
	    "\x92\xd2\x7a\x9e\xcb\x31\xd9\x92\x46\x98\x6d\x34\x53\xd0\xc3\xd5\x7a\x22\x2a\x61"),
	RAW(VID_NETSCREEN_09, VID_KEEP, "Netscreen-09",
	    "\x9b\x09\x6d\x9a\xc3\x27\x5a\x7d\x6f\xe8\xb9\x1c\x58\x31\x11\xb0\x9e\xfe\xd1\xa0"),
	RAW(VID_NETSCREEN_10, VID_KEEP, "Netscreen-10",
	    "\xbf\x03\x74\x61\x08\xd7\x46\xc9\x04\xf1\xf3\x54\x7d\xe2\x4f\x78\x47\x9f\xed\x12"),
	RAW(VID_NETSCREEN_11, VID_KEEP, "Netscreen-11",
	    "\xc2\xe8\x05\x00\xf4\xcc\x5f\xbf\x5d\xaa\xee\xd3\xbb\x59\xab\xae\xee\x56\xc6\x52"),
	RAW(VID_NETSCREEN_12, VID_KEEP, "Netscreen-12",
	    "\xc8\x66\x0a\x62\xb0\x3b\x1b\x61\x30\xbf\x78\x16\x08\xd3\x2a\x6a\x8d\x0f\xb8\x9f"),
	RAW(VID_NETSCREEN_13, VID_KEEP, "Netscreen-13",
	    "\xf8\x85\xda\x40\xb1\xe7\xa9\xab\xd1\x76\x55\xec\x5b\xbe\xc0\xf2\x1f\x0e\xd5\x2e"),
	RAW(VID_NETSCREEN_14, VID_KEEP, "Netscreen-14",
	    "\x2a\x2b\xca\xc1\x9b\x8e\x91\xb4\x26\x10\x78\x07\xe0\x2e\x72\x49\x56\x9d\x6f\xd3"),
	RAW(VID_NETSCREEN_15, VID_KEEP, "Netscreen-15",
	    "\x16\x6f\x93\x2d\x55\xeb\x64\xd8\xe4\xdf\x4f\xd3\x7e\x23\x13\xf0\xd0\xfd\x84\x51"),
	RAW(VID_NETSCREEN_16, VID_KEEP, "Netscreen-16",
	    "\xa3\x5b\xfd\x05\xca\x1a\xc0\xb3\xd2\xf2\x4e\x9e\x82\xbf\xcb\xff\x9c\x9e\x52\xb5"),

	RAW(VID_ZYWALL, VID_KEEP, "Zywall",
	    "\x62\x50\x27\x74\x9d\x5a\xb9\x7f\x56\x16\xc1\x60\x27\x65\xcf\x48\x0a\x3b\x7d\x0b"),

	RAW(VID_SIDEWINDER, VID_KEEP, "Sidewinder",
	    "\x84\x04\xad\xf9\xcd\xa0\x57\x60\xb2\xca\x29\x2e\x4b\xff\x53\x7b"),

	RAW(VID_LUCENT_GW9, VID_KEEP, "Lucent VPN Gateway 9 (LVG9.1.255:BRICK:9.1.255)",
	    "\x4c\x56\x47\x39\x2e\x32\x2e\x32\x34\x35\x3a\x42\x52\x49\x43\x4b\x3a\x39\x2e\x32\x2e\x32\x34\x35"),
	RAW(VID_LUCENT_CL7, VID_KEEP, "Lucent VPN Client 7 (LVC7.1.2:XP)",
	    "\x4c\x56\x43\x37\x2e\x31\x2e\x32\x3a\x58\x50"),

	RAW(VID_CHECKPOINT, VID_KEEP, "Check Point",
	    "\xf4\xed\x19\xe0\xc1\x14\xeb\x51\x6f\xaa\xac\x0e\xe3\x7d\xaf\x28\x07\xb4\x38\x1f"),

	RAW(VID_LIBRESWAN, VID_SUBSTRING, "Libreswan (3.6+)",
	    "\x4f\x45\x2d\x4c\x69\x62\x72\x65\x73\x77\x61\x6e\x2d"),

	RAW(VID_LIBRESWAN_OLD, VID_SUBSTRING, "Libreswan 3.0 - 3.5",
	    "\x4f\x45\x4e"),

	RAW(VID_XOPENSWAN, VID_SUBSTRING, "Openswan(xeleranized)",
	    "\x4f\x53\x57"),

	RAW(VID_OPENSWANORG, VID_SUBSTRING, "Openswan(project)",
	    "\x4f\x45"),

	/*
	 * "ELVIS-PLUS Zastava"
	 * Last two bytes (not matched here) are major|minor nibbles and a reserved 00
	 */
	RAW(VID_ELVIS, VID_SUBSTRING, "ELVIS-PLUS Zastava",
	    "\x08\xdb\x45\xe6\xcb\x01\xf8\x0b\xb5\x76\xe9\xa7\x8c\x0f\x54\xe1\x30\x0b\x88\x81"),

	/*
	 * Fortinet
	 */
	VID(VID_FORTINET_ENDPOINT_CONTROL, VID_MD5HASH, NULL, "Fortinet Endpoint Control"),
	VID(VID_FORTINET_CONNECT_LICENSE, VID_MD5HASH, NULL, "forticlient connect license"),

	/*
	 * OpenIKED
	 */

	RAW(VID_OPENIKED, VID_SUBSTRING, "OpenIKED", "OpenIKED"),

	/* END OF TABLE */
	VID(VID_none, 0, NULL, NULL),

#undef VID
#undef RAW
};

/*
 * SEE: comments in init_vendorid().
 */

struct vid_entry {
	const struct vid_struct *entry; /* in VID_TAB[] */
};

/* vendor IDs sorted by the raw .vid; VID_none aka 0 is omitted */
static struct vid_entry vid_sorted[elemsof(vid_tab) - 1/*leave out entry 0*/];

/* bsearch table pointing at VID_SORTED[] */
static const struct vid_entry *vid_lookup[elemsof(vid_sorted)];
unsigned elemsof_vid_lookup;

static int vid_sorted_cmp(const void *lp, const void *rp)
{
	const struct vid_entry *l = lp;
	const struct vid_entry *r = rp;

	/*
	 * If this isn't sufficient there are deeper problems.
	 */
	return hunk_cmp(l->entry->vid, r->entry->vid);
}

static int vid_entry_cmp(const shunk_t *key, const struct vid_entry *member)
{
	if (member->entry->vid.len < key->len &&
	    member->entry->kind == VID_SUBSTRING) {
		return raw_cmp(key->ptr, member->entry->vid.len,
			       member->entry->vid.ptr, member->entry->vid.len);
	} else {
		return hunk_cmp(*key, member->entry->vid);
	}
}

static int vid_lookup_cmp(const void *key, const void *member)
{
	return vid_entry_cmp(key, *(const struct vid_entry**)member);
}

/*
 * Setup VendorID structs, and populate them
 * FIXME: This functions leaks a little bit, but these are one time leaks:
 * leak: 3 * vid->data, item size: 6
 * leak: self-vendor ID, item size: 37
 * leak: 2 * vid->data, item size: 13
 */

static void LDBG_vid_struct(const struct logger *logger, const struct vid_struct *vid)
{
	LLOG_JAMBUF(DEBUG_STREAM, logger, buf) {
		jam(buf, " %3d ", vid->id); /* match " %3s " below */
		jam_string(buf, vid->descr);
		jam_string(buf, " ");
		switch (vid->kind) {
		case VID_KEEP:
			jam_string(buf, " keep");
			break;
		case VID_FSWAN_HASH:
			jam_string(buf, " fswan-hash");
			break;
		case VID_MD5HASH:
			jam_string(buf, " md5");
			break;
		case VID_SUBSTRING:
			jam_string(buf, " substring");
			break;
		case VID_STRING:
			jam_string(buf, " string");
			break;
		}
	}
	LLOG_JAMBUF(DEBUG_STREAM, logger, buf) {
		jam(buf, " %3s ", ""); /* match " %3d " above */
		jam_dump_hunk(buf, vid->vid);
		jam_string(buf, " [");
		jam_sanitized_bytes(buf, vid->vid.ptr, vid->vid.len);
		jam_string(buf, "]");
	}
}

void init_vendorid(struct logger *logger)
{
	ldbg(logger, "building Vendor ID table");

	FOR_EACH_ELEMENT_FROM_1(vid, vid_tab) {
		bool good = true;
		switch (vid->kind) {
		case VID_STRING:
			/* built using VID() */
			good &= pexpect(vid->vid.ptr == NULL);
			good &= pexpect(vid->vid.len == 0);
			good &= pexpect(vid->descr == NULL || !streq(vid->descr, vid->data));
			vid->vid = shunk1(vid->data);
			break;
		case VID_SUBSTRING:
			/* built using RAW */
			good &= pexpect(vid->vid.ptr != NULL);
			good &= pexpect(vid->vid.len > 0);
			good &= pexpect(vid->descr != NULL);
			break;
		case VID_MD5HASH:
			/* built using VID(), .data is a string to hash with MD5 **/
			good &= pexpect(vid->vid.ptr == NULL);
			good &= pexpect(vid->vid.len == 0);
			/* TODO: This use must allowed even with USE_MD5=false */
			struct crypt_hash *ctx = crypt_hash_init("vendor id",
								 &ike_alg_hash_md5,
								 logger);
			crypt_hash_digest_bytes(ctx, "data", vid->data, strlen(vid->data));
			void *vidm = alloc_bytes(MD5_DIGEST_SIZE, "VendorID MD5 (ignore)");
			crypt_hash_final_bytes(&ctx, vidm, MD5_DIGEST_SIZE);
			vid->vid = shunk2(vidm, MD5_DIGEST_SIZE);
			break;
		case VID_FSWAN_HASH:
		{
			/** FreeS/WAN 2.00+ specific hash **/
			good &= pexpect(vid->vid.ptr == NULL);
			good &= pexpect(vid->vid.len == 0);
#define FSWAN_VID_SIZE 12
			unsigned char hash[MD5_DIGEST_SIZE];
			char *vidm = alloc_bytes(FSWAN_VID_SIZE, "fswan VID (ignore)");

			struct crypt_hash *ctx = crypt_hash_init("vendor id",
								 &ike_alg_hash_md5,
								 logger);
			crypt_hash_digest_bytes(ctx, "data", vid->data, strlen(vid->data));
			crypt_hash_final_bytes(&ctx, hash, MD5_DIGEST_SIZE);

			vidm[0] = 'O';
			vidm[1] = 'E';
#if FSWAN_VID_SIZE <= 2 + MD5_DIGEST_SIZE
			memcpy(vidm + 2, hash, FSWAN_VID_SIZE - 2);	/* truncate hash */
#else
			memcpy(vidm + 2, hash, MD5_DIGEST_SIZE);
			memset(vidm + 2 + MD5_DIGEST_SIZE, '\0',
			       FSWAN_VID_SIZE - (2 + MD5_DIGEST_SIZE));	/* pad hash */
#endif
			for (int i = 2; i < FSWAN_VID_SIZE; i++) {
				vidm[i] &= 0x7f;
				vidm[i] |= 0x40;
			}
			vid->vid = shunk2(vidm, FSWAN_VID_SIZE);
#undef FSWAN_VID_SIZE
			break;
		}
		case VID_KEEP:
			/* RAW() */
			good &= pexpect(vid->vid.len > 0);
			good &= pexpect(vid->vid.ptr != NULL);
			good &= pexpect(vid->descr != NULL);
			good &= pexpect(vid->data == NULL);
			break;
		}

		if (vid->descr == NULL) {
			/** Find something to display **/
			vid->descr = vid->data;
		}

		/* job done? */
		good &= pexpect(vid->descr != NULL);
		good &= pexpect(vid->vid.ptr != NULL);
		good &= pexpect(vid->vid.len > 0);
		if (!good || LDBGP(DBG_TMI, logger)) {
			LDBG_vid_struct(logger, vid);
		}
	}

	/*
	 * Step 1: Sort the VID_TAB[] creating VID_SORTED.
	 *
	 * Because VIDs overlap, the result is a table containing
	 * multiple entries with the same prefix which means it isn't
	 * suitable for a binary search.
	 *
	 * For instance, say the table includes the entries:
	 *
	 *    "OA.*"
	 *    "OE.*"
	 *    "OE Libreswan.*"
	 *    "OE Libreswan 123"
	 *    "OF.*"
	 *
	 * then a binary search for "OE LIBRESWAN" would match either
	 * "OE.*" or "OE Libreswan", or fail.
	 *
	 * Note that vid_sorted[] is zero indexed.
	 */
	ldbg(logger, "building sorted Vendor ID table");
	FOR_EACH_ELEMENT_FROM_1(vid, vid_tab) {
		passert(vid->id > 0);
		/* make it zero indexed */
		unsigned id0 = vid->id - 1;
		passert(id0 < elemsof(vid_sorted));
		vid_sorted[id0].entry = vid;
	}
	qsort(vid_sorted, elemsof(vid_sorted), sizeof(vid_sorted[0]), vid_sorted_cmp);

	/*
	 * Step 2: Prune the VID_SORTED[] table of all but the
	 * shortest overlapping VIDs creating VID_LOOKUP[].
	 *
	 * Each entry points into VID_SORTED[] at the first of the
	 * overlapping VIDs that match the VID_LOOKUP[] entry.
	 *
	 * For instance, using the above:
	 *
	 *   VID_LOOKUP[]    VID_SORTED[]
	 *     "OA.*"     ->   "OA.*"
	 *     "OE.*"     ->   "OE.*"
	 *                     "OE Libreswan.*"
	 *                     "OE Libreswan 123"
	 *     "OF.*"     ->   "OF.*"
	 *
	 * A search for "OE LIBRESWAN" is then performed in two steps:
	 *
	 * 1. using bsearch(VID_LOOKUP) to find the element "OE.*"
	 *
	 * 2. a linear search of VID_SORTED[] starting at it's "OE.*"
	 *    entry and finding "OE Libreswan.*"
	 */
	ldbg(logger, "building lookup Vendor ID table");
	vid_lookup[elemsof_vid_lookup++] = &vid_sorted[0];
	FOR_EACH_ELEMENT_FROM_1(vidp, vid_sorted) {

		/* do this and prev entry share their prefix? */
		const struct vid_entry *prev = vid_lookup[elemsof_vid_lookup-1];
		int c = vid_entry_cmp(&vidp->entry->vid, prev);
		if (c > 0) {
			/* no: easy peasy; lemon squeezy */
			vid_lookup[elemsof_vid_lookup++] = vidp;
			continue;
		}

		if (LDBGP(DBG_BASE, logger)) {
			LDBG_log(logger, "Vendor IDs '%s' and '%s' have a common prefix",
				prev->entry->descr,
				vidp->entry->descr);
			LDBG_vid_struct(logger, prev->entry);
			LDBG_vid_struct(logger, vidp->entry);
		}
	}
}

void llog_vendorid(struct logger *logger, enum known_vendorid id, shunk_t vid, bool vid_useful)
{
	const unsigned MAX_LOG_VID_LEN = 32;

	lset_t stream = (id == VID_none ? RC_LOG|ALL_STREAMS :
			 LDBGP(DBG_BASE, logger) ? DEBUG_STREAM :
			 0);
	if (stream == 0) {
		return;
	}

	LLOG_JAMBUF(stream, logger, buf) {
		/* truncate the VID */
		shunk_t tvid = hunk_slice(vid, 0, PMIN(vid.len, MAX_LOG_VID_LEN));
		const char *trunc = (vid.len > MAX_LOG_VID_LEN ? " ..." : "");
		jam_string(buf, vid_useful ? "received" : "ignoring");
		/* description */
		jam_string(buf, " ");
		if (id == VID_none) {
			jam_string(buf, "unknown");
		} else {
			jam_string(buf, vid_tab[id].descr);
		}
		jam_string(buf, " Vendor ID payload");
		/* dump as ascii */
		jam_string(buf, " \"");
		jam_sanitized_hunk(buf, tvid);
		jam_string(buf, trunc);
		jam_string(buf, "\"");
		/* dump as hex */
		jam_string(buf, " [");
		jam_dump_hunk(buf, tvid);
		jam_string(buf, trunc);
		jam_string(buf, "]");
	}
}

/*
 * Handle VendorID's.  This function parses what the remote peer
 * sends us, calls handle_known_vendorid on each VID we received
 *
 * Known VendorID's are defined in vendor.h
 *
 * @param md Message Digest from remote peer
 * @param vid String of VendorIDs
 * @param len Length of vid
 * @param vid VendorID Struct (see vendor.h)
 * @param st State Structure (Hopefully initialized)
 * @return void
 */

enum known_vendorid vendorid_by_shunk(shunk_t vid)
{
	const struct logger *logger = &global_logger;
	/*
	 * Find known VendorID in vid_tab
	 */
	if (vid.len > 0) {
		/* oh for generics */
		const struct vid_entry **bvid = bsearch(&vid, vid_lookup,
							elemsof_vid_lookup,
							sizeof(vid_lookup[0]),
							vid_lookup_cmp);
		if (bvid == NULL) {
			/* no luck */
			return VID_none;
		}

		/* BVID points into VID_LOOKUP[] */
		passert(bvid >= &vid_lookup[0]);
		passert(bvid < &vid_lookup[elemsof_vid_lookup]);

		/* *BVID points into VID_SORTED[] */
		const struct vid_entry *best = *bvid;
		pexpect(vid_entry_cmp(&vid, best) == 0);
		passert(best >= &vid_sorted[0]);
		passert(best < &vid_sorted[elemsof(vid_sorted)]);
		if (LDBGP(DBG_TMI, logger)) {
			LDBG_log(logger, "starting with the Vendor ID:");
			LDBG_vid_struct(logger, best->entry);
		}

		/*
		 * Search through the Vendor IDs sharing a common
		 * prefix looking for the best match.  Since they are
		 * sorted short-to-long and the last match is used it
		 * will have the longest prefix.
		 */

		for (const struct vid_entry *vidp = best + 1;
		     vidp < &vid_sorted[elemsof(vid_sorted)];
		     vidp++) {

			if (LDBGP(DBG_TMI, logger)) {
				LDBG_log(logger, "comparing with Vendor ID:");
				LDBG_vid_struct(logger, vidp->entry);
			}

			int c = vid_entry_cmp(&vid, vidp);
			if (c < 0) {
				if (LDBGP(DBG_TMI, logger)) {
					LDBG_log(logger, "  reached the end of the overlapping Vendor IDs");
				}
				break;
			}

			if (c == 0) {
				if (LDBGP(DBG_TMI, logger)) {
					LDBG_log(logger, "  better match");
				}
				best = vidp;
				continue;
			}

			if (LDBGP(DBG_TMI, logger)) {
				LDBG_log(logger, "  not the best");
			}
		}

		return best->entry->id;
	}
	return VID_none;
}

const char *str_vendorid(enum known_vendorid id, name_buf *eb)
{
	if (id > 0 && id < elemsof(vid_tab)) {
		return vid_tab[id].descr;
	}

	snprintf(eb->tmp, sizeof(eb->tmp), "VID_%u", id);
	eb->buf = eb->tmp;
	return eb->buf;
}

shunk_t shunk_from_vendorid(enum known_vendorid id)
{
	passert(id > 0);
	passert(id < elemsof(vid_tab));
	const struct vid_struct *pvid = &vid_tab[id];
	return pvid->vid;
}

void llog_vendorids(lset_t rc_flags, struct logger *logger)
{
	FOR_EACH_ELEMENT(v, vid_sorted) {
		enum known_vendorid id = v->entry->id;
		shunk_t vid = shunk_from_vendorid(id);
		name_buf idb;
		llog(rc_flags, logger, "[%s]%s", str_vendorid(id, &idb),
		     (v->entry->kind == VID_SUBSTRING ? " (prefix match)" : ""));
		llog_hunk(rc_flags, logger, vid);
		enum known_vendorid r = vendorid_by_shunk(vid);
		passert(r != VID_none);
		if (r != id) {
			name_buf idb, rb;
			llog_passert(logger, HERE,
				     "lookup for %d [%s] returned %d [%s]",
				     id, str_vendorid(id, &idb),
				     r, str_vendorid(r, &rb));
		}
	}
}
