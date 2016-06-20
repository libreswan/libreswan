/* Libreswan ISAKMP VendorID Handling
 * Copyright (C) 2002-2003 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2004 Xelerance Corporation
 * Copyright (C) 2012-2014 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Wolfgang Nothdurft <wolfgang@linogate.de>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 *
 * See also https://github.com/royhills/ike-scan/blob/master/ike-vendor-ids
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

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "log.h"
#include "md5.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"
#include "packet.h"
#include "demux.h"
#include "server.h"
#include "whack.h"
#include "vendor.h"
#include "quirks.h"
#include "kernel.h"

#include "nat_traversal.h"

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
 * Solaris 10 has RF 3974 but also md5('RFC XXXX') whih is 810fa565f8ab14369105d706fbd57279
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

#define MAX_LOG_VID_LEN         32

#define VID_KEEP                0x0000
#define VID_MD5HASH             0x0001
#define VID_STRING              0x0002
#define VID_FSWAN_HASH          0x0004
#define VID_SELF                0x0008

#define VID_SUBSTRING_DUMPHEXA  0x0100
#define VID_SUBSTRING_DUMPASCII 0x0200
#define VID_SUBSTRING_MATCH     0x0400
#define VID_SUBSTRING  (VID_SUBSTRING_DUMPHEXA | VID_SUBSTRING_DUMPASCII | \
			VID_SUBSTRING_MATCH)

struct vid_struct {
	const enum known_vendorid id;
	const unsigned short flags;
	const char *const data;

	/* filled in at runtime: */
	const char *descr;
	const char *vid;
	unsigned int vid_len;
};

#define DEC_MD5_VID_D(id, str, descr) \
	{ id, VID_MD5HASH, str, descr, NULL, 0 }
#define DEC_MD5_VID(id, str) \
	{ id, VID_MD5HASH, str, NULL, NULL, 0 }
#define DEC_FSWAN_VID(id, str, descr) \
	{ id, VID_FSWAN_HASH, str, descr, NULL, 0 }

static struct vid_struct vid_tab[] = {

	/* Implementation names */

	{ VID_OPENPGP, VID_STRING, "OpenPGP10171", "OpenPGP", NULL, 0 },

	DEC_MD5_VID(VID_KAME_RACOON, "KAME/racoon"),
	{
		VID_MS_NT5, VID_MD5HASH | VID_SUBSTRING_DUMPHEXA,
		"MS NT5 ISAKMPOAKLEY", NULL, NULL, 0
	},
	/* http://msdn.microsoft.com/en-us/library/cc233476%28v=prot.10%29.aspx
	   Windows 2000 00 00 00 02
	   Windows XP 00 00 00 03
	   Windows Server 2003 00 00 00 04
	   Windows Vista 00 00 00 05
	   Windows Server 2008 00 00 00 06
	   Windows 7 00 00 00 07
	   Windows Server 2008 R2 00 00 00 08
	 */

	/* These two VID's plus VID_MS_NT5 trigger GSS-API support */
	DEC_MD5_VID(VID_GSSAPILONG, "A GSS-API Authentication Method for IKE"),
	DEC_MD5_VID(VID_GSSAPI, "GSSAPI"),

	DEC_MD5_VID(VID_SSH_SENTINEL, "SSH Sentinel"),
	DEC_MD5_VID(VID_SSH_SENTINEL_1_1, "SSH Sentinel 1.1"),
	DEC_MD5_VID(VID_SSH_SENTINEL_1_2, "SSH Sentinel 1.2"),
	DEC_MD5_VID(VID_SSH_SENTINEL_1_3, "SSH Sentinel 1.3"),
	DEC_MD5_VID(VID_SSH_SENTINEL_1_4, "SSH Sentinel 1.4"),
	DEC_MD5_VID(VID_SSH_SENTINEL_1_4_1, "SSH Sentinel 1.4.1"),

	/* These ones come from SSH vendors.txt */
	DEC_MD5_VID(VID_SSH_IPSEC_1_1_0,
		    "Ssh Communications Security IPSEC Express version 1.1.0"),
	DEC_MD5_VID(VID_SSH_IPSEC_1_1_1,
		    "Ssh Communications Security IPSEC Express version 1.1.1"),
	DEC_MD5_VID(VID_SSH_IPSEC_1_1_2,
		    "Ssh Communications Security IPSEC Express version 1.1.2"),
	DEC_MD5_VID(VID_SSH_IPSEC_1_2_1,
		    "Ssh Communications Security IPSEC Express version 1.2.1"),
	DEC_MD5_VID(VID_SSH_IPSEC_1_2_2,
		    "Ssh Communications Security IPSEC Express version 1.2.2"),
	DEC_MD5_VID(VID_SSH_IPSEC_2_0_0,
		    "SSH Communications Security IPSEC Express version 2.0.0"),
	DEC_MD5_VID(VID_SSH_IPSEC_2_1_0,
		    "SSH Communications Security IPSEC Express version 2.1.0"),
	DEC_MD5_VID(VID_SSH_IPSEC_2_1_1,
		    "SSH Communications Security IPSEC Express version 2.1.1"),
	DEC_MD5_VID(VID_SSH_IPSEC_2_1_2,
		    "SSH Communications Security IPSEC Express version 2.1.2"),
	DEC_MD5_VID(VID_SSH_IPSEC_3_0_0,
		    "SSH Communications Security IPSEC Express version 3.0.0"),
	DEC_MD5_VID(VID_SSH_IPSEC_3_0_1,
		    "SSH Communications Security IPSEC Express version 3.0.1"),
	DEC_MD5_VID(VID_SSH_IPSEC_4_0_0,
		    "SSH Communications Security IPSEC Express version 4.0.0"),
	DEC_MD5_VID(VID_SSH_IPSEC_4_0_1,
		    "SSH Communications Security IPSEC Express version 4.0.1"),
	DEC_MD5_VID(VID_SSH_IPSEC_4_1_0,
		    "SSH Communications Security IPSEC Express version 4.1.0"),
	DEC_MD5_VID(VID_SSH_IPSEC_4_2_0,
		    "SSH Communications Security IPSEC Express version 4.2.0"),
	/* The VPN 3000 concentrator VID is a truncated MD5 hash of "ALTIGA GATEWAY" */
	/* Last two bytes are version number, eg 0306 = 3.0.6 */
	{ VID_CISCO3K, VID_KEEP | VID_SUBSTRING_MATCH,
	  NULL, "Cisco VPN 3000 Series",
		"\x1f\x07\xf7\x0e\xaa\x65\x14\xd3\xb0\xfa\x96\x54\x2a\x50", 14
	},

	{ VID_CISCO_IOS, VID_KEEP | VID_SUBSTRING_MATCH,
	  NULL, "Cisco IOS Device", "\x3e\x98\x40\x48", 4 },

	/* note: md5('CISCO-UNITY') = 12f5f28c457168a9702d9fe274cc02d4 */
	/*       last two bytes replaced with 01 00 */
	{ VID_CISCO_UNITY, VID_KEEP, NULL, "Cisco-Unity",
	  "\x12\xf5\xf2\x8c\x45\x71\x68\xa9\x70\x2d\x9f\xe2\x74\xcc\x01\x00",
	  16 },
	{ VID_CISCO_UNITY_FWTYPE, VID_KEEP, NULL, "Cisco-Unity FW type",
	  "\x80\x01\x00\x01\x80\x02\x00\x01\x80\x03\x00\x02", 12 },
	/* 434953434f2d44454c4554452d524541534f4e */
	{ VID_CISCO_DELETE_REASON, VID_STRING, "CISCO-DELETE-REASON",
	  NULL, NULL, 0 },
	/* 464c455856504e2d535550504f52544544 */
	{ VID_CISCO_FLEXVPN_SUPPORTED, VID_STRING, "FLEXVPN-SUPPORTED",
	  NULL, NULL, 0 },

	/*
	 * Timestep VID seen:
	 *   - 54494d455354455020312053475720313532302033313520322e303145303133
	 *     = 'TIMESTEP 1 SGW 1520 315 2.01E013'
	 */
	{ VID_TIMESTEP, VID_STRING | VID_SUBSTRING_DUMPASCII, "TIMESTEP",
	  NULL, NULL, 0 },

	DEC_FSWAN_VID(VID_FSWAN_2_00_VID,
		      "Linux FreeS/WAN 2.00 PLUTO_SENDS_VENDORID",
		      "FreeS/WAN 2.00"),
	DEC_FSWAN_VID(VID_FSWAN_2_00_X509_1_3_1_VID,
		      "Linux FreeS/WAN 2.00 X.509-1.3.1 PLUTO_SENDS_VENDORID",
		      "FreeS/WAN 2.00 (X.509-1.3.1)"),
	DEC_FSWAN_VID(VID_FSWAN_2_00_X509_1_3_1_LDAP_VID,
		      "Linux FreeS/WAN 2.00 X.509-1.3.1 LDAP PLUTO_SENDS_VENDORID",
		      "FreeS/WAN 2.00 (X.509-1.3.1 + LDAP)"),
	DEC_FSWAN_VID(VID_OPENSWAN2,
		      "Openswan 2.2.0",
		      "Openswan 2.2.0"),
	{
		/* always make sure to include ourself! */
		VID_LIBRESWANSELF, VID_SELF, libreswan_vendorid, "Libreswan (this version)",
		libreswan_vendorid, 0
	},

	/* NAT-Traversal */
	DEC_MD5_VID(VID_NATT_STENBERG_01, "draft-stenberg-ipsec-nat-traversal-01"),
	DEC_MD5_VID(VID_NATT_STENBERG_02, "draft-stenberg-ipsec-nat-traversal-02"),
	DEC_MD5_VID(VID_NATT_HUTTUNEN, "ESPThruNAT"),
	DEC_MD5_VID(VID_NATT_HUTTUNEN_ESPINUDP,
		    "draft-huttunen-ipsec-esp-in-udp-00.txt"),
	DEC_MD5_VID(VID_NATT_IETF_00, "draft-ietf-ipsec-nat-t-ike-00"),
	DEC_MD5_VID(VID_NATT_IETF_01, "draft-ietf-ipsec-nat-t-ike-01"),
	DEC_MD5_VID(VID_NATT_IETF_02, "draft-ietf-ipsec-nat-t-ike-02"),
	/* hash in draft-ietf-ipsec-nat-t-ike-02 contains '\n'... Accept both */
	DEC_MD5_VID_D(VID_NATT_IETF_02_N, "draft-ietf-ipsec-nat-t-ike-02\n",
		      "draft-ietf-ipsec-nat-t-ike-02_n"),
	DEC_MD5_VID(VID_NATT_IETF_03, "draft-ietf-ipsec-nat-t-ike-03"),
	DEC_MD5_VID(VID_NATT_IETF_04, "draft-ietf-ipsec-nat-t-ike-04"),
	DEC_MD5_VID(VID_NATT_IETF_05, "draft-ietf-ipsec-nat-t-ike-05"),
	DEC_MD5_VID(VID_NATT_IETF_06, "draft-ietf-ipsec-nat-t-ike-06"),
	DEC_MD5_VID(VID_NATT_IETF_07, "draft-ietf-ipsec-nat-t-ike-07"),
	DEC_MD5_VID(VID_NATT_IETF_08, "draft-ietf-ipsec-nat-t-ike-08"),
	DEC_MD5_VID(VID_NATT_DRAFT_IETF_IPSEC_NAT_T_IKE,
		    "draft-ietf-ipsec-nat-t-ike"),
	DEC_MD5_VID(VID_NATT_RFC, "RFC 3947"),
	{
		/* SonicWall */
		VID_SONICWALL_1, VID_KEEP, NULL,
		"Sonicwall 1 (TZ 170 Standard?)",
		"\x40\x4b\xf4\x39\x52\x2c\xa3\xf6", 8
	},
	{ VID_SONICWALL_2, VID_KEEP, NULL, "Sonicwall 2 (3.1.0.12-86s?)",
	  "\xda\x8e\x93\x78\x80\x01\x00\x00", 8 },

	/* MD5("draft-ietf-ipsra-isakmp-xauth-06.txt") */
	{ VID_MISC_XAUTH, VID_KEEP, NULL, "XAUTH",
	  "\x09\x00\x26\x89\xdf\xd6\xb7\x12", 8 },

	{ VID_MISC_DPD, VID_KEEP, NULL, "Dead Peer Detection",
	  "\xaf\xca\xd7\x13\x68\xa1\xf1\xc9\x6b\x86\x96\xfc\x77\x57\x01\x00",
	  16 },

	/* From Shrew Soft source code */
	{ VID_DPD1_NG, VID_KEEP, "DPDv1_NG" , NULL,
	  "\x3b\x90\x31\xdc\xe4\xfc\xf8\x8b\x48\x9a\x92\x39\x63\xdd\x0c\x49",
	  16 },

	/* Used by libreswan and openswan to detect bid-down attacks */
	{ VID_MISC_IKEv2, VID_STRING | VID_KEEP, "IKEv2", "CAN-IKEv2", NULL,
	  0 },

	/* VID is ASCII "HeartBeat_Notify" plus a few bytes (version?) */
	{ VID_MISC_HEARTBEAT_NOTIFY, VID_STRING | VID_SUBSTRING_DUMPHEXA,
	  "HeartBeat_Notify", "HeartBeat Notify", NULL, 0 },

	/*
	 * MacOS X
	 */
	{ VID_MACOSX, VID_STRING | VID_SUBSTRING_DUMPHEXA, "Mac OSX 10.x",
	  "\x4d\xf3\x79\x28\xe9\xfc\x4f\xd1\xb3\x26\x21\x70\xd5\x15\xc6\x62",
	  NULL, 0 },

	/*
	 * We send this VID to let people know this opportunistic ipsec
	 * (we hope people thinking they are under attack will google for
	 *  this string and find information about it)
	 */
	{ VID_OPPORTUNISTIC, VID_STRING | VID_KEEP, "Opportunistic IPsec",
	 "\x4f\x70\x70\x6f\x72\x74\x75\x6e\x69\x73\x74\x69\x63\x20\x49\x50\x73\x65\x63",
	  NULL, 0},

	DEC_MD5_VID(VID_IKE_FRAGMENTATION, "FRAGMENTATION"),
	DEC_MD5_VID(VID_INITIAL_CONTACT, "Vid-Initial-Contact"),

	/* Microsoft Windows Vista, and maybe Server 2008? */
	DEC_MD5_VID(VID_VISTA_AUTHIP,  "MS-Negotiation Discovery Capable"),
	DEC_MD5_VID(VID_VISTA_AUTHIP2, "IKE CGA version 1"),
	DEC_MD5_VID(VID_VISTA_AUTHIP3, "MS-MamieExists"),

	/*
	 * strongSwan
	 */

	DEC_MD5_VID(VID_STRONGSWAN, "strongSwan"),
	DEC_MD5_VID(VID_STRONGSWAN_4_0_0, "strongSwan 4.0.0"),
	DEC_MD5_VID(VID_STRONGSWAN_4_0_1, "strongSwan 4.0.1"),
	DEC_MD5_VID(VID_STRONGSWAN_4_0_2, "strongSwan 4.0.2"),
	DEC_MD5_VID(VID_STRONGSWAN_4_0_3, "strongSwan 4.0.3"),
	DEC_MD5_VID(VID_STRONGSWAN_4_0_4, "strongSwan 4.0.4"),
	DEC_MD5_VID(VID_STRONGSWAN_4_0_5, "strongSwan 4.0.5"),
	DEC_MD5_VID(VID_STRONGSWAN_4_0_6, "strongSwan 4.0.6"),
	DEC_MD5_VID(VID_STRONGSWAN_4_0_7, "strongSwan 4.0.7"),
	DEC_MD5_VID(VID_STRONGSWAN_4_1_0, "strongSwan 4.1.0"),
	DEC_MD5_VID(VID_STRONGSWAN_4_1_1, "strongSwan 4.1.1"),
	DEC_MD5_VID(VID_STRONGSWAN_4_1_2, "strongSwan 4.1.2"),
	DEC_MD5_VID(VID_STRONGSWAN_4_1_3, "strongSwan 4.1.3"),
	DEC_MD5_VID(VID_STRONGSWAN_4_1_4, "strongSwan 4.1.4"),
	DEC_MD5_VID(VID_STRONGSWAN_4_1_5, "strongSwan 4.1.5"),
	DEC_MD5_VID(VID_STRONGSWAN_4_1_6, "strongSwan 4.1.6"),
	DEC_MD5_VID(VID_STRONGSWAN_4_1_7, "strongSwan 4.1.7"),
	DEC_MD5_VID(VID_STRONGSWAN_4_1_8, "strongSwan 4.1.8"),
	DEC_MD5_VID(VID_STRONGSWAN_4_1_9, "strongSwan 4.1.9"),
	DEC_MD5_VID(VID_STRONGSWAN_4_1_10, "strongSwan 4.1.10"),
	DEC_MD5_VID(VID_STRONGSWAN_4_1_11, "strongSwan 4.1.11"),
	DEC_MD5_VID(VID_STRONGSWAN_4_2_0, "strongSwan 4.2.0"),
	DEC_MD5_VID(VID_STRONGSWAN_4_2_1, "strongSwan 4.2.1"),
	DEC_MD5_VID(VID_STRONGSWAN_4_2_2, "strongSwan 4.2.2"),
	DEC_MD5_VID(VID_STRONGSWAN_4_2_3, "strongSwan 4.2.3"),

	DEC_MD5_VID(VID_STRONGSWAN_2_8_8, "strongSwan 2.8.8"),
	DEC_MD5_VID(VID_STRONGSWAN_2_8_7, "strongSwan 2.8.7"),
	DEC_MD5_VID(VID_STRONGSWAN_2_8_6, "strongSwan 2.8.6"),
	DEC_MD5_VID(VID_STRONGSWAN_2_8_5, "strongSwan 2.8.5"),
	DEC_MD5_VID(VID_STRONGSWAN_2_8_4, "strongSwan 2.8.4"),
	DEC_MD5_VID(VID_STRONGSWAN_2_8_3, "strongSwan 2.8.3"),
	DEC_MD5_VID(VID_STRONGSWAN_2_8_2, "strongSwan 2.8.2"),
	DEC_MD5_VID(VID_STRONGSWAN_2_8_1, "strongSwan 2.8.1"),
	DEC_MD5_VID(VID_STRONGSWAN_2_8_0, "strongSwan 2.8.0"),
	DEC_MD5_VID(VID_STRONGSWAN_2_7_3, "strongSwan 2.7.3"),
	DEC_MD5_VID(VID_STRONGSWAN_2_7_2, "strongSwan 2.7.2"),
	DEC_MD5_VID(VID_STRONGSWAN_2_7_1, "strongSwan 2.7.1"),
	DEC_MD5_VID(VID_STRONGSWAN_2_7_0, "strongSwan 2.7.0"),
	DEC_MD5_VID(VID_STRONGSWAN_2_6_4, "strongSwan 2.6.4"),
	DEC_MD5_VID(VID_STRONGSWAN_2_6_3, "strongSwan 2.6.3"),
	DEC_MD5_VID(VID_STRONGSWAN_2_6_2, "strongSwan 2.6.2"),
	DEC_MD5_VID(VID_STRONGSWAN_2_6_1, "strongSwan 2.6.1"),
	DEC_MD5_VID(VID_STRONGSWAN_2_6_0, "strongSwan 2.6.0"),
	DEC_MD5_VID(VID_STRONGSWAN_2_5_7, "strongSwan 2.5.7"),
	DEC_MD5_VID(VID_STRONGSWAN_2_5_6, "strongSwan 2.5.6"),
	DEC_MD5_VID(VID_STRONGSWAN_2_5_5, "strongSwan 2.5.5"),
	DEC_MD5_VID(VID_STRONGSWAN_2_5_4, "strongSwan 2.5.4"),
	DEC_MD5_VID(VID_STRONGSWAN_2_5_3, "strongSwan 2.5.3"),
	DEC_MD5_VID(VID_STRONGSWAN_2_5_2, "strongSwan 2.5.2"),
	DEC_MD5_VID(VID_STRONGSWAN_2_5_1, "strongSwan 2.5.1"),
	DEC_MD5_VID(VID_STRONGSWAN_2_5_0, "strongSwan 2.5.0"),
	DEC_MD5_VID(VID_STRONGSWAN_2_4_4, "strongSwan 2.4.4"),
	DEC_MD5_VID(VID_STRONGSWAN_2_4_3, "strongSwan 2.4.3"),
	DEC_MD5_VID(VID_STRONGSWAN_2_4_2, "strongSwan 2.4.2"),
	DEC_MD5_VID(VID_STRONGSWAN_2_4_1, "strongSwan 2.4.1"),
	DEC_MD5_VID(VID_STRONGSWAN_2_4_0, "strongSwan 2.4.0"),
	DEC_MD5_VID(VID_STRONGSWAN_2_3_2, "strongSwan 2.3.2"),
	DEC_MD5_VID(VID_STRONGSWAN_2_3_1, "strongSwan 2.3.1"),
	DEC_MD5_VID(VID_STRONGSWAN_2_3_0, "strongSwan 2.3.0"),
	DEC_MD5_VID(VID_STRONGSWAN_2_2_2, "strongSwan 2.2.2"),
	DEC_MD5_VID(VID_STRONGSWAN_2_2_1, "strongSwan 2.2.1"),
	DEC_MD5_VID(VID_STRONGSWAN_2_2_0, "strongSwan 2.2.0"),
	{
		/**
		 * Cisco VPN 3000
		 */
		VID_IKE_FRAGMENTATION, VID_MD5HASH | VID_SUBSTRING_DUMPHEXA,
		"FRAGMENTATION", NULL, NULL, 0
	},

	/*
	 * NCP.de
	 * Also seen from ncp client:
	 * eb4c1b788afd4a9cb7730a68d56d088b
	 * c61baca1f1a60cc10800000000000000
	 * cbe79444a0870de4224a2c151fbfe099
	 */
	{ VID_NCP, VID_KEEP, "NCP client", NULL,
	  "\x10\x1f\xb0\xb3\x5c\x5a\x4f\x4c\x08\xb9\x19\xf1\xcb\x97\x77\xb0",
	  16 },

	{ VID_SHREWSOFT, VID_KEEP, "Shrew Soft client", NULL,
	  "\xf1\x4b\x94\xb7\xbf\xf1\xfe\xf0\x27\x73\xb8\xc4\x9f\xed\xed\x26",
	  16 },

	{ VID_NETSCREEN_01, VID_KEEP, "Netscreen-01", NULL,
	  "\x29\x9e\xe8\x28\x9f\x40\xa8\x97\x3b\xc7\x86\x87\xe2\xe7\x22\x6b\x53\x2c\x3b\x76",
	  20 },
	{ VID_NETSCREEN_02, VID_KEEP, "Netscreen-02", NULL,
	  "\x3a\x15\xe1\xf3\xcf\x2a\x63\x58\x2e\x3a\xc8\x2d\x1c\x64\xcb\xe3\xb6\xd7\x79\xe7",
	  20 },
	{ VID_NETSCREEN_03, VID_KEEP, "Netscreen-03", NULL,
	  "\x47\xd2\xb1\x26\xbf\xcd\x83\x48\x97\x60\xe2\xcf\x8c\x5d\x4d\x5a\x03\x49\x7c\x15",
	  20 },
	{ VID_NETSCREEN_04, VID_KEEP, "Netscreen-04", NULL,
	  "\x4a\x43\x40\xb5\x43\xe0\x2b\x84\xc8\x8a\x8b\x96\xa8\xaf\x9e\xbe\x77\xd9\xac\xcc",
	  20 },
	{ VID_NETSCREEN_05, VID_KEEP, "Netscreen-05", NULL,
	  "\x64\x40\x5f\x46\xf0\x3b\x76\x60\xa2\x3b\xe1\x16\xa1\x97\x50\x58\xe6\x9e\x83\x87",
	  20 },
	{ VID_NETSCREEN_06, VID_KEEP, "Netscreen-06", NULL,
	  "\x69\x93\x69\x22\x87\x41\xc6\xd4\xca\x09\x4c\x93\xe2\x42\xc9\xde\x19\xe7\xb7\xc6",
	  20 },
	{ VID_NETSCREEN_07, VID_KEEP, "Netscreen-07", NULL,
	  "\x8c\x0d\xc6\xcf\x62\xa0\xef\x1b\x5c\x6e\xab\xd1\xb6\x7b\xa6\x98\x66\xad\xf1\x6a",
	  20 },
	{ VID_NETSCREEN_08, VID_KEEP, "Netscreen-08", NULL,
	  "\x92\xd2\x7a\x9e\xcb\x31\xd9\x92\x46\x98\x6d\x34\x53\xd0\xc3\xd5\x7a\x22\x2a\x61",
	  20 },
	{ VID_NETSCREEN_09, VID_KEEP, "Netscreen-09", NULL,
	  "\x9b\x09\x6d\x9a\xc3\x27\x5a\x7d\x6f\xe8\xb9\x1c\x58\x31\x11\xb0\x9e\xfe\xd1\xa0",
	  20 },
	{ VID_NETSCREEN_10, VID_KEEP, "Netscreen-10", NULL,
	  "\xbf\x03\x74\x61\x08\xd7\x46\xc9\x04\xf1\xf3\x54\x7d\xe2\x4f\x78\x47\x9f\xed\x12",
	  20 },
	{ VID_NETSCREEN_11, VID_KEEP, "Netscreen-11", NULL,
	  "\xc2\xe8\x05\x00\xf4\xcc\x5f\xbf\x5d\xaa\xee\xd3\xbb\x59\xab\xae\xee\x56\xc6\x52",
	  20 },
	{ VID_NETSCREEN_12, VID_KEEP, "Netscreen-12", NULL,
	  "\xc8\x66\x0a\x62\xb0\x3b\x1b\x61\x30\xbf\x78\x16\x08\xd3\x2a\x6a\x8d\x0f\xb8\x9f",
	  20 },
	{ VID_NETSCREEN_13, VID_KEEP, "Netscreen-13", NULL,
	  "\xf8\x85\xda\x40\xb1\xe7\xa9\xab\xd1\x76\x55\xec\x5b\xbe\xc0\xf2\x1f\x0e\xd5\x2e",
	  20 },
	{ VID_NETSCREEN_14, VID_KEEP, "Netscreen-14", NULL,
	  "\x2a\x2b\xca\xc1\x9b\x8e\x91\xb4\x26\x10\x78\x07\xe0\x2e\x72\x49\x56\x9d\x6f\xd3",
	  20 },
	{ VID_NETSCREEN_15, VID_KEEP, "Netscreen-15", NULL,
	  "\x16\x6f\x93\x2d\x55\xeb\x64\xd8\xe4\xdf\x4f\xd3\x7e\x23\x13\xf0\xd0\xfd\x84\x51",
	  20 },
	{ VID_NETSCREEN_16, VID_KEEP, "Netscreen-16", NULL,
	  "\xa3\x5b\xfd\x05\xca\x1a\xc0\xb3\xd2\xf2\x4e\x9e\x82\xbf\xcb\xff\x9c\x9e\x52\xb5",
	  20 },

	{ VID_ZYWALL, VID_KEEP, "Zywall", NULL,
	  "\x62\x50\x27\x74\x9d\x5a\xb9\x7f\x56\x16\xc1\x60\x27\x65\xcf\x48\x0a\x3b\x7d\x0b",
	  20 },

	{ VID_SIDEWINDER, VID_KEEP, "Sidewinder", NULL,
	  "\x84\x04\xad\xf9\xcd\xa0\x57\x60\xb2\xca\x29\x2e\x4b\xff\x53\x7b",
	  16 },

	{ VID_WATCHGUARD, VID_KEEP, "Watchguard FireBox", NULL,
	  "\xda\x8e\x93\x78\x80\x01\x00\x00", 8 },

	{ VID_LUCENT_GW9, VID_KEEP,
	  "Lucent VPN Gateway 9 (LVG9.1.255:BRICK:9.1.255)", NULL,
	  "\x4c\x56\x47\x39\x2e\x32\x2e\x32\x34\x35\x3a\x42\x52\x49\x43\x4b\x3a\x39\x2e\x32\x2e\x32\x34\x35",
	  24 },
	{ VID_LUCENT_CL7, VID_KEEP, "Lucent VPN Client 7 (LVC7.1.2:XP)", NULL,
	  "\x4c\x56\x43\x37\x2e\x31\x2e\x32\x3a\x58\x50", 11 },

	{ VID_CHECKPOINT, VID_KEEP, "Check Point", NULL,
	  "\xf4\xed\x19\xe0\xc1\x14\xeb\x51\x6f\xaa\xac\x0e\xe3\x7d\xaf\x28\x07\xb4\x38\x1f",
	  20 },

	{ VID_LIBRESWAN, VID_KEEP | VID_SUBSTRING_DUMPHEXA,
	  NULL, "Libreswan (3.6+)", "\x4f\x45\x2d\x4c\x69\x62\x72\x65\x73\x77\x61\x6e\x2d", 13 },

	{ VID_LIBRESWAN_OLD, VID_KEEP | VID_SUBSTRING_MATCH, NULL, "Libreswan 3.0 - 3.5", "\x4f\x45\x4e", 3 },

	{ VID_XOPENSWAN, VID_KEEP | VID_SUBSTRING_MATCH, NULL, "Openswan(xeleranized)", "\x4f\x53\x57", 3 },

	{ VID_OPENSWANORG, VID_KEEP | VID_SUBSTRING_MATCH, NULL, "Openswan(project)", "\x4f\x45", 2 },

	/* END OF TABLE */
	{ 0, 0, NULL, NULL, NULL, 0 }
};

static const char hexdig[] = "0123456789abcdef";

/*
 * Setup VendorID structs, and populate them
 * FIXME: This functions leaks a little bit, but these are one time leaks:
 * leak: 3 * vid->data, item size: 6
 * leak: self-vendor ID, item size: 37
 * leak: 2 * vid->data, item size: 13
 */
void init_vendorid(void)
{
	struct vid_struct *vid;

	for (vid = vid_tab; vid->id; vid++) {
		if (vid->flags & VID_SELF) {
			vid->vid_len = strlen(vid->vid);
		} else if (vid->flags & VID_STRING) {
			/** VendorID is a string **/
			vid->vid = clone_str(vid->data, "vid->data (ignore)");
			/* clang 3.4 thinks that vid->data might be NULL but it won't be */
			vid->vid_len = strlen(vid->data);
		} else if (vid->flags & VID_MD5HASH) {
			/** VendorID is a string to hash with MD5 **/
			unsigned char *vidm = alloc_bytes(MD5_DIGEST_SIZE,
							 "VendorID MD5 (ignore)");
			const unsigned char *d = (const unsigned char *)vid->data;
			lsMD5_CTX ctx;

			vid->vid = (char *)vidm;

			lsMD5Init(&ctx);
			lsMD5Update(&ctx, d, strlen(vid->data));
			lsMD5Final(vidm, &ctx);
			vid->vid_len = MD5_DIGEST_SIZE;
		} else if (vid->flags & VID_FSWAN_HASH) {
			/** FreeS/WAN 2.00+ specific hash **/
#define FSWAN_VID_SIZE 12
			unsigned char hash[MD5_DIGEST_SIZE];
			char *vidm = alloc_bytes(FSWAN_VID_SIZE, "fswan VID (ignore)");
			lsMD5_CTX ctx;
			int i;

			vid->vid = vidm;

			lsMD5Init(&ctx);
			lsMD5Update(&ctx, (const unsigned char *)vid->data,
				strlen(vid->data));
			lsMD5Final(hash, &ctx);
			vidm[0] = 'O';
			vidm[1] = 'E';
#if FSWAN_VID_SIZE <= 2 + MD5_DIGEST_SIZE
			memcpy(vidm + 2, hash, FSWAN_VID_SIZE - 2);	/* truncate hash */
#else
			memcpy(vidm + 2, hash, MD5_DIGEST_SIZE);
			memset(vidm + 2 + MD5_DIGEST_SIZE, '\0',
			       FSWAN_VID_SIZE - (2 + MD5_DIGEST_SIZE));	/* pad hash */
#endif
			for (i = 2; i < FSWAN_VID_SIZE; i++) {
				vidm[i] &= 0x7f;
				vidm[i] |= 0x40;
			}
			vid->vid_len = FSWAN_VID_SIZE;
#undef FSWAN_VID_SIZE
		}

		if (vid->descr == NULL) {
			/** Find something to display **/
			vid->descr = vid->data;
		}
#if 0
		DBG_log("init_vendorid: %d [%s]",
			vid->id,
			vid->descr == NULL ? vid->descr : "");
		if (vid->vid != NULL)
			DBG_dump("VID:", vid->vid, vid->vid_len);
#endif
	}
}

static void vidlog(const char *vidstr, size_t len, struct vid_struct *vid, bool vid_useful)
{
	char vid_dump[128];

	if (vid->flags & VID_SUBSTRING_DUMPHEXA) {
		/* Dump description + Hexa */
		size_t i, j;

		snprintf(vid_dump, sizeof(vid_dump), "%s ",
			 vid->descr ? vid->descr : "");
		for (i = strlen(vid_dump), j = vid->vid_len
		     ; (j < len) && (i < sizeof(vid_dump) - 2)
		     ; i += 2, j++) {
			vid_dump[i] = hexdig[(vidstr[j] >> 4) & 0xF];
			vid_dump[i + 1] = hexdig[vidstr[j] & 0xF];
		}
		vid_dump[i] = '\0';
	} else if (vid->flags & VID_SUBSTRING_DUMPASCII) {
		/* Dump ASCII content */
		size_t i;

		for (i = 0; i < len && i < sizeof(vid_dump) - 1; i++)
			vid_dump[i] = isprint(vidstr[i]) ? vidstr[i] : '.';
		vid_dump[i] = '\0';
	} else {
		/* Dump description (descr) */
		snprintf(vid_dump, sizeof(vid_dump), "%s",
			 vid->descr ? vid->descr : "");
	}

	DBG(DBG_CONTROL, DBG_log("%s Vendor ID payload [%s]",
	       vid_useful ? "received" : "ignoring", vid_dump));
}

/*
 * Handle IKEv2 Known VendorID's.
 * We don't know about any real IKEv2 vendor id strings yet
 */

static void handle_known_vendorid_v2(struct msg_digest *md UNUSED,
				  const char *vidstr,
				  size_t len,
				  struct vid_struct *vid)
{
	bool vid_useful = TRUE; /* tentatively TRUE */

	/* IKEv2 VID processing */
	switch (vid->id) {
	case VID_LIBRESWANSELF:
	case VID_LIBRESWAN:
	case VID_LIBRESWAN_OLD:
	case VID_OPPORTUNISTIC:
		/* not really useful, but it changes the msg from "ignored" to "received" */
		break;
	default:
		vid_useful = FALSE;
		break;
	}

	vidlog(vidstr, len, vid, vid_useful);
}

/*
 * Handle IKEv1 Known VendorID's.  This function parses what the remote peer
 * sends us, and enables/disables features based on it.  As we go along,
 * we set vid_useful to TRUE if we did something based on this VendorID.  This
 * supresses the 'Ignored VendorID ...' log message.
 *
 * @param md message_digest
 * @param vidstr VendorID String
 * @param len Length of vidstr
 * @param vid VendorID Struct (see vendor.h)
 * @param st State Structure (Hopefully initialized)
 * @return void
 */
static void handle_known_vendorid_v1(struct msg_digest *md,
				  const char *vidstr,
				  size_t len,
				  struct vid_struct *vid)
{
	bool vid_useful = TRUE; /* tentatively TRUE */

	switch (vid->id) {
	/*
	 * Use most recent supported NAT-Traversal method and ignore
	 * the other ones (implementations will send all supported
	 * methods but only one will be used)
	 *
	 * Note: most recent == higher id in vendor.h
	 */

	case VID_LIBRESWANSELF:
	case VID_LIBRESWAN:
	case VID_LIBRESWAN_OLD:
	case VID_OPPORTUNISTIC:
		/* not really useful, but it changes the msg from "ignored" to "received" */
		break;

	case VID_NATT_IETF_00:
	case VID_NATT_IETF_01:
		vid_useful = FALSE; /* no longer supported */
		break;

	case VID_NATT_IETF_02:
	case VID_NATT_IETF_02_N:
	case VID_NATT_IETF_03:
	case VID_NATT_IETF_04:
	case VID_NATT_IETF_05:
	case VID_NATT_IETF_06:
	case VID_NATT_IETF_07:
	case VID_NATT_IETF_08:
	case VID_NATT_DRAFT_IETF_IPSEC_NAT_T_IKE:
		/* FALL THROUGH */
	case VID_NATT_RFC:
		if (md->quirks.qnat_traversal_vid < vid->id) {
			DBG(DBG_NATT, DBG_log(" quirks.qnat_traversal_vid set to=%d ",
					      vid->id));
			md->quirks.qnat_traversal_vid = vid->id;
		} else {
			DBG(DBG_NATT,
			    DBG_log("Ignoring older NAT-T Vendor ID paylad [%s]",
				    vid->descr));
			vid_useful = FALSE;
		}
		break;

	case VID_MISC_DPD:
	case VID_DPD1_NG:
		/* Remote side would like to do DPD with us on this connection */
		md->dpd = TRUE;
		break;

	case VID_MISC_IKEv2:
		md->ikev2 = TRUE;
		break;

	case VID_NORTEL:
		md->nortel = TRUE;
		break;

	case VID_SSH_SENTINEL_1_4_1:
		loglog(RC_LOG_SERIOUS,
		       "SSH Sentinel 1.4.1 found, setting XAUTH_ACK quirk");
		md->quirks.xauth_ack_msgid = TRUE;
		break;

	case VID_CISCO_UNITY:
		md->quirks.modecfg_pull_mode = TRUE;
		break;

	case VID_MISC_XAUTH:
		md->quirks.xauth_vid = TRUE;
		break;

	case VID_CISCO_IKE_FRAGMENTATION:
	case VID_IKE_FRAGMENTATION:
		md->fragvid = TRUE;
		break;

	default:
		vid_useful = FALSE;
		break;
	}
	vidlog(vidstr, len, vid, vid_useful);
}


static void handle_known_vendorid(struct msg_digest *md,
				  const char *vidstr,
				  size_t len,
				  struct vid_struct *vid,
				  bool ikev2)
{
	if (ikev2)
		handle_known_vendorid_v2(md, vidstr, len, vid);
	else
		handle_known_vendorid_v1(md, vidstr, len, vid);
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
void handle_vendorid(struct msg_digest *md, const char *vid, size_t len,
		     bool ikev2)
{
	struct vid_struct *pvid;

	/*
	 * Find known VendorID in vid_tab
	 */
	for (pvid = vid_tab; pvid->id; pvid++) {
		if (pvid->vid && vid && pvid->vid_len && len) {
			if (pvid->vid_len == len) {
				if (memeq(pvid->vid, vid, len)) {
					handle_known_vendorid(md, vid,
							      len, pvid, ikev2);
					return;
				}
			} else if ((pvid->vid_len < len) &&
				   (pvid->flags & VID_SUBSTRING)) {
				if (memeq(pvid->vid, vid, pvid->vid_len)) {
					handle_known_vendorid(md, vid, len,
							      pvid, ikev2);
					return;
				}
			}
		}
	}

	/*
	 * Unknown VendorID. Log the beginning.
	 */
	{
		char log_vid[2 * MAX_LOG_VID_LEN + 1];
		size_t i;

		for (i = 0; (i < len) && (i < MAX_LOG_VID_LEN); i++) {
			/*
			 * clang 3.4 thinks the vid might be NULL; wrong
			 */
			log_vid[2 * i] = hexdig[(vid[i] >> 4) & 0xF];
			log_vid[2 * i + 1] = hexdig[vid[i] & 0xF];
		}
		log_vid[2 * i] = '\0';
		loglog(RC_LOG_SERIOUS,
		       "ignoring unknown Vendor ID payload [%s%s]",
		       log_vid, (len > MAX_LOG_VID_LEN) ? "..." : "");
	}
}

/**
 * Add an IKEv1 (!)  vendor id payload to the msg
 *
 * @param np
 * @param outs PB stream
 * @param vid Int of VendorID to be sent (see vendor.h for the list)
 * @return bool True if successful
 */
bool out_vid(u_int8_t np, pb_stream *outs, unsigned int vid)
{
	struct vid_struct *pvid;

	for (pvid = vid_tab; pvid->id != vid; pvid++) /* stop at right vid */

	passert(pvid->id != 0); /* we must find what we are trying to send */

	DBG(DBG_EMITTING,
	    DBG_log("out_vid(): sending [%s]", pvid->descr));

	return ikev1_out_generic_raw(np, &isakmp_vendor_id_desc, outs,
			       pvid->vid, pvid->vid_len, "V_ID");
}

/*
 * The VID table or entries are static
 */
bool vid_is_oppo(const char *vid, size_t len)
{
	struct vid_struct *pvid;

	/* stop at right vid in vidtable */
	for (pvid = vid_tab; pvid->id != VID_OPPORTUNISTIC; pvid++)

	passert(pvid->id != 0); /* we must find VID_OPPORTUNISTIC */

	if (pvid->vid_len != len) {
		DBG(DBG_CONTROLMORE, DBG_log("VID is not VID_OPPORTUNISTIC: length differs"));
		return FALSE;
	}

	if (memeq(vid, pvid->vid, len)) {
		DBG(DBG_CONTROL, DBG_log("VID_OPPORTUNISTIC received"));
		return TRUE;
	} else {
		DBG(DBG_CONTROLMORE, DBG_log("VID is not VID_OPPORTUNISTIC: content differs"));
		return FALSE;
	}
}

