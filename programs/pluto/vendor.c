/* Openswan ISAKMP VendorID Handling
 * Copyright (C) 2002-2003 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2004 Xelerance Corporation
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
 * RCSID $Id: vendor.c,v 1.43.2.1 2005/07/26 02:05:10 ken Exp $
 */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/queue.h>
#include <openswan.h>

#include "constants.h"
#include "defs.h"
#include "log.h"
#include "md5.h"
#include "id.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#include "smartcard.h"
#ifdef XAUTH_USEPAM
#include <security/pam_appl.h>
#endif
#include "connections.h"
#include "packet.h"
#include "demux.h"
#include "server.h"
#include "whack.h"
#include "vendor.h"
#include "quirks.h"
#include "kernel.h"
#include "state.h"

#ifdef NAT_TRAVERSAL
#include "nat_traversal.h"
#endif

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
 * NCP.de
 *    101fb0b35c5a4f4c08b919f1cb9777b0
 *
 * Watchguard FireBox (II ?)
 * da8e937880010000
 *
 * Nortel contivity 251 (RAS F/W Version: VA251_2.0.0.0.013 | 12/3/2003  
 *   DSL FW Version: Alcatel, Version 3.9.122)
 * 4485152d18b6bbcd0be8a8469579ddcc
 * 625027749d5ab97f5616c1602765cf480a3b7d0b)
 *
 * Zyxel Zywall 2 / Zywall 30w
 * 625027749d5ab97f5616c1602765cf480a3b7d0b
 */

#define MAX_LOG_VID_LEN            32

#define VID_KEEP                   0x0000  
#define VID_MD5HASH                0x0001
#define VID_STRING                 0x0002
#define VID_FSWAN_HASH             0x0004
#define VID_SELF                   0x0008

#define VID_SUBSTRING_DUMPHEXA     0x0100
#define VID_SUBSTRING_DUMPASCII    0x0200
#define VID_SUBSTRING_MATCH        0x0400
#define VID_SUBSTRING  (VID_SUBSTRING_DUMPHEXA | VID_SUBSTRING_DUMPASCII | VID_SUBSTRING_MATCH)

struct vid_struct {
	enum known_vendorid id;
	unsigned short flags;
	const char *data;
	const char *descr;
	const char *vid;
	unsigned int vid_len;
};

#define DEC_MD5_VID_D(id,str,descr) \
	{ VID_##id, VID_MD5HASH, str, descr, NULL, 0 },
#define DEC_MD5_VID(id,str) \
	{ VID_##id, VID_MD5HASH, str, NULL, NULL, 0 },
#define DEC_FSWAN_VID(id,str,descr) \
	{ VID_##id, VID_FSWAN_HASH, str, descr, NULL, 0 },

static struct vid_struct _vid_tab[] = {

	/* Implementation names */

	{ VID_OPENPGP, VID_STRING, "OpenPGP10171", "OpenPGP", NULL, 0 },

	DEC_MD5_VID(KAME_RACOON, "KAME/racoon")

	{ VID_MS_NT5, VID_MD5HASH | VID_SUBSTRING_DUMPHEXA,
		"MS NT5 ISAKMPOAKLEY", NULL, NULL, 0 },

	DEC_MD5_VID(SSH_SENTINEL, "SSH Sentinel")
	DEC_MD5_VID(SSH_SENTINEL_1_1, "SSH Sentinel 1.1")
	DEC_MD5_VID(SSH_SENTINEL_1_2, "SSH Sentinel 1.2")
	DEC_MD5_VID(SSH_SENTINEL_1_3, "SSH Sentinel 1.3")
	DEC_MD5_VID(SSH_SENTINEL_1_4, "SSH Sentinel 1.4")
	DEC_MD5_VID(SSH_SENTINEL_1_4_1, "SSH Sentinel 1.4.1")

	/* These ones come from SSH vendors.txt */
	DEC_MD5_VID(SSH_IPSEC_1_1_0,
		"Ssh Communications Security IPSEC Express version 1.1.0")
	DEC_MD5_VID(SSH_IPSEC_1_1_1,
		"Ssh Communications Security IPSEC Express version 1.1.1")
	DEC_MD5_VID(SSH_IPSEC_1_1_2,
		"Ssh Communications Security IPSEC Express version 1.1.2")
	DEC_MD5_VID(SSH_IPSEC_1_2_1,
		"Ssh Communications Security IPSEC Express version 1.2.1")
	DEC_MD5_VID(SSH_IPSEC_1_2_2,
		"Ssh Communications Security IPSEC Express version 1.2.2")
	DEC_MD5_VID(SSH_IPSEC_2_0_0,
		"SSH Communications Security IPSEC Express version 2.0.0")
	DEC_MD5_VID(SSH_IPSEC_2_1_0,
		"SSH Communications Security IPSEC Express version 2.1.0")
	DEC_MD5_VID(SSH_IPSEC_2_1_1,
		"SSH Communications Security IPSEC Express version 2.1.1")
	DEC_MD5_VID(SSH_IPSEC_2_1_2,
		"SSH Communications Security IPSEC Express version 2.1.2")
	DEC_MD5_VID(SSH_IPSEC_3_0_0,
		"SSH Communications Security IPSEC Express version 3.0.0")
	DEC_MD5_VID(SSH_IPSEC_3_0_1,
		"SSH Communications Security IPSEC Express version 3.0.1")
	DEC_MD5_VID(SSH_IPSEC_4_0_0,
		"SSH Communications Security IPSEC Express version 4.0.0")
	DEC_MD5_VID(SSH_IPSEC_4_0_1,
		"SSH Communications Security IPSEC Express version 4.0.1")
	DEC_MD5_VID(SSH_IPSEC_4_1_0,
		"SSH Communications Security IPSEC Express version 4.1.0")
	DEC_MD5_VID(SSH_IPSEC_4_2_0,
		"SSH Communications Security IPSEC Express version 4.2.0")


	/* note: md5('CISCO-UNITY') = 12f5f28c457168a9702d9fe274cc02d4 */
	{ VID_CISCO_UNITY, VID_KEEP, NULL, "Cisco-Unity",
		"\x12\xf5\xf2\x8c\x45\x71\x68\xa9\x70\x2d\x9f\xe2\x74\xcc\x01\x00",
		16 },

	{ VID_CISCO3K, VID_KEEP | VID_SUBSTRING_MATCH, 
          NULL, "Cisco VPN 3000 Series" , "\x1f\x07\xf7\x0e\xaa\x65\x14\xd3\xb0\xfa\x96\x54\x2a\x50", 14},

	{ VID_CISCO3K, VID_KEEP | VID_SUBSTRING_MATCH, 
          NULL, "Cisco VPN 3000 Series" , "\x1f\x07\xf7\x0e\xaa\x65\x14\xd3\xb0\xfa\x96\x54\x2a\x50", 14},

	{ VID_CISCO_IOS, VID_KEEP | VID_SUBSTRING_MATCH, 
	  NULL, "Cisco IOS Device", "\x3e\x98\x40\x48", 4},


	/**
	 * Timestep VID seen:
	 *   - 54494d455354455020312053475720313532302033313520322e303145303133
	 *     = 'TIMESTEP 1 SGW 1520 315 2.01E013'
	 */
	{ VID_TIMESTEP, VID_STRING | VID_SUBSTRING_DUMPASCII, "TIMESTEP",
		NULL, NULL, 0 },

	DEC_FSWAN_VID(FSWAN_2_00_VID,
		"Linux FreeS/WAN 2.00 PLUTO_SENDS_VENDORID",
		"FreeS/WAN 2.00")
	DEC_FSWAN_VID(FSWAN_2_00_X509_1_3_1_VID,
		"Linux FreeS/WAN 2.00 X.509-1.3.1 PLUTO_SENDS_VENDORID",
		"FreeS/WAN 2.00 (X.509-1.3.1)")
	DEC_FSWAN_VID(FSWAN_2_00_X509_1_3_1_LDAP_VID,
		"Linux FreeS/WAN 2.00 X.509-1.3.1 LDAP PLUTO_SENDS_VENDORID",
		"FreeS/WAN 2.00 (X.509-1.3.1 + LDAP)")
	DEC_FSWAN_VID(OPENSWAN2,
		"Openswan 2.2.0",
		"Openswan 2.2.0")

	/* always make sure to include ourself! */
	{ VID_OPENSWANSELF,VID_SELF, "","Openswan (this version)", NULL,0},
	

	/* NAT-Traversal */

	DEC_MD5_VID(NATT_STENBERG_01, "draft-stenberg-ipsec-nat-traversal-01")
	DEC_MD5_VID(NATT_STENBERG_02, "draft-stenberg-ipsec-nat-traversal-02")
	DEC_MD5_VID(NATT_HUTTUNEN, "ESPThruNAT")
	DEC_MD5_VID(NATT_HUTTUNEN_ESPINUDP, "draft-huttunen-ipsec-esp-in-udp-00.txt")
	DEC_MD5_VID(NATT_IETF_00, "draft-ietf-ipsec-nat-t-ike-00")
	DEC_MD5_VID(NATT_IETF_02, "draft-ietf-ipsec-nat-t-ike-02")
	/* hash in draft-ietf-ipsec-nat-t-ike-02 contains '\n'... Accept both */
	DEC_MD5_VID_D(NATT_IETF_02_N, "draft-ietf-ipsec-nat-t-ike-02\n", "draft-ietf-ipsec-nat-t-ike-02_n")
	DEC_MD5_VID(NATT_IETF_03, "draft-ietf-ipsec-nat-t-ike-03")
	DEC_MD5_VID(NATT_RFC, "RFC 3947")

	DEC_MD5_VID(NATT_DRAFT_IETF_IPSEC_NAT_T_IKE,"draft-ietf-ipsec-nat-t-ike")

	/* misc */

	
	{ VID_MISC_XAUTH, VID_KEEP, NULL, "XAUTH",
		"\x09\x00\x26\x89\xdf\xd6\xb7\x12", 8 },

	{ VID_MISC_DPD, VID_KEEP, NULL, "Dead Peer Detection",
		"\xaf\xca\xd7\x13\x68\xa1\xf1\xc9\x6b\x86\x96\xfc\x77\x57\x01\x00",
		16 },

	/**
	 * Netscreen:
	 * 4865617274426561745f4e6f74696679386b0100  (HeartBeat_Notify + 386b0100)
	 */
	{ VID_MISC_HEARTBEAT_NOTIFY, VID_STRING | VID_SUBSTRING_DUMPHEXA,
		"HeartBeat_Notify", "HeartBeat Notify", NULL, 0 },

	/**
	 * MacOS X
	 */
	{ VID_MACOSX, VID_STRING|VID_SUBSTRING_DUMPHEXA, "Mac OSX 10.x",
	  "\x4d\xf3\x79\x28\xe9\xfc\x4f\xd1\xb3\x26\x21\x70\xd5\x15\xc6\x62", NULL, 0},

	DEC_MD5_VID(MISC_FRAGMENTATION, "FRAGMENTATION")
	DEC_MD5_VID(INITIAL_CONTACT, "Vid-Initial-Contact")

	/*
	 * NCP.de
	 */
	{ VID_NCP, VID_KEEP, "NCP client", NULL, 
	  "\x10\x1f\xb0\xb3\x5c\x5a\x4f\x4c\x08\xb9\x19\xf1\xcb\x97\x77\xb0", 16 },
	

	/* -- */
	{ 0, 0, NULL, NULL, NULL, 0 }

};

static const char _hexdig[] = "0123456789abcdef";

static int _vid_struct_init = 0;

/** 
 * Setup VendorID structs, and populate them
 *
 */
void init_vendorid(void)
{
	struct vid_struct *vid;
	MD5_CTX ctx;
	int i;

	for (vid = _vid_tab; vid->id; vid++) {
	    if(vid->flags & VID_SELF) {
		char *d;
		vid->vid = strdup(init_pluto_vendorid());
		vid->vid_len = strlen(vid->vid);
		d = alloc_bytes(strlen(vid->descr)+4
				+strlen(ipsec_version_code())
				+strlen(compile_time_interop_options)
				, "self-vendor ID");
		sprintf(d, "%s %s %s"
			, vid->descr, ipsec_version_code()
			, compile_time_interop_options);
		vid->descr = (const char *)d;
	    }
	    else if (vid->flags & VID_STRING) {
		/** VendorID is a string **/
		vid->vid = strdup(vid->data);
		vid->vid_len = strlen(vid->data);
	    }
	    else if (vid->flags & VID_MD5HASH) {
		/** VendorID is a string to hash with MD5 **/
		char *vidm =  malloc(MD5_DIGEST_SIZE);
		vid->vid = vidm;
		if (vidm) {
		    unsigned const char *d = vid->data;
		    osMD5Init(&ctx);
		    osMD5Update(&ctx, d, strlen(vid->data));
		    osMD5Final(vidm, &ctx);
		    vid->vid_len = MD5_DIGEST_SIZE;
		}
	    }
	    else if (vid->flags & VID_FSWAN_HASH) {
		/** FreeS/WAN 2.00+ specific hash **/
#define FSWAN_VID_SIZE 12
		unsigned char hash[MD5_DIGEST_SIZE];
		char *vidm =  malloc(FSWAN_VID_SIZE);
		vid->vid = vidm;
		if (vidm) {
		    osMD5Init(&ctx);
		    osMD5Update(&ctx, vid->data, strlen(vid->data));
		    osMD5Final(hash, &ctx);
		    vidm[0] = 'O';
		    vidm[1] = 'E';
#if FSWAN_VID_SIZE - 2 <= MD5_DIGEST_SIZE
		    memcpy(vidm + 2, hash, FSWAN_VID_SIZE - 2);
#else
		    memcpy(vidm + 2, hash, MD5_DIGEST_SIZE);
		    memset(vidm + 2 + MD5_DIGEST_SIZE, '\0',
			   FSWAN_VID_SIZE - 2 - MD5_DIGEST_SIZE);
#endif
		    for (i = 2; i < FSWAN_VID_SIZE; i++) {
			vidm[i] &= 0x7f;
			vidm[i] |= 0x40;
		    }
		    vid->vid_len = FSWAN_VID_SIZE;
		}
	    }
	    
	    if (vid->descr == NULL) {
		/** Find something to display **/
		vid->descr = vid->data;
	    }
#if 0
	    DBG_log("vendorid_init: %d [%s]",
		    vid->id,
		    vid->descr ? vid->descr : ""
		);
	    if (vid->vid) DBG_dump("VID:", vid->vid, vid->vid_len);
#endif
	}
	_vid_struct_init = 1;
}


/**
 * Handle Known VendorID's.  This function parses what the remote peer 
 * sends us, and enables/disables features based on it.  As we go along, 
 * we set vid_usefull =1 if we did something based on this VendorID.  This
 * supresses the 'Ignored VendorID ...' log message.
 *
 * @param md UNUSED - Deprecated
 * @param vidstr VendorID String
 * @param len Length of vidstr
 * @param vid VendorID Struct (see vendor.h)
 * @param st State Structure (Hopefully initialized)
 * @return void
 */
static void handle_known_vendorid (struct msg_digest *md UNUSED
				   , const char *vidstr
				   , size_t len
				   , struct vid_struct *vid
				   , struct state *st UNUSED)
{
	char vid_dump[128];
	int vid_usefull = 0;
	size_t i, j;

	switch (vid->id) {
#ifdef NAT_TRAVERSAL
	    /**
	     * Use most recent supported NAT-Traversal method and ignore
	     * the other ones (implementations will send all supported
	     * methods but only one will be used)
	     *
	     * Note: most recent == higher id in vendor.h
	     */

	    /* PAUL TRY THIS IF BELOW FAILS WITH APPLE */
	    /*case VID_NATT_DRAFT_IETF_IPSEC_NAT_T_IKE: */
	case VID_NATT_IETF_00:
	    if (!nat_traversal_support_non_ike)
		break;
	    vid_usefull = 1;
	    if ((nat_traversal_enabled) && (!md->quirks.nat_traversal_vid)) {
		md->quirks.nat_traversal_vid = vid->id;
	    }
	    break;
	case VID_NATT_IETF_02:
	case VID_NATT_IETF_02_N:
	case VID_NATT_IETF_03:
	case VID_NATT_DRAFT_IETF_IPSEC_NAT_T_IKE:
	case VID_NATT_RFC:
	    vid_usefull = 1;
	    if(!nat_traversal_support_port_floating) {
		loglog(RC_LOG_SERIOUS
		       , "received Vendor ID payload [%s] meth=%d, "
		       "but port floating is off"
		       , vid->descr, vid->id);
		return;
	    } else {
		if (md->quirks.nat_traversal_vid < vid->id) {
		    loglog(RC_LOG_SERIOUS
			   , "received Vendor ID payload [%s] method set to=%d "
			   , vid->descr, vid->id);
		    md->quirks.nat_traversal_vid = vid->id;
		    return;
		} else {
		    loglog(RC_LOG_SERIOUS
			   , "received Vendor ID payload [%s] meth=%d, "
			   "but already using method %d"
			   , vid->descr, vid->id
			   , md->quirks.nat_traversal_vid);
		    return;
		}
	    }
	    break;
#endif
	    
        case VID_MISC_DPD:
	    /* Remote side would like to do DPD with us on this connection */
	    md->dpd = 1;
	    vid_usefull = 1;
            break;

/* We only need these when dealing with XAUTH */
#ifdef XAUTH
	case VID_SSH_SENTINEL_1_4_1:
	  loglog(RC_LOG_SERIOUS
		 , "SSH Sentinel 1.4.1 found, setting XAUTH_ACK quirk");
	  md->quirks.xauth_ack_msgid = TRUE;
	  vid_usefull = 1;
	  break;

	case VID_CISCO_UNITY:
	  md->quirks.modecfg_pull_mode= TRUE;
	  vid_usefull = 1;
	  break;

	case VID_MISC_XAUTH:
	    vid_usefull=1;
	    break;
#endif
	    
	case VID_OPENSWANSELF:
	    vid_usefull=1;
	    break;
	    
	default:
	    break;
	}

	if (vid->flags & VID_SUBSTRING_DUMPHEXA) {
		/* Dump description + Hexa */
		memset(vid_dump, 0, sizeof(vid_dump));
		snprintf(vid_dump, sizeof(vid_dump), "%s ",
			vid->descr ? vid->descr : "");
		for (i=strlen(vid_dump), j=vid->vid_len;
			(j<len) && (i<sizeof(vid_dump)-2);
			i+=2, j++) {
			vid_dump[i] = _hexdig[(vidstr[j] >> 4) & 0xF];
			vid_dump[i+1] = _hexdig[vidstr[j] & 0xF];
		}
	}
	else if (vid->flags & VID_SUBSTRING_DUMPASCII) {
		/* Dump ASCII content */
		memset(vid_dump, 0, sizeof(vid_dump));
		for (i=0; (i<len) && (i<sizeof(vid_dump)-1); i++) {
			vid_dump[i] = (isprint(vidstr[i])) ? vidstr[i] : '.';
		}
	}
	else {
		/* Dump description (descr) */
		snprintf(vid_dump, sizeof(vid_dump), "%s",
			vid->descr ? vid->descr : "");
	}

	loglog(RC_LOG_SERIOUS, "%s Vendor ID payload [%s]",
		vid_usefull ? "received" : "ignoring", vid_dump);
}


/**
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
void handle_vendorid (struct msg_digest *md, const char *vid, size_t len, struct state *st)
{
	struct vid_struct *pvid;

	if (!_vid_struct_init) {
		init_vendorid();
	}

	/*
	 * Find known VendorID in _vid_tab
	 */
	for (pvid = _vid_tab; pvid->id; pvid++) {
		if (pvid->vid && vid && pvid->vid_len && len) {
			if (pvid->vid_len == len) {
				if (memcmp(pvid->vid, vid, len)==0) {
					handle_known_vendorid(md, vid
							      , len, pvid, st);
					return;
				}
			}
			else if ((pvid->vid_len < len)
				 && (pvid->flags & VID_SUBSTRING)) {
				if (memcmp(pvid->vid, vid, pvid->vid_len)==0) {
					handle_known_vendorid(md, vid, len
							      , pvid, st);
					return;
				}
			}
		}
	}

	/*
	 * Unknown VendorID. Log the beginning.
	 */
	{
		char log_vid[2*MAX_LOG_VID_LEN+1];
		size_t i;
		memset(log_vid, 0, sizeof(log_vid));
		for (i=0; (i<len) && (i<MAX_LOG_VID_LEN); i++) {
			log_vid[2*i] = _hexdig[(vid[i] >> 4) & 0xF];
			log_vid[2*i+1] = _hexdig[vid[i] & 0xF];
		}
		loglog(RC_LOG_SERIOUS, "ignoring unknown Vendor ID payload [%s%s]",
			log_vid, (len>MAX_LOG_VID_LEN) ? "..." : "");
	}
}

/**
 * Add a vendor id payload to the msg
 *
 * @param np
 * @param outs PB stream
 * @param vid Int of VendorID to be sent (see vendor.h for the list)
 * @return bool True if successful
 */
bool out_vendorid (u_int8_t np, pb_stream *outs, unsigned int vid)
{
	struct vid_struct *pvid;

	if (!_vid_struct_init) {
		init_vendorid();
	}

	for (pvid = _vid_tab; (pvid->id) && (pvid->id!=vid); pvid++);

	if (pvid->id != vid) return STF_INTERNAL_ERROR; /* not found */
	if (!pvid->vid) return STF_INTERNAL_ERROR; /* not initialized */

	DBG(DBG_EMITTING,
		DBG_log("out_vendorid(): sending [%s]", pvid->descr);
	);

	if (!out_modify_previous_np(ISAKMP_NEXT_VID, outs))
		return FALSE;

	return out_generic_raw(np, &isakmp_vendor_id_desc, outs,
		pvid->vid, pvid->vid_len, "V_ID");
}

/* OpenPGP Vendor ID needed for interoperability with PGPnet
 *
 * Note: it is a NUL-terminated ASCII string, but NUL won't go on the wire.
 */
char pgp_vendorid[] = "OpenPGP10171";
const int pgp_vendorid_len = sizeof(pgp_vendorid);

char dpd_vendorid[] = {0xAF, 0xCA, 0xD7, 0x13, 0x68, 0xA1, 0xF1,
          0xC9, 0x6B, 0x86, 0x96, 0xFC, 0x77, 0x57, 0x01, 0x00};
const int dpd_vendorid_len = sizeof(dpd_vendorid);



/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
