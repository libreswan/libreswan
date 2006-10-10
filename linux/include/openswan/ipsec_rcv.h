/*
 * 
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
 * RCSID $Id: ipsec_rcv.h,v 1.28.2.1 2006/07/10 15:52:20 paul Exp $
 */

#ifndef IPSEC_RCV_H
#define IPSEC_RCV_H

#include "openswan/ipsec_auth.h"

#define DB_RX_PKTRX	0x0001
#define DB_RX_PKTRX2	0x0002
#define DB_RX_DMP	0x0004
#define DB_RX_IPSA	0x0010
#define DB_RX_XF	0x0020
#define DB_RX_IPAD	0x0040
#define DB_RX_INAU	0x0080
#define DB_RX_OINFO	0x0100
#define DB_RX_OINFO2	0x0200
#define DB_RX_OH	0x0400
#define DB_RX_REPLAY	0x0800

#ifdef __KERNEL__
/* struct options; */

#define __NO_VERSION__
#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif	/* for CONFIG_IP_FORWARD */
#ifdef CONFIG_MODULES
#include <linux/module.h>
#endif
#include <linux/version.h>
#include <openswan.h>

#define IPSEC_BIRTH_TEMPLATE_MAXLEN 256

struct ipsec_birth_reply {
  int            packet_template_len;
  unsigned char  packet_template[IPSEC_BIRTH_TEMPLATE_MAXLEN];
};

extern struct ipsec_birth_reply ipsec_ipv4_birth_packet;
extern struct ipsec_birth_reply ipsec_ipv6_birth_packet;

enum ipsec_rcv_value {
	IPSEC_RCV_LASTPROTO=1,
	IPSEC_RCV_OK=0,
	IPSEC_RCV_BADPROTO=-1,
	IPSEC_RCV_BADLEN=-2,
	IPSEC_RCV_ESP_BADALG=-3,
	IPSEC_RCV_3DES_BADBLOCKING=-4,
	IPSEC_RCV_ESP_DECAPFAIL=-5,
	IPSEC_RCV_DECAPFAIL=-6,
	IPSEC_RCV_SAIDNOTFOUND=-7,
	IPSEC_RCV_IPCOMPALONE=-8,
	IPSEC_RCV_IPCOMPFAILED=-10,
	IPSEC_RCV_SAIDNOTLIVE=-11,
	IPSEC_RCV_FAILEDINBOUND=-12,
	IPSEC_RCV_LIFETIMEFAILED=-13,
	IPSEC_RCV_BADAUTH=-14,
	IPSEC_RCV_REPLAYFAILED=-15,
	IPSEC_RCV_AUTHFAILED=-16,
	IPSEC_RCV_REPLAYROLLED=-17,
	IPSEC_RCV_BAD_DECRYPT=-18
};

struct ipsec_rcv_state {
	struct sk_buff *skb;
	struct net_device_stats *stats;
	struct iphdr    *ipp;          /* the IP header */
	struct ipsec_sa *ipsp;         /* current SA being processed */
	int len;                       /* length of packet */
	int ilen;                      /* length of inner payload (-authlen) */
	int authlen;                   /* how big is the auth data at end */
	int hard_header_len;           /* layer 2 size */
	int iphlen;                    /* how big is IP header */
	struct auth_alg *authfuncs;
	ip_said said;
	char   sa[SATOT_BUF];
	size_t sa_len;
	__u8 next_header;
	__u8 hash[AH_AMAX];
	char ipsaddr_txt[ADDRTOA_BUF];
	char ipdaddr_txt[ADDRTOA_BUF];
	__u8 *octx;
	__u8 *ictx;
	int ictx_len;
	int octx_len;
	union {
		struct {
			struct esphdr *espp;
		} espstuff;
		struct {
			struct ahhdr *ahp;
		} ahstuff;
		struct {
			struct ipcomphdr *compp;
		} ipcompstuff;
	} protostuff;
#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
	__u8		natt_type;
	__u16		natt_sport;
	__u16		natt_dport;
	int             natt_len; 
#endif  
};

extern int
#ifdef PROTO_HANDLER_SINGLE_PARM
ipsec_rcv(struct sk_buff *skb);
#else /* PROTO_HANDLER_SINGLE_PARM */
ipsec_rcv(struct sk_buff *skb,
	  unsigned short xlen);
#endif /* PROTO_HANDLER_SINGLE_PARM */

#ifdef CONFIG_KLIPS_DEBUG
extern int debug_rcv;
#define ipsec_rcv_dmp(_x,_y, _z) if (debug_rcv && sysctl_ipsec_debug_verbose) ipsec_dmp_block(_x,_y,_z)
#else
#define ipsec_rcv_dmp(_x,_y, _z) do {} while(0)
#endif /* CONFIG_KLIPS_DEBUG */

extern int sysctl_ipsec_inbound_policy_check;
#endif /* __KERNEL__ */

extern int klips26_rcv_encap(struct sk_buff *skb, __u16 encap_type);

// manage ipsec rcv state objects
extern int ipsec_rcv_state_cache_init (void);
extern void ipsec_rcv_state_cache_cleanup (void);

#endif /* IPSEC_RCV_H */

/*
 * $Log: ipsec_rcv.h,v $
 * Revision 1.28.2.1  2006/07/10 15:52:20  paul
 * Fix for bug #642 by Bart Trojanowski
 *
 * Revision 1.28  2005/05/11 00:59:45  mcr
 * 	do not call debug routines if !defined KLIPS_DEBUG.
 *
 * Revision 1.27  2005/04/29 04:59:46  mcr
 * 	use ipsec_dmp_block.
 *
 * Revision 1.26  2005/04/13 22:48:35  mcr
 * 	added comments, and removed some log.
 * 	removed Linux 2.0 support.
 *
 * Revision 1.25  2005/04/08 18:25:37  mcr
 * 	prototype klips26 encap receive function
 *
 * Revision 1.24  2004/08/20 21:45:37  mcr
 * 	CONFIG_KLIPS_NAT_TRAVERSAL is not used in an attempt to
 * 	be 26sec compatible. But, some defines where changed.
 *
 * Revision 1.23  2004/08/03 18:17:40  mcr
 * 	in 2.6, use "net_device" instead of #define device->net_device.
 * 	this probably breaks 2.0 compiles.
 *
 * Revision 1.22  2004/07/10 19:08:41  mcr
 * 	CONFIG_IPSEC -> CONFIG_KLIPS.
 *
 * Revision 1.21  2004/04/06 02:49:08  mcr
 * 	pullup of algo code from alg-branch.
 *
 * Revision 1.20  2004/04/05 19:55:06  mcr
 * Moved from linux/include/freeswan/ipsec_rcv.h,v
 *
 * Revision 1.19  2003/12/15 18:13:09  mcr
 * 	when compiling with NAT traversal, don't assume that the
 * 	kernel has been patched, unless CONFIG_IPSEC_NAT_NON_ESP
 * 	is set.
 *
 * history elided 2005-04-12.
 *
 * Local Variables:
 * c-basic-offset:8
 * c-style:linux
 * End:
 *
 */


