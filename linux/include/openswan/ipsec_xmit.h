/*
 * IPSEC tunneling code
 * Copyright (C) 1996, 1997  John Ioannidis.
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003  Richard Guy Briggs.
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
 * RCSID $Id: ipsec_xmit.h,v 1.14 2005/05/11 01:00:26 mcr Exp $
 */

#include "openswan/ipsec_sa.h"

#ifdef CONFIG_KLIPS_OCF
#include <crypto/cryptodev.h>
#endif

enum ipsec_xmit_value
{
	IPSEC_XMIT_STOLEN=2,
	IPSEC_XMIT_PASS=1,
	IPSEC_XMIT_OK=0,
	IPSEC_XMIT_ERRMEMALLOC=-1,
	IPSEC_XMIT_ESP_BADALG=-2,
	IPSEC_XMIT_BADPROTO=-3,
	IPSEC_XMIT_ESP_PUSHPULLERR=-4,
	IPSEC_XMIT_BADLEN=-5,
	IPSEC_XMIT_AH_BADALG=-6,
	IPSEC_XMIT_SAIDNOTFOUND=-7,
	IPSEC_XMIT_SAIDNOTLIVE=-8,
	IPSEC_XMIT_REPLAYROLLED=-9,
	IPSEC_XMIT_LIFETIMEFAILED=-10,
	IPSEC_XMIT_CANNOTFRAG=-11,
	IPSEC_XMIT_MSSERR=-12,
	IPSEC_XMIT_ERRSKBALLOC=-13,
	IPSEC_XMIT_ENCAPFAIL=-14,
	IPSEC_XMIT_NODEV=-15,
	IPSEC_XMIT_NOPRIVDEV=-16,
	IPSEC_XMIT_NOPHYSDEV=-17,
	IPSEC_XMIT_NOSKB=-18,
	IPSEC_XMIT_NOIPV6=-19,
	IPSEC_XMIT_NOIPOPTIONS=-20,
	IPSEC_XMIT_TTLEXPIRED=-21,
	IPSEC_XMIT_BADHHLEN=-22,
	IPSEC_XMIT_PUSHPULLERR=-23,
	IPSEC_XMIT_ROUTEERR=-24,
	IPSEC_XMIT_RECURSDETECT=-25,
	IPSEC_XMIT_IPSENDFAILURE=-26,
	IPSEC_XMIT_ESPUDP=-27,
	IPSEC_XMIT_ESPUDP_BADTYPE=-28,
	IPSEC_XMIT_PENDING=-29,
};


/*
 * state machine states
 */

#define IPSEC_XSM_INIT			0	/* make it easy, starting state is 0 */
#define IPSEC_XSM_ENCAP_INIT	1
#define IPSEC_XSM_ENCAP_SELECT	2
#define IPSEC_XSM_ESP			3
#define IPSEC_XSM_ESP_AH		4
#define IPSEC_XSM_AH			5
#define IPSEC_XSM_IPIP			6
#define IPSEC_XSM_IPCOMP		7
#define IPSEC_XSM_CONT			8
#define IPSEC_XSM_DONE 			100


struct ipsec_xmit_state
{
	struct sk_buff *skb;		/* working skb pointer */
	struct net_device *dev;		/* working dev pointer */
	struct ipsecpriv *prv;		/* Our device' private space */
	struct sk_buff *oskb;		/* Original skb pointer */
	struct net_device_stats *stats;	/* This device's statistics */
	struct iphdr  *iph;		/* Our new IP header */
	__u32   newdst;			/* The other SG's IP address */
	__u32	orgdst;			/* Original IP destination address */
	__u32	orgedst;		/* 1st SG's IP address */
	__u32   newsrc;			/* The new source SG's IP address */
	__u32	orgsrc;			/* Original IP source address */
	__u32	innersrc;		/* Innermost IP source address */
	int	iphlen;			/* IP header length */
	int	pyldsz;			/* upper protocol payload size */
	int	headroom;
	int	tailroom;
        int     authlen;
	int     max_headroom;		/* The extra header space needed */
	int	max_tailroom;		/* The extra stuffing needed */
	int     ll_headroom;		/* The extra link layer hard_header space needed */
	int     tot_headroom;		/* The total header space needed */
	int	tot_tailroom;		/* The totalstuffing needed */
	__u8	*saved_header;		/* saved copy of the hard header */
	unsigned short   sport, dport;

	struct sockaddr_encap matcher;	/* eroute search key */
	struct eroute *eroute;
	struct ipsec_sa *ipsp, *ipsq;	/* ipsec_sa pointers */
	char sa_txt[SATOT_BUF];
	size_t sa_len;
	int hard_header_stripped;	/* has the hard header been removed yet? */
	int hard_header_len;
	struct net_device *physdev;
/*	struct device *virtdev; */
	short physmtu;
	short cur_mtu;          /* copy of prv->mtu, cause prv may == NULL */
	short mtudiff;
#ifdef NET_21
	struct rtable *route;
#endif /* NET_21 */
	ip_said outgoing_said;
#ifdef NET_21
	int pass;
#endif /* NET_21 */
	int error;
	uint32_t eroute_pid;
	struct ipsec_sa ips;
#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
	uint8_t natt_type;
	uint8_t natt_head;
	uint16_t natt_sport;
	uint16_t natt_dport;
#endif

	/*
	 * xmit state machine use
	 */
	void (*xsm_complete)(struct ipsec_xmit_state *ixs,
			enum ipsec_xmit_value stat);
	int		state;
	int		next_state;
#ifdef CONFIG_KLIPS_OCF
	struct work_struct	workq;
#endif
	struct ipsec_alg_auth *ixt_a;
	struct ipsec_alg_enc *ixt_e;
#ifdef CONFIG_KLIPS_ESP
	struct esphdr *espp;
	unsigned char *idat;
#endif /* !CONFIG_KLIPS_ESP */
	int blocksize;
	int ilen, len;
	unsigned char *dat;
	__u8 frag_off, tos;
	__u16 ttl, check;
};

enum ipsec_xmit_value
ipsec_xmit_sanity_check_dev(struct ipsec_xmit_state *ixs);

enum ipsec_xmit_value
ipsec_xmit_sanity_check_skb(struct ipsec_xmit_state *ixs);

enum ipsec_xmit_value
ipsec_xmit_encap_bundle(struct ipsec_xmit_state *ixs);

extern void ipsec_xsm(struct ipsec_xmit_state *ixs);

extern void ipsec_extract_ports(struct iphdr * iph, struct sockaddr_encap * er);


extern int ipsec_xmit_trap_count;
extern int ipsec_xmit_trap_sendcount;

#ifdef CONFIG_KLIPS_DEBUG
extern int debug_tunnel;

#define debug_xmit debug_tunnel

#define ipsec_xmit_dmp(_x,_y, _z) if (debug_xmit && sysctl_ipsec_debug_verbose) ipsec_dmp_block(_x,_y,_z)
#else
#define ipsec_xmit_dmp(_x,_y, _z) do {} while(0)

#endif /* CONFIG_KLIPS_DEBUG */

extern int sysctl_ipsec_debug_verbose;
extern int sysctl_ipsec_icmp;
extern int sysctl_ipsec_tos;


/*
 * $Log: ipsec_xmit.h,v $
 * Revision 1.14  2005/05/11 01:00:26  mcr
 * 	do not call debug routines if !defined KLIPS_DEBUG.
 *
 * Revision 1.13  2005/04/29 05:01:38  mcr
 * 	use ipsec_dmp_block.
 * 	added cur_mtu to ixs instead of using ixs->dev.
 *
 * Revision 1.12  2004/08/20 21:45:37  mcr
 * 	CONFIG_KLIPS_NAT_TRAVERSAL is not used in an attempt to
 * 	be 26sec compatible. But, some defines where changed.
 *
 * Revision 1.11  2004/08/03 18:18:21  mcr
 * 	in 2.6, use "net_device" instead of #define device->net_device.
 * 	this probably breaks 2.0 compiles.
 *
 * Revision 1.10  2004/07/10 19:08:41  mcr
 * 	CONFIG_IPSEC -> CONFIG_KLIPS.
 *
 * Revision 1.9  2004/04/06 02:49:08  mcr
 * 	pullup of algo code from alg-branch.
 *
 * Revision 1.8  2004/04/05 19:55:07  mcr
 * Moved from linux/include/freeswan/ipsec_xmit.h,v
 *
 * Revision 1.7  2004/02/03 03:11:40  mcr
 * 	new xmit type if the UDP encapsulation is wrong.
 *
 * Revision 1.6  2003/12/13 19:10:16  mcr
 * 	refactored rcv and xmit code - same as FS 2.05.
 *
 * Revision 1.5  2003/12/10 01:20:06  mcr
 * 	NAT-traversal patches to KLIPS.
 *
 * Revision 1.4  2003/12/06 16:37:04  mcr
 * 	1.4.7a X.509 patch applied.
 *
 * Revision 1.3  2003/10/31 02:27:05  mcr
 * 	pulled up port-selector patches and sa_id elimination.
 *
 * Revision 1.2.4.2  2003/10/29 01:10:19  mcr
 * 	elimited "struct sa_id"
 *
 * Revision 1.2.4.1  2003/09/21 13:59:38  mcr
 * 	pre-liminary X.509 patch - does not yet pass tests.
 *
 * Revision 1.2  2003/06/20 01:42:13  mcr
 * 	added counters to measure how many ACQUIREs we send to pluto,
 * 	and how many are successfully sent.
 *
 * Revision 1.1  2003/02/12 19:31:03  rgb
 * Refactored from ipsec_tunnel.c
 *
 */
