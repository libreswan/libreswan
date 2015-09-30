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
 */

#include "libreswan/ipsec_sa.h"

#ifdef CONFIG_KLIPS_OCF
#include <cryptodev.h>
#endif

enum ipsec_xmit_value {
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

#define IPSEC_XSM_INIT1                 0       /* make it easy, starting state is 0 */
#define IPSEC_XSM_INIT2                 1
#define IPSEC_XSM_ENCAP_INIT    2
#define IPSEC_XSM_ENCAP_SELECT  3
#define IPSEC_XSM_ESP                   4
#define IPSEC_XSM_ESP_AH                5
#define IPSEC_XSM_AH                    6
#define IPSEC_XSM_IPIP                  7
#define IPSEC_XSM_IPCOMP                8
#define IPSEC_XSM_CONT                  9
#define IPSEC_XSM_DONE                  100

struct ipsec_xmit_state {
	struct sk_buff *skb;            /* working skb pointer */
	struct sk_buff *pre_ipcomp_skb; /* skb before ipcomp was attempted */
	struct net_device *dev;         /* working dev pointer */
	struct ipsecpriv *iprv;         /* Our device' private space */
	struct mastpriv *mprv;
	struct sk_buff *oskb;           /* Original skb pointer */
	struct net_device_stats *stats; /* This device's statistics */
	void    *iph;                   /* Our new IP header */

	ip_address orgedst;             /* 1st SG's IP address */

	int iphlen;                     /* IP header length */
	int pyldsz;                     /* upper protocol payload size */
	int headroom;
	int tailroom;
	int authlen;
	int max_headroom;               /* The extra header space needed */
	int max_tailroom;               /* The extra stuffing needed */
	int ll_headroom;                /* The extra link layer hard_header space needed */
	int tot_headroom;               /* The total header space needed */
	int tot_tailroom;               /* The totalstuffing needed */
	__u8    *saved_header;          /* saved copy of the hard header */
	unsigned short sport, dport;

	struct sockaddr_encap matcher;  /* eroute search key */
	struct eroute *eroute;
	struct ipsec_sa *ipsp;          /* ipsec_sa pointers */
	char sa_txt[SATOT_BUF];
	size_t sa_len;
	int hard_header_stripped;       /* has the hard header been removed yet? */
	int hard_header_len;
	struct net_device *physdev;
	short physmtu;
	short cur_mtu;          /* copy of prv->mtu, cause prv may == NULL */
	short mtudiff;
	__u8 next_header;       /* protocol of the nested header */
	struct rtable *route;
	ip_said outgoing_said;
	int pass;
	uint32_t eroute_pid;
	struct ipsec_sa ips;
	uint8_t natt_type;
	uint8_t natt_head;
	uint16_t natt_sport;
	uint16_t natt_dport;

	/*
	 * xmit flags
	 */
	uint16_t mast_mode : 1;
	uint16_t set_dst : 1;

	/* if carrying IPv6,  IPPROTO_IPV6, else IPPROTO_IPIP */
	uint8_t ipip_proto;

	/*
	 * xmit state machine use
	 */
	void (*xsm_complete)(struct ipsec_xmit_state *ixs,
			     enum ipsec_xmit_value stat);
	int state;
	int next_state;
#ifdef CONFIG_KLIPS_ALG
	struct ipsec_alg_auth *ixt_a;
	struct ipsec_alg_enc *ixt_e;
#endif
#ifdef CONFIG_KLIPS_ESP
	struct esphdr *espp;
	unsigned char *idat;
#endif  /* !CONFIG_KLIPS_ESP */
	int blocksize;
	int ilen, len;
	unsigned char *dat;
	__u8 frag_off, tos;
	__u16 ttl, check;
};

extern enum ipsec_xmit_value ipsec_xmit_sanity_check_ipsec_dev(
	struct ipsec_xmit_state *ixs);

extern enum ipsec_xmit_value ipsec_xmit_sanity_check_mast_dev(
	struct ipsec_xmit_state *ixs);

extern enum ipsec_xmit_value ipsec_xmit_sanity_check_skb(
	struct ipsec_xmit_state *ixs);

extern enum ipsec_xmit_value ipsec_xmit_encap_bundle(
	struct ipsec_xmit_state *ixs);

extern void ipsec_xsm(struct ipsec_xmit_state *ixs);
#ifdef HAVE_KMEM_CACHE_T
extern kmem_cache_t *ipsec_ixs_cache;
#else
extern struct kmem_cache *ipsec_ixs_cache;
#endif
extern int ipsec_ixs_max;
extern atomic_t ipsec_ixs_cnt;

extern void ipsec_extract_ports(struct sk_buff *skb, unsigned char nexthdr,
				int nexthdroff, struct sockaddr_encap * er);

extern enum ipsec_xmit_value ipsec_xmit_send(struct ipsec_xmit_state *ixs);

extern enum ipsec_xmit_value ipsec_nat_encap(struct ipsec_xmit_state *ixs);

extern enum ipsec_xmit_value ipsec_tunnel_send(struct ipsec_xmit_state *ixs);

extern void ipsec_xmit_cleanup(struct ipsec_xmit_state *ixs);

extern int ipsec_xmit_trap_count;
extern int ipsec_xmit_trap_sendcount;

extern int debug_xmit;
extern int debug_mast;

#define ipsec_xmit_dmp(_x, _y, _z) { \
		if (debug_xmit && sysctl_ipsec_debug_verbose) \
			ipsec_dmp_block(_x, _y, _z); \
	}

extern int sysctl_ipsec_debug_verbose;
extern int sysctl_ipsec_icmp;
extern int sysctl_ipsec_tos;
