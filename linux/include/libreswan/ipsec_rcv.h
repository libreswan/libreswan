/*
 *
 * Copyright (C) 1996, 1997  John Ioannidis.
 * Copyright (C) 1998, 1999, 2000, 2001  Richard Guy Briggs.
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
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

#ifndef IPSEC_RCV_H
#define IPSEC_RCV_H

#include "libreswan/ipsec_auth.h"

#define DB_RX_PKTRX     0x0001
#define DB_RX_PKTRX2    0x0002
#define DB_RX_DMP       0x0004
#define DB_RX_IPSA      0x0010
#define DB_RX_XF        0x0020
#define DB_RX_IPAD      0x0040
#define DB_RX_INAU      0x0080
#define DB_RX_OINFO     0x0100
#define DB_RX_OINFO2    0x0200
#define DB_RX_OH        0x0400
#define DB_RX_REPLAY    0x0800

#ifdef __KERNEL__
/* struct options; */

#define __NO_VERSION__
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38) && \
	!defined(AUTOCONF_INCLUDED)
#include <linux/config.h>
#endif  /* for CONFIG_IP_FORWARD */
#ifdef CONFIG_MODULES
#include <linux/module.h>
#endif
#include <libreswan.h>

#ifdef CONFIG_KLIPS_OCF
#include <cryptodev.h>
#endif

#define IPSEC_BIRTH_TEMPLATE_MAXLEN 256

struct ipsec_birth_reply {
	int packet_template_len;
	unsigned char packet_template[IPSEC_BIRTH_TEMPLATE_MAXLEN];
};

extern struct ipsec_birth_reply ipsec_ipv4_birth_packet;
extern struct ipsec_birth_reply ipsec_ipv6_birth_packet;

enum ipsec_rcv_value {
	IPSEC_RCV_PENDING=2,
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
	IPSEC_RCV_BAD_DECRYPT=-18,
	IPSEC_RCV_REALLYBAD=-19,
	IPSEC_RCV_ERRMEMALLOC=-20
};

/*
 * state machine states
 */

#define IPSEC_RSM_INIT                  0       /* make it easy, starting state is 0 */
#define IPSEC_RSM_DECAP_INIT    1
#define IPSEC_RSM_DECAP_LOOKUP  2
#define IPSEC_RSM_AUTH_INIT             3
#define IPSEC_RSM_AUTH_DECAP    4
#define IPSEC_RSM_AUTH_CALC             5
#define IPSEC_RSM_AUTH_CHK              6
#define IPSEC_RSM_DECRYPT               7
#define IPSEC_RSM_DECAP_CONT    8       /* do we restart at IPSEC_RSM_DECAP_INIT */
#define IPSEC_RSM_CLEANUP               9
#define IPSEC_RSM_IPCOMP                10
#define IPSEC_RSM_COMPLETE              11
#define IPSEC_RSM_DONE                  100

struct ipsec_rcv_state {
	struct sk_buff *skb;
	struct sk_buff *pre_ipcomp_skb; /* skb before ipcomp was attempted */
	struct net_device_stats *stats;
	void *iph;                      /* the IP header */
	struct ipsec_sa *ipsp;          /* current SA being processed */
	struct ipsec_sa *lastipsp;      /* last SA that was processed */
	int len;                        /* length of packet */
	int ilen;                       /* length of inner payload (-authlen) */
	int authlen;                    /* how big is the auth data at end */
	int hard_header_len;            /* layer 2 size */
	int iphlen;                     /* how big is IP header */
	unsigned int transport_direct : 1;
	struct auth_alg *authfuncs;
	ip_said said;
	char sa[SATOT_BUF];
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
	__u8 natt_type;
	__u16 natt_sport;
	__u16 natt_dport;
	int natt_len;

	/*
	 * rcv state machine use
	 */
	int state;
	int next_state;
	int auth_checked;
	struct xform_functions *proto_funcs;
	__u8 proto;
	int replay;
	unsigned char *authenticator;
	int esphlen;
#ifdef CONFIG_KLIPS_ALG
	struct ipsec_alg_auth *ixt_a;
#endif
	__u8 ttl, tos;
	__u16 frag_off, check;
};

extern void ipsec_rsm(struct ipsec_rcv_state *irs);
#ifdef HAVE_KMEM_CACHE_T
extern kmem_cache_t *ipsec_irs_cache;
#else
extern struct kmem_cache *ipsec_irs_cache;
#endif
extern int ipsec_irs_max;
extern atomic_t ipsec_irs_cnt;

extern int ipsec_rcv(struct sk_buff *skb);

extern int sysctl_ipsec_inbound_policy_check;
extern int debug_rcv;
#define ipsec_rcv_dmp(_x, _y, _z) { \
		if (debug_rcv && sysctl_ipsec_debug_verbose) \
			ipsec_dmp_block((_x), (_y), (_z)); \
	}
#else
#define ipsec_rcv_dmp(_x, _y, _z) { }
#endif /* __KERNEL__ */

extern int klips26_udp_encap_rcv(struct sock *sk, struct sk_buff *skb);
extern int klips26_rcv_encap(struct sk_buff *skb, __u16 encap_type);

// manage ipsec rcv state objects
extern int ipsec_rcv_state_cache_init(void);
extern void ipsec_rcv_state_cache_cleanup(void);

#endif /* IPSEC_RCV_H */

