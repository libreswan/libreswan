/*
 * @(#) prototypes for FreeSWAN functions
 *
 * Copyright (C) 2001  Richard Guy Briggs  <rgb@freeswan.org>
 *                 and Michael Richardson  <mcr@freeswan.org>
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

#ifndef _IPSEC_PROTO_H_

#include "ipsec_param.h"

/*
 * This file is a kernel only file that declares prototypes for
 * all intra-module function calls and global data structures.
 *
 * Include this file last.
 *
 */

/* forward references */
enum ipsec_direction;
enum ipsec_life_type;
struct ipsec_lifetime64;
struct ident;
struct sockaddr_encap;
struct ipsec_sa;

/* ipsec_init.c */
extern struct prng ipsec_prng;

/* ipsec_sa.c */
extern struct ipsec_sa *ipsec_sadb_hash[SADB_HASHMOD];
extern spinlock_t tdb_lock;
extern int ipsec_sadb_init(void);
extern int ipsec_sadb_cleanup(__u8);

extern struct ipsec_sa *ipsec_sa_alloc(int *error);

extern struct ipsec_sa *ipsec_sa_getbyid(ip_said *, int type);
extern /* void */ int ipsec_sa_add(struct ipsec_sa *);

extern int ipsec_sa_init(struct ipsec_sa *ipsp);

/* debug declarations */

/* ipsec_proc.c */
extern int  ipsec_proc_init(void);
extern void ipsec_proc_cleanup(void);

/* ipsec_rcv.c */
extern int ipsec_rcv(struct sk_buff *skb);
extern int klips26_rcv_encap(struct sk_buff *skb, __u16 encap_type);

/* ipsec_xmit.c */
struct ipsec_xmit_state;
extern enum ipsec_xmit_value ipsec_xmit_sanity_check_ipsec_dev(
	struct ipsec_xmit_state *ixs);
extern enum ipsec_xmit_value ipsec_xmit_sanity_check_mast_dev(
	struct ipsec_xmit_state *ixs);
extern enum ipsec_xmit_value ipsec_xmit_sanity_check_skb(
	struct ipsec_xmit_state *ixs);
extern void ipsec_print_ip(void *ip);

/* ipsec_radij.c */
extern int ipsec_makeroute(struct sockaddr_encap *ea,
			   struct sockaddr_encap *em,
			   ip_said said,
			   uint32_t pid,
			   struct sk_buff *skb,
			   struct ident *ident_s,
			   struct ident *ident_d);

extern int ipsec_breakroute(struct sockaddr_encap *ea,
			    struct sockaddr_encap *em,
			    struct sk_buff **first,
			    struct sk_buff **last);

int ipsec_radijinit(void);
int ipsec_cleareroutes(void);
int ipsec_radijcleanup(void);

/* ipsec_life.c */
extern enum ipsec_life_alive ipsec_lifetime_check(
	struct ipsec_lifetime64 *il64,
	const char *lifename,
	const char *saname,
	enum ipsec_life_type ilt,
	enum ipsec_direction idir,
	struct ipsec_sa *ips);

extern int ipsec_lifetime_format(struct seq_file *seq,
				 char *lifename,
				 enum ipsec_life_type timebaselife,
				 struct ipsec_lifetime64 *lifetime);

extern void ipsec_lifetime_update_hard(struct ipsec_lifetime64 *lifetime,
				       __u64 newvalue);

extern void ipsec_lifetime_update_soft(struct ipsec_lifetime64 *lifetime,
				       __u64 newvalue);

/* ipsec_snprintf.c */
extern int ipsec_snprintf(char * buf, ssize_t size, const char *fmt, ...);
extern void ipsec_dmp_block(char *s, caddr_t bb, int len);

/* ipsec_alg.c */
extern int ipsec_alg_init(void);

extern int debug_xform;
extern int debug_eroute;
extern int debug_spi;
extern int debug_netlink;

#define _IPSEC_PROTO_H
#endif /* _IPSEC_PROTO_H_ */
