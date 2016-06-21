/*
 * @(#) RFC2367 PF_KEYv2 Key management API message parser
 * Copyright (C) 1999, 2000, 2001  Richard Guy Briggs <rgb@freeswan.org>
 * Copyright (C) 2012  Paul Wouters  <paul@libreswan.org>
 * Copyright (C) 2012  David McCullough <david_mccullough@mcafee.com>
 *
 * OCF support written by David McCullough <dmccullough@cyberguard.com>
 * Copyright (C) 2004-2005 Intel Corporation.  All Rights Reserved.
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

/*
 *		Template from klips/net/ipsec/ipsec/ipsec_netlink.c.
 */

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38) && \
	!defined(AUTOCONF_INCLUDED)
#include <linux/config.h>
#endif
#include <linux/kernel.h> /* printk() */

#include "libreswan/ipsec_param.h"

#include <linux/slab.h>         /* kmalloc() */
#include <linux/errno.h>        /* error codes */
#include <linux/types.h>        /* size_t */
#include <linux/interrupt.h>    /* mark_bh */

#include <linux/netdevice.h>    /* struct device, and other headers */
#include <linux/etherdevice.h>  /* eth_type_trans */
#include <linux/ip.h>           /* struct iphdr */
#include <linux/skbuff.h>

#include "libreswan/ipsec_param2.h"

#include <libreswan.h>

#include <klips-crypto/des.h>

#include <linux/spinlock.h>     /* *lock* */
# include <net/route.h>         /* inet_addr_type */
# include <linux/in6.h>
# include <net/ipv6.h>
# define IS_MYADDR RTN_LOCAL

#include <net/ip.h>
#include <linux/netlink.h>

#include <linux/random.h>       /* get_random_bytes() */

#include "libreswan/radij.h"
#include "libreswan/ipsec_encap.h"
#include "libreswan/ipsec_sa.h"

#include "libreswan/ipsec_radij.h"
#include "libreswan/ipsec_xform.h"
#include "libreswan/ipsec_ah.h"
#include "libreswan/ipsec_esp.h"
#include "libreswan/ipsec_tunnel.h"
#include "libreswan/ipsec_mast.h"
#include "libreswan/ipsec_rcv.h"
#include "libreswan/ipcomp.h"

#include <libreswan/pfkeyv2.h>
#include <libreswan/pfkey.h>

#include "libreswan/ipsec_proto.h"
#include "libreswan/ipsec_alg.h"
#include "libreswan/ipsec_kversion.h"

#define SENDERR(_x) { error = -(_x); goto errlab; }

struct sklist_t {
	struct socket *sk;
	struct sklist_t *next;
} pfkey_sklist_head, *pfkey_sklist, *pfkey_sklist_prev;

static __u32 pfkey_msg_seq = 0;

#if 0
#define DUMP_SAID dump_said(&extr->ips->ips_said, __LINE__)
#define DUMP_SAID2 dump_said(&extr.ips->ips_said, __LINE__)
static void dump_said(ip_said *s, int line)
{
	char msa[SATOT_BUF];
	size_t msa_len;

	msa_len = KLIPS_SATOT(1, s, 0, msa, sizeof(msa));

	printk("line: %d msa: %s\n", line, msa);
}
#endif

int pfkey_alloc_eroute(struct eroute **eroute)
{
	int error = 0;

	if (*eroute) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_alloc_eroute: "
			    "eroute struct already allocated\n");
		SENDERR(EEXIST);
	}

	if ((*eroute = kmalloc(sizeof(**eroute), GFP_ATOMIC) ) == NULL) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_alloc_eroute: "
			    "memory allocation error\n");
		SENDERR(ENOMEM);
	}

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_alloc_eroute: "
		    "allocating %lu bytes for an eroute at 0p%p\n",
		    (unsigned long) sizeof(**eroute), *eroute);

	memset((caddr_t)*eroute, 0, sizeof(**eroute));
	(*eroute)->er_eaddr.sen_len =
		(*eroute)->er_emask.sen_len = sizeof(struct sockaddr_encap);
	(*eroute)->er_eaddr.sen_family =
		(*eroute)->er_emask.sen_family = AF_ENCAP;
	(*eroute)->er_eaddr.sen_type = SENT_IP4;
	(*eroute)->er_emask.sen_type = 255;
	(*eroute)->er_pid = 0;
	(*eroute)->er_count = 0;
	(*eroute)->er_lasttime = jiffies / HZ;

errlab:
	return error;
}

DEBUG_NO_STATIC int pfkey_x_protocol_process(struct sadb_ext *pfkey_ext,
					     struct pfkey_extracted_data *extr)
{
	int error = 0;
	struct sadb_protocol * p = (struct sadb_protocol *)pfkey_ext;

	KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_x_protocol_process: %p\n",
		    extr);

	if (extr == 0) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_x_protocol_process:"
			    "extr is NULL, fatal\n");
		SENDERR(EINVAL);
	}
	if (extr->eroute == 0) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_x_protocol_process:"
			    "extr->eroute is NULL, fatal\n");
		SENDERR(EINVAL);
	}

	extr->eroute->er_eaddr.sen_proto = p->sadb_protocol_proto;
	extr->eroute->er_emask.sen_proto = p->sadb_protocol_proto ? ~0 : 0;
	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_x_protocol_process: protocol = %d.\n",
		    p->sadb_protocol_proto);
errlab:
	return error;
}

DEBUG_NO_STATIC int pfkey_ipsec_sa_init(struct ipsec_sa *ipsp)
{
	int rc;

	KLIPS_PRINT(debug_pfkey, "Calling SA_INIT\n");
	rc = ipsec_sa_init(ipsp);
	return rc;
}

static int pfkey_safe_build(int error, struct sadb_ext *extensions[K_SADB_MAX + 1])
{
	KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_safe_build: "
		    "error=%d\n",
		    error);
	if (!error) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_safe_build:"
			    "success.\n");
		return 1;
	} else {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_safe_build:"
			    "caught error %d\n",
			    error);
		pfkey_extensions_free(extensions);
		return 0;
	}
}

DEBUG_NO_STATIC int pfkey_getspi_parse(struct sock *sk,
				       struct sadb_ext **extensions,
				       struct pfkey_extracted_data *extr)
{
	int error = 0;
	ipsec_spi_t minspi = htonl(256), maxspi = htonl(-1L);
	int found_avail = 0;
	struct ipsec_sa *ipsq;
	char sa[SATOT_BUF];
	size_t sa_len;
	struct sadb_ext *extensions_reply[K_SADB_EXT_MAX + 1];
	struct sadb_msg *pfkey_reply = NULL;
	struct socket_list *pfkey_socketsp;
	uint8_t satype =
		((struct sadb_msg*)extensions[K_SADB_EXT_RESERVED])->
		sadb_msg_satype;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_getspi_parse: .\n");

	pfkey_extensions_init(extensions_reply);

	if (extr == NULL || extr->ips == NULL) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_getspi_parse: "
			    "error, extr or extr->ipsec_sa pointer NULL\n");
		SENDERR(EINVAL);
	}

	if (extensions[K_SADB_EXT_SPIRANGE]) {
		minspi = ((struct sadb_spirange *)
			extensions[K_SADB_EXT_SPIRANGE])->sadb_spirange_min;
		maxspi = ((struct sadb_spirange *)
			extensions[K_SADB_EXT_SPIRANGE])->sadb_spirange_max;
	}

	if (maxspi == minspi) {
		extr->ips->ips_said.spi = maxspi;
		spin_lock_bh(&tdb_lock);
		ipsq = ipsec_sa_getbyid(&(extr->ips->ips_said), IPSEC_REFSA);
		if (ipsq != NULL) {
			sa_len = KLIPS_SATOT(debug_pfkey, &extr->ips->ips_said,
					     0, sa, sizeof(sa));
			ipsec_sa_put(ipsq, IPSEC_REFSA);
			spin_unlock_bh(&tdb_lock);
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_getspi_parse: "
				    "EMT_GETSPI found an old ipsec_sa for SA: %s, delete it first.\n",
				    sa_len ? sa : " (error)");
			SENDERR(EEXIST);
		} else {
			found_avail = 1;
		}
		spin_unlock_bh(&tdb_lock);
	} else {
		int i = 0;
		__u32 rand_val;
		__u32 spi_diff;
		while ( ( i < (spi_diff = (ntohl(maxspi) - ntohl(minspi)))) &&
			!found_avail ) {
			prng_bytes(&ipsec_prng, (char *) &(rand_val),
				   ( (spi_diff < (2 ^ 8))  ? 1 :
				     ( (spi_diff < (2 ^ 16)) ? 2 :
				       ( (spi_diff < (2 ^ 24)) ? 3 :
					 4 ) ) ) );
			extr->ips->ips_said.spi = htonl(ntohl(minspi) +
							(rand_val %
							 (spi_diff + 1)));
			i++;
			spin_lock_bh(&tdb_lock);
			ipsq = ipsec_sa_getbyid(&(extr->ips->ips_said),
						IPSEC_REFSA);
			if (ipsq == NULL)
				found_avail = 1;
			else
				ipsec_sa_put(ipsq, IPSEC_REFSA);
			spin_unlock_bh(&tdb_lock);
		}
	}

	sa_len = KLIPS_SATOT(debug_pfkey, &extr->ips->ips_said, 0, sa,
			     sizeof(sa));

	if (!found_avail) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_getspi_parse: "
			    "found an old ipsec_sa for SA: %s, delete it first.\n",
			    sa_len ? sa : " (error)");
		SENDERR(EEXIST);
	}

#ifdef CONFIG_KLIPS_IPV6
	if (ip_address_family(&extr->ips->ips_said.dst) == AF_INET6 &&
	    ip6_chk_addr(&extr->ips->ips_said.dst.u.v6.sin6_addr) == IS_MYADDR)
		extr->ips->ips_flags |= EMT_INBOUND;
	else
#endif
	if (ip_chk_addr((unsigned long)extr->ips->ips_said.dst.u.v4.sin_addr.
			s_addr) == IS_MYADDR)
		extr->ips->ips_flags |= EMT_INBOUND;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_getspi_parse: "
		    "existing ipsec_sa not found (this is good) for SA: %s, %s-bound, allocating.\n",
		    sa_len ? sa : " (error)",
		    extr->ips->ips_flags & EMT_INBOUND ? "in" : "out");

	/* XXX extr->ips->ips_rcvif = &(enc_softc[em->em_if].enc_if);*/
	extr->ips->ips_rcvif = NULL;
	extr->ips->ips_life.ipl_addtime.ipl_count = jiffies / HZ;

	extr->ips->ips_state = K_SADB_SASTATE_LARVAL;

	if (!extr->ips->ips_life.ipl_allocations.ipl_count)
		extr->ips->ips_life.ipl_allocations.ipl_count += 1;

	if (!(pfkey_safe_build(error =
			pfkey_msg_hdr_build(&extensions_reply[0],
					    K_SADB_GETSPI,
					    satype,
					    0,
					    ((struct sadb_msg*)extensions[
					      K_SADB_EXT_RESERVED])->
					      sadb_msg_seq,
					    ((struct sadb_msg*)extensions[
					      K_SADB_EXT_RESERVED])->
					      sadb_msg_pid),
			       extensions_reply) &&
	      pfkey_safe_build(error =
			pfkey_sa_build(&extensions_reply[K_SADB_EXT_SA],
				       K_SADB_EXT_SA,
				       extr->ips->ips_said.spi,
				       0,
				       K_SADB_SASTATE_LARVAL,
				       0,
				       0,
				       0),
			       extensions_reply) &&
	      pfkey_safe_build(error =
			pfkey_address_build(&extensions_reply[K_SADB_EXT_ADDRESS_SRC],
					    K_SADB_EXT_ADDRESS_SRC,
					    0, /*extr->ips->ips_said.proto,*/
					    0,
					    extr->ips->ips_addr_s),
				  extensions_reply) &&
	      pfkey_safe_build(error =
			pfkey_address_build(&extensions_reply[
					      K_SADB_EXT_ADDRESS_DST],
					    K_SADB_EXT_ADDRESS_DST,
					    0, /*extr->ips->ips_said.proto,*/
					    0,
					    extr->ips->ips_addr_d),
			       extensions_reply) )) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_getspi_parse: "
			    "failed to build the getspi reply message extensions\n");
		goto errlab;
	}

	if ((error = pfkey_msg_build(&pfkey_reply, extensions_reply,
				     EXT_BITS_OUT))) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_getspi_parse: "
			    "failed to build the getspi reply message\n");
		SENDERR(-error);
	}
	for (pfkey_socketsp = pfkey_open_sockets;
	     pfkey_socketsp;
	     pfkey_socketsp = pfkey_socketsp->next) {
		if ((error = pfkey_upmsg(pfkey_socketsp->socketp,
					 pfkey_reply))) {
			KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_getspi_parse: "
				    "sending up getspi reply message for satype=%d(%s) to socket=0p%p failed with error=%d.\n",
				    satype,
				    satype2name(satype),
				    pfkey_socketsp->socketp,
				    error);
			SENDERR(-error);
		}
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_getspi_parse: "
			    "sending up getspi reply message for satype=%d(%s) to socket=0p%p succeeded.\n",
			    satype,
			    satype2name(satype),
			    pfkey_socketsp->socketp);
	}

	/* ipsec_sa_add does tdb_lock */
	if ((error = ipsec_sa_add(extr->ips))) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_getspi_parse: "
			    "failed to add the larval SA=%s with error=%d.\n",
			    sa_len ? sa : " (error)",
			    error);
		SENDERR(-error);
	}
	extr->ips = NULL;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_getspi_parse: "
		    "successful for SA: %s\n",
		    sa_len ? sa : " (error)");

errlab:
	if (pfkey_reply)
		pfkey_msg_free(&pfkey_reply);
	pfkey_extensions_free(extensions_reply);
	return error;
}

DEBUG_NO_STATIC int pfkey_update_parse(struct sock *sk,
				       struct sadb_ext **extensions,
				       struct pfkey_extracted_data *extr)
{
	int error = 0;
	struct ipsec_sa *ipsq;
	char sa[SATOT_BUF];
	size_t sa_len;
	struct sadb_ext *extensions_reply[K_SADB_EXT_MAX + 1];
	struct sadb_msg *pfkey_reply = NULL;
	struct socket_list *pfkey_socketsp;
	uint8_t satype =
		((struct sadb_msg*)extensions[K_SADB_EXT_RESERVED])->
		sadb_msg_satype;

	struct ipsec_sa *nat_t_ips_saved = NULL;
	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_update_parse: .\n");

	pfkey_extensions_init(extensions_reply);

	if (((struct sadb_sa*)extensions[K_SADB_EXT_SA])->sadb_sa_state !=
	    K_SADB_SASTATE_MATURE) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_update_parse: "
			    "error, sa_state=%d must be MATURE=%d\n",
			    ((struct sadb_sa*)extensions[K_SADB_EXT_SA])->sadb_sa_state,
			    K_SADB_SASTATE_MATURE);
		SENDERR(EINVAL);
	}

	if (extr == NULL || extr->ips == NULL) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_update_parse: "
			    "error, extr or extr->ips pointer NULL\n");
		SENDERR(EINVAL);
	}

	sa_len = KLIPS_SATOT(debug_pfkey, &extr->ips->ips_said, 0, sa,
			     sizeof(sa));

	spin_lock_bh(&tdb_lock);

	ipsq = ipsec_sa_getbyid(&(extr->ips->ips_said), IPSEC_REFSA);
	if (ipsq == NULL) {
		spin_unlock_bh(&tdb_lock);
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_update_parse: "
			    "reserved ipsec_sa for SA: %s not found.  Call K_SADB_GETSPI first or call K_SADB_ADD instead.\n",
			    sa_len ? sa : " (error)");
		SENDERR(ENOENT);
	}

#ifdef CONFIG_KLIPS_IPV6
	if (ip_address_family(&extr->ips->ips_said.dst) == AF_INET6 &&
	    ip6_chk_addr(&extr->ips->ips_said.dst.u.v6.sin6_addr) == IS_MYADDR)
		extr->ips->ips_flags |= EMT_INBOUND;
	else
#endif
	if (ip_chk_addr((unsigned long)extr->ips->ips_said.dst.u.v4.sin_addr.
			s_addr) == IS_MYADDR)
		extr->ips->ips_flags |= EMT_INBOUND;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_update_parse: "
		    "existing ipsec_sa found (this is good) for SA: %s, %s-bound, updating.\n",
		    sa_len ? sa : " (error)",
		    extr->ips->ips_flags & EMT_INBOUND ? "in" : "out");

	if (extr->ips->ips_natt_sport || extr->ips->ips_natt_dport) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_update_parse: only updating NAT-T ports "
			    "(%u:%u -> %u:%u)\n",
			    ipsq->ips_natt_sport, ipsq->ips_natt_dport,
			    extr->ips->ips_natt_sport,
			    extr->ips->ips_natt_dport);

		if (extr->ips->ips_natt_sport) {
			ipsq->ips_natt_sport = extr->ips->ips_natt_sport;
			if (ipsq->ips_addr_s->sa_family == AF_INET)
				((struct sockaddr_in *)(ipsq->ips_addr_s))->
				sin_port = htons(extr->ips->ips_natt_sport);
		}

		if (extr->ips->ips_natt_dport) {
			ipsq->ips_natt_dport = extr->ips->ips_natt_dport;
			if (ipsq->ips_addr_d->sa_family == AF_INET)
				((struct sockaddr_in *)(ipsq->ips_addr_d))->
				sin_port = htons(extr->ips->ips_natt_dport);
		}

		nat_t_ips_saved = extr->ips;
		extr->ips = ipsq;
	} else
	{
		/* XXX extr->ips->ips_rcvif = &(enc_softc[em->em_if].enc_if);*/
		extr->ips->ips_rcvif = NULL;
		if ((error = pfkey_ipsec_sa_init(extr->ips))) {
			ipsec_sa_put(ipsq, IPSEC_REFSA);
			spin_unlock_bh(&tdb_lock);
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_update_parse: "
				    "not successful for SA: %s, deleting.\n",
				    sa_len ? sa : " (error)");
			SENDERR(-error);
		}

		extr->ips->ips_life.ipl_addtime.ipl_count =
			ipsq->ips_life.ipl_addtime.ipl_count;

		/* this will call delchain-equivalent if refcount=>0 */
		ipsec_sa_put(ipsq, IPSEC_REFSA);
	}

	spin_unlock_bh(&tdb_lock);

	if (!(pfkey_safe_build(error =
		pfkey_msg_hdr_build(&extensions_reply[0],
				    K_SADB_UPDATE,
				    satype,
				    0,
				    ((struct sadb_msg*)extensions[
				      K_SADB_EXT_RESERVED])->sadb_msg_seq,
				    ((struct sadb_msg*)extensions[
				      K_SADB_EXT_RESERVED])->sadb_msg_pid),
			       extensions_reply) &&
		pfkey_safe_build(error =
			pfkey_sa_build(&extensions_reply[K_SADB_EXT_SA],
				       K_SADB_EXT_SA,
				       extr->ips->ips_said.spi,
				       extr->ips->ips_replaywin,
				       extr->ips->ips_state,
				       extr->ips->ips_authalg,
				       extr->ips->ips_encalg,
				       extr->ips->ips_flags),
			       extensions_reply) &&
		/* The 3 lifetime extentions should only be sent if non-zero. */
		(extensions[K_SADB_EXT_LIFETIME_HARD] == 0 ||
		    pfkey_safe_build(error =
			pfkey_lifetime_build(&extensions_reply[
					       K_SADB_EXT_LIFETIME_HARD],
					     K_SADB_EXT_LIFETIME_HARD,
					     extr->ips->ips_life.
					       ipl_allocations.ipl_hard,
					     extr->ips->ips_life.ipl_bytes.
					       ipl_hard,
					     extr->ips->ips_life.ipl_addtime.
					       ipl_hard,
					     extr->ips->ips_life.ipl_usetime.
					       ipl_hard,
					     extr->ips->ips_life.ipl_packets.
					       ipl_hard),
				   extensions_reply)) &&
		(extensions[K_SADB_EXT_LIFETIME_SOFT] == 0 ||
		    pfkey_safe_build(error =
			pfkey_lifetime_build(&extensions_reply[
					       K_SADB_EXT_LIFETIME_SOFT],
					     K_SADB_EXT_LIFETIME_SOFT,
					     extr->ips->ips_life.
					       ipl_allocations.ipl_count,
					     extr->ips->ips_life.ipl_bytes.
					       ipl_count,
					     extr->ips->ips_life.ipl_addtime.
					       ipl_count,
					     extr->ips->ips_life.ipl_usetime.
					       ipl_count,
					     extr->ips->ips_life.ipl_packets.
					       ipl_count),
				extensions_reply)) &&
		(!(extr->ips->ips_life.ipl_allocations.ipl_count ||
		   extr->ips->ips_life.ipl_bytes.ipl_count ||
		   extr->ips->ips_life.ipl_addtime.ipl_count ||
		   extr->ips->ips_life.ipl_usetime.ipl_count ||
		   extr->ips->ips_life.ipl_packets.ipl_count) ||

		  pfkey_safe_build(error =
			pfkey_lifetime_build(&extensions_reply[
						K_SADB_EXT_LIFETIME_CURRENT],
					     K_SADB_EXT_LIFETIME_CURRENT,
					     extr->ips->ips_life.
						ipl_allocations.ipl_count,
					     extr->ips->ips_life.ipl_bytes.
						ipl_count,
					     extr->ips->ips_life.ipl_addtime.
						ipl_count,
					     extr->ips->ips_life.ipl_usetime.
						ipl_count,
					     extr->ips->ips_life.ipl_packets.
						ipl_count),
				  extensions_reply)) &&
		pfkey_safe_build(error =
			pfkey_address_build(&extensions_reply[
						K_SADB_EXT_ADDRESS_SRC],
					    K_SADB_EXT_ADDRESS_SRC,
					    0,   /*extr->ips->ips_said.proto,*/
					    0,
					    extr->ips->ips_addr_s),
			       extensions_reply) &&
		pfkey_safe_build(error =
			pfkey_address_build(&extensions_reply[
						K_SADB_EXT_ADDRESS_DST],
					    K_SADB_EXT_ADDRESS_DST,
					    0,   /*extr->ips->ips_said.proto,*/
					    0,
					    extr->ips->ips_addr_d),
			       extensions_reply) &&
		(!extr->ips->ips_ident_s.data ||
		  pfkey_safe_build(error =
			pfkey_ident_build(&extensions_reply[
					      K_SADB_EXT_IDENTITY_SRC],
					  K_SADB_EXT_IDENTITY_SRC,
					  extr->ips->ips_ident_s.type,
					  extr->ips->ips_ident_s.id,
					  extr->ips->ips_ident_s.len,
					  extr->ips->ips_ident_s.data),
				extensions_reply)) &&
		(!extr->ips->ips_ident_d.data ||
		 pfkey_safe_build(error =
			pfkey_ident_build(&extensions_reply[
					      K_SADB_EXT_IDENTITY_DST],
					  K_SADB_EXT_IDENTITY_DST,
					  extr->ips->ips_ident_d.type,
					  extr->ips->ips_ident_d.id,
					  extr->ips->ips_ident_d.len,
					  extr->ips->ips_ident_d.data),
				extensions_reply))
#if 0
		/* FIXME: This won't work yet because I have not finished it */

		&&
		(!extr->ips->ips_sens ||
		 pfkey_safe_build(error =
			pfkey_sens_build(&extensions_reply[
					     K_SADB_EXT_SENSITIVITY],
					 extr->ips->ips_sens_dpd,
					 extr->ips->ips_sens_sens_level,
					 extr->ips->ips_sens_sens_len,
					 extr->ips->ips_sens_sens_bitmap,
					 extr->ips->ips_sens_integ_level,
					 extr->ips->ips_sens_integ_len,
					 extr->ips->ips_sens_integ_bitmap),
				   extensions_reply))
#endif
	      )) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_update_parse: "
			    "failed to build the update reply message extensions\n");
		SENDERR(-error);
	}

	if ((error = pfkey_msg_build(&pfkey_reply, extensions_reply,
				     EXT_BITS_OUT))) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_update_parse: "
			    "failed to build the update reply message\n");
		SENDERR(-error);
	}
	for (pfkey_socketsp = pfkey_open_sockets;
	     pfkey_socketsp;
	     pfkey_socketsp = pfkey_socketsp->next) {
		if ((error = pfkey_upmsg(pfkey_socketsp->socketp,
					 pfkey_reply))) {
			KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_update_parse: "
				    "sending up update reply message for satype=%d(%s) to socket=0p%p failed with error=%d.\n",
				    satype,
				    satype2name(satype),
				    pfkey_socketsp->socketp,
				    error);
			SENDERR(-error);
		}
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_update_parse: "
			    "sending up update reply message for satype=%d(%s) to socket=0p%p succeeded.\n",
			    satype,
			    satype2name(satype),
			    pfkey_socketsp->socketp);
	}

	if (nat_t_ips_saved) {
		/**
		 * As we _really_ update existing SA, we keep tdbq and need to delete
		 * parsed ips (nat_t_ips_saved, was extr->ips).
		 *
		 * goto errlab with extr->ips = nat_t_ips_saved will free it.
		 */

		extr->ips = nat_t_ips_saved;

		error = 0;
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_update_parse (NAT-T ports): "
			    "successful for SA: %s\n",
			    sa_len ? sa : " (error)");

		goto errlab;
	}

	/* ipsec_sa_add does tdb_lock */
	if ((error = ipsec_sa_add(extr->ips))) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_update_parse: "
			    "failed to update the mature SA=%s with error=%d.\n",
			    sa_len ? sa : " (error)",
			    error);
		SENDERR(-error);
	}
	extr->ips = NULL;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_update_parse: "
		    "successful for SA: %s\n",
		    sa_len ? sa : " (error)");

errlab:
	if (pfkey_reply)
		pfkey_msg_free(&pfkey_reply);
	pfkey_extensions_free(extensions_reply);
	return error;
}

DEBUG_NO_STATIC int pfkey_add_parse(struct sock *sk,
				    struct sadb_ext **extensions,
				    struct pfkey_extracted_data *extr)
{
	int error = 0;
	struct ipsec_sa *ipsq;
	char sa[SATOT_BUF];
	size_t sa_len;
	struct sadb_ext *extensions_reply[K_SADB_EXT_MAX + 1];
	struct sadb_msg *pfkey_reply = NULL;
	struct socket_list *pfkey_socketsp;
	uint8_t satype =
		((struct sadb_msg*)extensions[K_SADB_EXT_RESERVED])->
		sadb_msg_satype;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_add_parse: .\n");

	pfkey_extensions_init(extensions_reply);

	if (((struct sadb_sa*)extensions[K_SADB_EXT_SA])->sadb_sa_state !=
	    K_SADB_SASTATE_MATURE) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_add_parse: "
			    "error, sa_state=%d must be MATURE=%d\n",
			    ((struct sadb_sa*)extensions[K_SADB_EXT_SA])->sadb_sa_state,
			    K_SADB_SASTATE_MATURE);
		SENDERR(EINVAL);
	}

	if (!extr || !extr->ips) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_add_parse: "
			    "extr or extr->ips pointer NULL\n");
		SENDERR(EINVAL);
	}

	sa_len = KLIPS_SATOT(debug_pfkey, &extr->ips->ips_said, 0, sa,
			     sizeof(sa));

	spin_lock_bh(&tdb_lock);
	ipsq = ipsec_sa_getbyid(&(extr->ips->ips_said), IPSEC_REFSA);
	if (ipsq != NULL) {
		ipsec_sa_put(ipsq, IPSEC_REFSA);
		spin_unlock_bh(&tdb_lock);
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_add_parse: "
			    "found an old ipsec_sa for SA%s, delete it first.\n",
			    sa_len ? sa : " (error)");
		SENDERR(EEXIST);
	}
	spin_unlock_bh(&tdb_lock);

#ifdef CONFIG_KLIPS_IPV6
	if (ip_address_family(&extr->ips->ips_said.dst) == AF_INET6 &&
	    ip6_chk_addr(&extr->ips->ips_said.dst.u.v6.sin6_addr) == IS_MYADDR)
		extr->ips->ips_flags |= EMT_INBOUND;
	else
#endif
	if (ip_chk_addr((unsigned long)extr->ips->ips_said.dst.u.v4.sin_addr.
			s_addr) == IS_MYADDR)
		extr->ips->ips_flags |= EMT_INBOUND;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_add_parse: "
		    "existing ipsec_sa not found (this is good) for SA%s, %s-bound, allocating.\n",
		    sa_len ? sa : " (error)",
		    extr->ips->ips_flags & EMT_INBOUND ? "in" : "out");

	/* XXX extr->ips->ips_rcvif = &(enc_softc[em->em_if].enc_if);*/
	extr->ips->ips_rcvif = NULL;

	if ((error = ipsec_sa_init(extr->ips))) {
		KLIPS_ERROR(debug_pfkey,
			    "pfkey_add_parse: "
			    "not successful for SA: %s, deleting.\n",
			    sa_len ? sa : " (error)");
		SENDERR(-error);
	}

	if (extr->sarefme != IPSEC_SAREF_NULL &&
	    extr->ips->ips_ref == IPSEC_SAREF_NULL)
		extr->ips->ips_ref = extr->sarefme;

	if (extr->sarefhim != IPSEC_SAREF_NULL &&
	    extr->ips->ips_refhim == IPSEC_SAREF_NULL)
		extr->ips->ips_refhim = extr->sarefhim;

	/* attach it to the SAref table */
	spin_lock_bh(&tdb_lock);
	if ((error = ipsec_sa_intern(extr->ips)) != 0) {
		spin_unlock_bh(&tdb_lock);
		KLIPS_ERROR(debug_pfkey,
			    "pfkey_add_parse: "
			    "failed to intern SA as SAref#%lu\n",
			    (unsigned long)extr->ips->ips_ref);
		SENDERR(-error);
	}
	spin_unlock_bh(&tdb_lock);

	extr->ips->ips_life.ipl_addtime.ipl_count = jiffies / HZ;
	if (!extr->ips->ips_life.ipl_allocations.ipl_count)
		extr->ips->ips_life.ipl_allocations.ipl_count += 1;

	if (!(pfkey_safe_build(error = pfkey_msg_hdr_build(&extensions_reply[0],
							   K_SADB_ADD,
							   satype,
							   0,
							   ((struct sadb_msg*)
							    extensions[
								    K_SADB_EXT_RESERVED
							    ])->sadb_msg_seq,
							   ((struct sadb_msg*)
							    extensions[
								    K_SADB_EXT_RESERVED
							    ])->sadb_msg_pid),
			       extensions_reply) &&
	      pfkey_safe_build(error = pfkey_sa_build(&extensions_reply[
							      K_SADB_EXT_SA],
						      K_SADB_EXT_SA,
						      extr->ips->ips_said.spi,
						      extr->ips->ips_replaywin,
						      extr->ips->ips_state,
						      extr->ips->ips_authalg,
						      extr->ips->ips_encalg,
						      extr->ips->ips_flags),
			       extensions_reply) &&
	      pfkey_safe_build(error = pfkey_saref_build(&extensions_reply[
								 K_SADB_X_EXT_SAREF
							 ],
							 extr->ips->ips_ref,
							 extr->ips->ips_refhim),
			       extensions_reply) &&
	      /* The 3 lifetime extentions should only be sent if non-zero. */
	      (extensions[K_SADB_EXT_LIFETIME_HARD] == 0 ||
		  pfkey_safe_build(error = pfkey_lifetime_build(&
								extensions_reply
								[
									K_SADB_EXT_LIFETIME_HARD
								],
								K_SADB_EXT_LIFETIME_HARD,
								extr->ips->
								ips_life.
								ipl_allocations
								.ipl_hard,
								extr->ips->
								ips_life.
								ipl_bytes.
								ipl_hard,
								extr->ips->
								ips_life.
								ipl_addtime.
								ipl_hard,
								extr->ips->
								ips_life.
								ipl_usetime.
								ipl_hard,
								extr->ips->
								ips_life.
								ipl_packets.
								ipl_hard),
				   extensions_reply)) &&
	      (extensions[K_SADB_EXT_LIFETIME_SOFT] == 0 ||
	       pfkey_safe_build(error = pfkey_lifetime_build(&extensions_reply[
								     K_SADB_EXT_LIFETIME_SOFT
							     ],
							     K_SADB_EXT_LIFETIME_SOFT,
							     extr->ips->
							     ips_life.
							     ipl_allocations.
							     ipl_soft,
							     extr->ips->
							     ips_life.ipl_bytes
							     .ipl_soft,
							     extr->ips->
							     ips_life.
							     ipl_addtime.
							     ipl_soft,
							     extr->ips->
							     ips_life.
							     ipl_usetime.
							     ipl_soft,
							     extr->ips->
							     ips_life.
							     ipl_packets.
							     ipl_soft),
				extensions_reply)) &&
	      pfkey_safe_build(error = pfkey_address_build(&extensions_reply[
								   K_SADB_EXT_ADDRESS_SRC
							   ],
							   K_SADB_EXT_ADDRESS_SRC,
							   0,   /*extr->ips->ips_said.proto,*/
							   0,
							   extr->ips->
							   ips_addr_s),
			       extensions_reply) &&
	      pfkey_safe_build(error = pfkey_address_build(&extensions_reply[
								   K_SADB_EXT_ADDRESS_DST
							   ],
							   K_SADB_EXT_ADDRESS_DST,
							   0,   /*extr->ips->ips_said.proto,*/
							   0,
							   extr->ips->
							   ips_addr_d),
			       extensions_reply) &&
	      (extr->ips->ips_ident_s.data == 0 ||
	       pfkey_safe_build(error = pfkey_ident_build(&extensions_reply[
								  K_SADB_EXT_IDENTITY_SRC
							  ],
							  K_SADB_EXT_IDENTITY_SRC,
							  extr->ips->
							  ips_ident_s.type,
							  extr->ips->
							  ips_ident_s.id,
							  extr->ips->
							  ips_ident_s.len,
							  extr->ips->
							  ips_ident_s.data),
				extensions_reply)) &&
	      (extr->ips->ips_ident_d.data == 0 ||
	       pfkey_safe_build(error = pfkey_ident_build(&extensions_reply[
								  K_SADB_EXT_IDENTITY_DST
							  ],
							  K_SADB_EXT_IDENTITY_DST,
							  extr->ips->
							  ips_ident_d.type,
							  extr->ips->
							  ips_ident_d.id,
							  extr->ips->
							  ips_ident_d.len,
							  extr->ips->
							  ips_ident_d.data),
				extensions_reply))
#if 0
		/* FIXME: This won't work yet because I have not finished it */
	      && (extr->ips->ips_sens_== 0 ||
		  pfkey_safe_build(error = pfkey_sens_build(&extensions_reply[
								    K_SADB_EXT_SENSITIVITY
							    ],
							    extr->ips->
							    ips_sens_dpd,
							    extr->ips->
							    ips_sens_sens_level,
							    extr->ips->
							    ips_sens_sens_len,
							    extr->ips->
							    ips_sens_sens_bitmap,
							    extr->ips->
							    ips_sens_integ_level,
							    extr->ips->
							    ips_sens_integ_len,
							    extr->ips->
							    ips_sens_integ_bitmap),
				   extensions_reply))
#endif
	      )) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_add_parse: "
			    "failed to build the add reply message extensions\n");
		SENDERR(-error);
	}

	if ((error = pfkey_msg_build(&pfkey_reply, extensions_reply,
				     EXT_BITS_OUT))) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_add_parse: "
			    "failed to build the add reply message\n");
		SENDERR(-error);
	}
	for (pfkey_socketsp = pfkey_open_sockets;
	     pfkey_socketsp;
	     pfkey_socketsp = pfkey_socketsp->next) {
		if ((error = pfkey_upmsg(pfkey_socketsp->socketp,
					 pfkey_reply))) {
			KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_add_parse: "
				    "sending up add reply message for satype=%d(%s) to socket=0p%p failed with error=%d.\n",
				    satype,
				    satype2name(satype),
				    pfkey_socketsp->socketp,
				    error);
			SENDERR(-error);
		}
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_add_parse: "
			    "sending up add reply message for satype=%d(%s) to socket=0p%p succeeded.\n",
			    satype,
			    satype2name(satype),
			    pfkey_socketsp->socketp);
	}

	if (extr->outif != 0 && extr->outif != -1) {
		extr->ips->ips_out = ipsec_mast_get_device(extr->outif);
		extr->ips->ips_transport_direct = ipsec_mast_is_transport(
			extr->outif);
	}

	/* ipsec_sa_add does tdb_lock */
	if ((error = ipsec_sa_add(extr->ips))) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_add_parse: "
			    "failed to add the mature SA=%s with error=%d.\n",
			    sa_len ? sa : " (error)",
			    error);
		SENDERR(-error);
	}
	extr->ips = NULL;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_add_parse: "
		    "successful for SA: %s\n",
		    sa_len ? sa : " (error)");

errlab:
	if (pfkey_reply)
		pfkey_msg_free(&pfkey_reply);
	pfkey_extensions_free(extensions_reply);
	return error;
}

DEBUG_NO_STATIC int pfkey_delete_parse(struct sock *sk,
				       struct sadb_ext **extensions,
				       struct pfkey_extracted_data *extr)
{
	struct ipsec_sa *ipsp, *ipsq, *ipsr;
	char sa[SATOT_BUF];
	size_t sa_len;
	int error = 0;
	struct sadb_ext *extensions_reply[K_SADB_EXT_MAX + 1];
	struct sadb_msg *pfkey_reply = NULL;
	struct socket_list *pfkey_socketsp;
	uint8_t satype =
		((struct sadb_msg*)extensions[K_SADB_EXT_RESERVED])->
		sadb_msg_satype;
	IPsecSAref_t ref;
	struct sadb_builds sab;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_delete_parse: .\n");

	pfkey_extensions_init(extensions_reply);

	if (!extr || !extr->ips) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_delete_parse: "
			    "extr or extr->ips pointer NULL, fatal\n");
		SENDERR(EINVAL);
	}

	sa_len = KLIPS_SATOT(debug_pfkey, &extr->ips->ips_said, 0, sa,
			     sizeof(sa));

	spin_lock_bh(&tdb_lock);

	ipsp = ipsec_sa_getbyid(&(extr->ips->ips_said), IPSEC_REFSA);
	if (ipsp == NULL) {
		spin_unlock_bh(&tdb_lock);
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_delete_parse: "
			    "ipsec_sa not found for SA:%s, could not delete.\n",
			    sa_len ? sa : " (error)");
		SENDERR(ESRCH);
	}

	ref = ipsp->ips_ref; /* save a copy of ref */

	/*
	 * remove it from SAref tables
	 *
	 * if we are part of a group we must untern/rm the whole group
	 * as this is what user space expects, so find the start of the chain.
	 */

	ipsq = ipsp;
	while (ipsq->ips_prev)
		ipsq = ipsq->ips_prev;
	while (ipsq) {
		ipsr = ipsq->ips_next;
		ipsec_sa_untern(ipsq);
		ipsec_sa_rm(ipsq);
		ipsq = ipsr;
	}

	/* this will call delchain-equivalent if refcount -> 0
	 * noting that get() above, added to ref count */
	ipsec_sa_put(ipsp, IPSEC_REFSA);

	/* put the original ALLOC to free the SA */
	ipsq = ipsp;
	while (ipsq->ips_prev)
		ipsq = ipsq->ips_prev;
	/* this should cause ipsec_sa_wipe to get called on the SA/group */
	ipsec_sa_put(ipsq, IPSEC_REFALLOC);

	spin_unlock_bh(&tdb_lock);

	memset(&sab, 0, sizeof(sab));
	sab.sa_base.sadb_sa_exttype = K_SADB_EXT_SA;
	sab.sa_base.sadb_sa_spi     = extr->ips->ips_said.spi;
	sab.sa_base.sadb_sa_replay  = 0;
	sab.sa_base.sadb_sa_state   = 0;
	sab.sa_base.sadb_sa_auth    = 0;
	sab.sa_base.sadb_sa_encrypt = 0;
	sab.sa_base.sadb_sa_flags   = 0;
	sab.sa_base.sadb_x_sa_ref   = ref;

	if (!(pfkey_safe_build(error = pfkey_msg_hdr_build(&extensions_reply[0],
							   K_SADB_DELETE,
							   satype,
							   0,
							   ((struct sadb_msg*)
							    extensions[
								    K_SADB_EXT_RESERVED
							    ])->sadb_msg_seq,
							   ((struct sadb_msg*)
							    extensions[
								    K_SADB_EXT_RESERVED
							    ])->sadb_msg_pid),
			       extensions_reply) &&
	      pfkey_safe_build(error = pfkey_sa_builds(&extensions_reply[
							       K_SADB_EXT_SA],
						       sab),
			       extensions_reply) &&
	      pfkey_safe_build(error = pfkey_address_build(&extensions_reply[
								   K_SADB_EXT_ADDRESS_SRC
							   ],
							   K_SADB_EXT_ADDRESS_SRC,
							   0,   /*extr->ips->ips_said.proto,*/
							   0,
							   extr->ips->
							   ips_addr_s),
			       extensions_reply) &&
	      pfkey_safe_build(error = pfkey_address_build(&extensions_reply[
								   K_SADB_EXT_ADDRESS_DST
							   ],
							   K_SADB_EXT_ADDRESS_DST,
							   0,   /*extr->ips->ips_said.proto,*/
							   0,
							   extr->ips->
							   ips_addr_d),
			       extensions_reply)
	      )) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_delete_parse: "
			    "failed to build the delete reply message extensions\n");
		SENDERR(-error);
	}

	if ((error = pfkey_msg_build(&pfkey_reply, extensions_reply,
				     EXT_BITS_OUT))) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_delete_parse: "
			    "failed to build the delete reply message\n");
		SENDERR(-error);
	}
	for (pfkey_socketsp = pfkey_open_sockets;
	     pfkey_socketsp;
	     pfkey_socketsp = pfkey_socketsp->next) {
		if ((error = pfkey_upmsg(pfkey_socketsp->socketp,
					 pfkey_reply))) {
			KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_delete_parse: "
				    "sending up delete reply message for satype=%d(%s) to socket=0p%p failed with error=%d.\n",
				    satype,
				    satype2name(satype),
				    pfkey_socketsp->socketp,
				    error);
			SENDERR(-error);
		}
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_delete_parse: "
			    "sending up delete reply message for satype=%d(%s) to socket=0p%p succeeded.\n",
			    satype,
			    satype2name(satype),
			    pfkey_socketsp->socketp);
	}

errlab:
	if (pfkey_reply)
		pfkey_msg_free(&pfkey_reply);
	pfkey_extensions_free(extensions_reply);
	return error;
}

DEBUG_NO_STATIC int pfkey_get_parse(struct sock *sk,
				    struct sadb_ext **extensions,
				    struct pfkey_extracted_data *extr)
{
	int error = 0;
	struct ipsec_sa *ipsp;
	char sa[SATOT_BUF];
	size_t sa_len;
	struct sadb_ext *extensions_reply[K_SADB_EXT_MAX + 1];
	struct sadb_msg *pfkey_reply = NULL;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_get_parse: .\n");

	pfkey_extensions_init(extensions_reply);

	if (!extr || !extr->ips) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_get_parse: "
			    "extr or extr->ips pointer NULL, fatal\n");
		SENDERR(EINVAL);
	}

	sa_len = KLIPS_SATOT(debug_pfkey, &extr->ips->ips_said, 0, sa,
			     sizeof(sa));

	spin_lock_bh(&tdb_lock);

	ipsp = ipsec_sa_getbyid(&(extr->ips->ips_said), IPSEC_REFSA);
	if (ipsp == NULL) {
		spin_unlock_bh(&tdb_lock);
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_get_parse: "
			    "ipsec_sa not found for SA=%s, could not get.\n",
			    sa_len ? sa : " (error)");
		SENDERR(ESRCH);
	}

	if (!(pfkey_safe_build(error = pfkey_msg_hdr_build(&extensions_reply[0],
							   K_SADB_GET,
							   ((struct sadb_msg*)
							    extensions[
								    K_SADB_EXT_RESERVED
							    ])->sadb_msg_satype,
							   0,
							   ((struct sadb_msg*)
							    extensions[
								    K_SADB_EXT_RESERVED
							    ])->sadb_msg_seq,
							   ((struct sadb_msg*)
							    extensions[
								    K_SADB_EXT_RESERVED
							    ])->sadb_msg_pid),
			       extensions_reply) &&
	      pfkey_safe_build(error = pfkey_sa_build(&extensions_reply[
							      K_SADB_EXT_SA],
						      K_SADB_EXT_SA,
						      extr->ips->ips_said.spi,
						      extr->ips->ips_replaywin,
						      extr->ips->ips_state,
						      extr->ips->ips_authalg,
						      extr->ips->ips_encalg,
						      extr->ips->ips_flags),
			       extensions_reply) &&
	      /* The 3 lifetime extentions should only be sent if non-zero. */
	      (!(ipsp->ips_life.ipl_allocations.ipl_count ||
		 ipsp->ips_life.ipl_bytes.ipl_count ||
		 ipsp->ips_life.ipl_addtime.ipl_count ||
		 ipsp->ips_life.ipl_usetime.ipl_count ||
		 ipsp->ips_life.ipl_packets.ipl_count) ||
		  pfkey_safe_build(error = pfkey_lifetime_build(&
								extensions_reply
								[
									K_SADB_EXT_LIFETIME_CURRENT
								],
								K_SADB_EXT_LIFETIME_CURRENT,
								ipsp->ips_life.
								ipl_allocations
								.ipl_count,
								ipsp->ips_life.
								ipl_bytes.
								ipl_count,
								ipsp->ips_life.
								ipl_addtime.
								ipl_count,
								ipsp->ips_life.
								ipl_usetime.
								ipl_count,
								ipsp->ips_life.
								ipl_packets.
								ipl_count),
				   extensions_reply)) &&
	      (!(ipsp->ips_life.ipl_allocations.ipl_hard ||
	       ipsp->ips_life.ipl_bytes.ipl_hard ||
	       ipsp->ips_life.ipl_addtime.ipl_hard ||
	       ipsp->ips_life.ipl_usetime.ipl_hard ||
	       ipsp->ips_life.ipl_packets.ipl_hard) ||
	       pfkey_safe_build(error = pfkey_lifetime_build(&extensions_reply[
								     K_SADB_EXT_LIFETIME_HARD
							     ],
							     K_SADB_EXT_LIFETIME_HARD,
							     ipsp->ips_life.
							     ipl_allocations.
							     ipl_hard,
							     ipsp->ips_life.
							     ipl_bytes.ipl_hard,
							     ipsp->ips_life.
							     ipl_addtime.
							     ipl_hard,
							     ipsp->ips_life.
							     ipl_usetime.
							     ipl_hard,
							     ipsp->ips_life.
							     ipl_packets.
							     ipl_hard),
				extensions_reply)) &&
	      (!(ipsp->ips_life.ipl_allocations.ipl_soft ||
	       ipsp->ips_life.ipl_bytes.ipl_soft ||
	       ipsp->ips_life.ipl_addtime.ipl_soft ||
	       ipsp->ips_life.ipl_usetime.ipl_soft ||
	       ipsp->ips_life.ipl_packets.ipl_soft) ||
	       pfkey_safe_build(error = pfkey_lifetime_build(&extensions_reply[
								     K_SADB_EXT_LIFETIME_SOFT
							     ],
							     K_SADB_EXT_LIFETIME_SOFT,
							     ipsp->ips_life.
							     ipl_allocations.
							     ipl_soft,
							     ipsp->ips_life.
							     ipl_bytes.ipl_soft,
							     ipsp->ips_life.
							     ipl_addtime.
							     ipl_soft,
							     ipsp->ips_life.
							     ipl_usetime.
							     ipl_soft,
							     ipsp->ips_life.
							     ipl_packets.
							     ipl_soft),
				extensions_reply)) &&
	      pfkey_safe_build(error = pfkey_address_build(&extensions_reply[
								   K_SADB_EXT_ADDRESS_SRC
							   ],
							   K_SADB_EXT_ADDRESS_SRC,
							   0,   /*extr->ips->ips_said.proto,*/
							   0,
							   extr->ips->
							   ips_addr_s),
			       extensions_reply) &&
	      pfkey_safe_build(error = pfkey_address_build(&extensions_reply[
								   K_SADB_EXT_ADDRESS_DST
							   ],
							   K_SADB_EXT_ADDRESS_DST,
							   0,   /*extr->ips->ips_said.proto,*/
							   0,
							   extr->ips->
							   ips_addr_d),
			       extensions_reply) &&
	      (extr->ips->ips_addr_p == NULL ||
	       pfkey_safe_build(error = pfkey_address_build(&extensions_reply[
								    K_SADB_EXT_ADDRESS_PROXY
							    ],
							    K_SADB_EXT_ADDRESS_PROXY,
							    0,     /*extr->ips->ips_said.proto,*/
							    0,
							    extr->ips->
							    ips_addr_p),
				extensions_reply))
#if 0
		/*
		 * FIXME: This won't work yet because the keys are not
		 * stored directly in the ipsec_sa.  They are stored as
		 * contexts.
		 */
	      && (extr->ips->ips_key_a_size == 0 ||
		  pfkey_safe_build(error = pfkey_key_build(&extensions_reply[
								   K_SADB_EXT_KEY_AUTH
							   ],
							   K_SADB_EXT_KEY_AUTH,
							   extr->ips->
							   ips_key_a_size * 8,
							   extr->ips->ips_key_a),
				   extensions_reply) : 1)
		/*
		 * FIXME: This won't work yet because the keys are not
		 * stored directly in the ipsec_sa.  They are stored as
		 * key schedules.
		 */
	      && (extr->ips->ips_key_e_size ?
		  pfkey_safe_build(error = pfkey_key_build(&extensions_reply[
								   K_SADB_EXT_KEY_ENCRYPT
							   ],
							   K_SADB_EXT_KEY_ENCRYPT,
							   extr->ips->
							   ips_key_e_size * 8,
							   extr->ips->ips_key_e),
				   extensions_reply))
#endif
	      && (extr->ips->ips_ident_s.data == 0 ||
		  pfkey_safe_build(error = pfkey_ident_build(&extensions_reply[
								     K_SADB_EXT_IDENTITY_SRC
							     ],
							     K_SADB_EXT_IDENTITY_SRC,
							     extr->ips->
							     ips_ident_s.type,
							     extr->ips->
							     ips_ident_s.id,
							     extr->ips->
							     ips_ident_s.len,
							     extr->ips->
							     ips_ident_s.data),
				   extensions_reply)) &&
	      (extr->ips->ips_ident_d.data == 0 ||
	       pfkey_safe_build(error = pfkey_ident_build(&extensions_reply[
								  K_SADB_EXT_IDENTITY_DST
							  ],
							  K_SADB_EXT_IDENTITY_DST,
							  extr->ips->
							  ips_ident_d.type,
							  extr->ips->
							  ips_ident_d.id,
							  extr->ips->
							  ips_ident_d.len,
							  extr->ips->
							  ips_ident_d.data),
				extensions_reply))
#if 0
		/* FIXME: This won't work yet because I have not finished it */
	      && (extr->ips->ips_sens_== 0 ||
		  pfkey_safe_build(error = pfkey_sens_build(&extensions_reply[
								    K_SADB_EXT_SENSITIVITY
							    ],
							    extr->ips->
							    ips_sens_dpd,
							    extr->ips->
							    ips_sens_sens_level,
							    extr->ips->
							    ips_sens_sens_len,
							    extr->ips->
							    ips_sens_sens_bitmap,
							    extr->ips->
							    ips_sens_integ_level,
							    extr->ips->
							    ips_sens_integ_len,
							    extr->ips->
							    ips_sens_integ_bitmap),
				   extensions_reply))
#endif
	      )) {
		ipsec_sa_put(ipsp, IPSEC_REFSA);
		spin_unlock_bh(&tdb_lock);
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_get_parse: "
			    "failed to build the get reply message extensions\n");
		SENDERR(-error);
	}

	ipsec_sa_put(ipsp, IPSEC_REFSA);
	spin_unlock_bh(&tdb_lock);

	if ((error = pfkey_msg_build(&pfkey_reply, extensions_reply,
				     EXT_BITS_OUT))) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_get_parse: "
			    "failed to build the get reply message\n");
		SENDERR(-error);
	}

	if ((error = pfkey_upmsg(sk->sk_socket, pfkey_reply))) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_get_parse: "
			    "failed to send the get reply message\n");
		SENDERR(-error);
	}

	KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_get_parse: "
		    "succeeded in sending get reply message.\n");

errlab:
	if (pfkey_reply)
		pfkey_msg_free(&pfkey_reply);
	pfkey_extensions_free(extensions_reply);
	return error;
}

DEBUG_NO_STATIC int pfkey_acquire_parse(struct sock *sk,
					struct sadb_ext **extensions,
					struct pfkey_extracted_data *extr)
{
	int error = 0;
	struct socket_list *pfkey_socketsp;
	uint8_t satype =
		((struct sadb_msg*)extensions[K_SADB_EXT_RESERVED])->
		sadb_msg_satype;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_acquire_parse: .\n");

	/* XXX I don't know if we want an upper bound, since userspace may
	   want to register itself for an satype > K_SADB_SATYPE_MAX. */
	if ((satype == 0) || (satype > K_SADB_SATYPE_MAX)) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_acquire_parse: "
			    "SATYPE=%d invalid.\n",
			    satype);
		SENDERR(EINVAL);
	}

	if (!(pfkey_registered_sockets[satype])) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_acquire_parse: "
			    "no sockets registered for SAtype=%d(%s).\n",
			    satype,
			    satype2name(satype));
		SENDERR(EPROTONOSUPPORT);
	}

	for (pfkey_socketsp = pfkey_registered_sockets[satype];
	     pfkey_socketsp;
	     pfkey_socketsp = pfkey_socketsp->next) {
		if ((error = pfkey_upmsg(pfkey_socketsp->socketp,
					 ((struct sadb_msg*)extensions[
						  K_SADB_EXT_RESERVED])))) {
			KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_acquire_parse: "
				    "sending up acquire reply message for satype=%d(%s) to socket=0p%p failed with error=%d.\n",
				    satype,
				    satype2name(satype),
				    pfkey_socketsp->socketp,
				    error);
			SENDERR(-error);
		}
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_acquire_parse: "
			    "sending up acquire reply message for satype=%d(%s) to socket=0p%p succeeded.\n",
			    satype,
			    satype2name(satype),
			    pfkey_socketsp->socketp);
	}

errlab:
	return error;
}

DEBUG_NO_STATIC int pfkey_register_parse(struct sock *sk,
					 struct sadb_ext **extensions,
					 struct pfkey_extracted_data *extr)
{
	int error = 0;
	uint8_t satype =
		((struct sadb_msg*)extensions[K_SADB_EXT_RESERVED])->
		sadb_msg_satype;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_register_parse: .\n");

	/* XXX I don't know if we want an upper bound, since userspace may
	   want to register itself for an satype > K_SADB_SATYPE_MAX. */
	if ((satype == 0) || (satype > K_SADB_SATYPE_MAX)) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_register_parse: "
			    "SATYPE=%d invalid.\n",
			    satype);
		SENDERR(EINVAL);
	}

	if (!pfkey_list_insert_socket(sk->sk_socket,
				      &(pfkey_registered_sockets[satype]))) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_register_parse: "
			    "SATYPE=%02d(%s) successfully registered by KMd (pid=%d).\n",
			    satype,
			    satype2name(satype),
			    key_pid(sk));
	}

	/* send up register msg with supported SATYPE algos */

	error = pfkey_register_reply(satype,
				     (struct sadb_msg*)extensions[
					     K_SADB_EXT_RESERVED]);
errlab:
	return error;
}

int pfkey_register_reply(int satype, struct sadb_msg *sadb_msg)
{
	struct sadb_ext *extensions_reply[K_SADB_EXT_MAX + 1];
	struct sadb_msg *pfkey_reply = NULL;
	struct socket_list *pfkey_socketsp;
	struct supported_list *pfkey_supported_listp;
	unsigned int alg_num_a = 0, alg_num_e = 0;
	struct sadb_alg *alg_a = NULL, *alg_e = NULL, *alg_ap = NULL,
		*alg_ep = NULL;
	int error = 0;

	pfkey_extensions_init(extensions_reply);

	if ((satype == 0) || (satype > K_SADB_SATYPE_MAX)) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_register_reply: "
			    "SAtype=%d unspecified or unknown.\n",
			    satype);
		SENDERR(EINVAL);
	}
	if (!(pfkey_registered_sockets[satype])) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_register_reply: "
			    "no sockets registered for SAtype=%d(%s).\n",
			    satype,
			    satype2name(satype));
		SENDERR(EPROTONOSUPPORT);
	}
	/* send up register msg with supported SATYPE algos */
	pfkey_supported_listp = pfkey_supported_list[satype];
	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_register_reply: "
		    "pfkey_supported_list[%d]=0p%p\n",
		    satype,
		    pfkey_supported_list[satype]);
	while (pfkey_supported_listp) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_register_reply: "
			    "checking supported=0p%p\n",
			    pfkey_supported_listp);
		if (pfkey_supported_listp->supportedp->ias_exttype ==
		    K_SADB_EXT_SUPPORTED_AUTH) {
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_register_reply: "
				    "adding auth alg.\n");
			alg_num_a++;
		}
		if (pfkey_supported_listp->supportedp->ias_exttype ==
		    K_SADB_EXT_SUPPORTED_ENCRYPT) {
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_register_reply: "
				    "adding encrypt alg.\n");
			alg_num_e++;
		}
		pfkey_supported_listp = pfkey_supported_listp->next;
	}

	if (alg_num_a) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_register_reply: "
			    "allocating %lu bytes for auth algs.\n",
			    (unsigned long) (alg_num_a *
					     sizeof(struct sadb_alg)));
		if ((alg_a = kmalloc(alg_num_a * sizeof(struct sadb_alg),
				     GFP_ATOMIC) ) == NULL) {
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_register_reply: "
				    "auth alg memory allocation error\n");
			SENDERR(ENOMEM);
		}
		alg_ap = alg_a;
	}

	if (alg_num_e) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_register_reply: "
			    "allocating %lu bytes for enc algs.\n",
			    (unsigned long) (alg_num_e *
					     sizeof(struct sadb_alg)));
		if ((alg_e = kmalloc(alg_num_e * sizeof(struct sadb_alg),
				     GFP_ATOMIC) ) == NULL) {
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_register_reply: "
				    "enc alg memory allocation error\n");
			SENDERR(ENOMEM);
		}
		alg_ep = alg_e;
	}

	pfkey_supported_listp = pfkey_supported_list[satype];
	while (pfkey_supported_listp) {
		if (alg_num_a) {
			if (pfkey_supported_listp->supportedp->ias_exttype ==
			    K_SADB_EXT_SUPPORTED_AUTH) {
				alg_ap->sadb_alg_id =
					pfkey_supported_listp->supportedp->
					ias_id;
				alg_ap->sadb_alg_ivlen =
					pfkey_supported_listp->supportedp->
					ias_ivlen;
				alg_ap->sadb_alg_minbits =
					pfkey_supported_listp->supportedp->
					ias_keyminbits;
				alg_ap->sadb_alg_maxbits =
					pfkey_supported_listp->supportedp->
					ias_keymaxbits;
				alg_ap->sadb_alg_reserved = 0;
				KLIPS_PRINT(
					debug_pfkey && sysctl_ipsec_debug_verbose,
					"klips_debug:pfkey_register_reply: "
					"adding auth=0p%p\n",
					alg_ap);
				alg_ap++;
			}
		}
		if (alg_num_e) {
			if (pfkey_supported_listp->supportedp->ias_exttype ==
			    K_SADB_EXT_SUPPORTED_ENCRYPT) {
				alg_ep->sadb_alg_id =
					pfkey_supported_listp->supportedp->
					ias_id;
				alg_ep->sadb_alg_ivlen =
					pfkey_supported_listp->supportedp->
					ias_ivlen;
				alg_ep->sadb_alg_minbits =
					pfkey_supported_listp->supportedp->
					ias_keyminbits;
				alg_ep->sadb_alg_maxbits =
					pfkey_supported_listp->supportedp->
					ias_keymaxbits;
				alg_ep->sadb_alg_reserved = 0;
				KLIPS_PRINT(
					debug_pfkey && sysctl_ipsec_debug_verbose,
					"klips_debug:pfkey_register_reply: "
					"adding encrypt=0p%p\n",
					alg_ep);
				alg_ep++;
			}
		}
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_register_reply: "
			    "found satype=%d(%s) exttype=%d id=%d ivlen=%d minbits=%d maxbits=%d.\n",
			    satype,
			    satype2name(satype),
			    pfkey_supported_listp->supportedp->ias_exttype,
			    pfkey_supported_listp->supportedp->ias_id,
			    pfkey_supported_listp->supportedp->ias_ivlen,
			    pfkey_supported_listp->supportedp->ias_keyminbits,
			    pfkey_supported_listp->supportedp->ias_keymaxbits);
		pfkey_supported_listp = pfkey_supported_listp->next;
	}

	if (!(pfkey_safe_build(error = pfkey_msg_hdr_build(&extensions_reply[0],
							   K_SADB_REGISTER,
							   satype,
							   0,
							   sadb_msg ? sadb_msg
							   ->sadb_msg_seq : ++
							   pfkey_msg_seq,
							   sadb_msg ? sadb_msg
							   ->sadb_msg_pid :
#ifdef HAVE_USER_NS
							   pfkey_kuid_to_uid(current_uid())),
#else
							   current_uid()),
#endif
			       extensions_reply) &&
	      (alg_num_a == 0 ||
	       pfkey_safe_build(error =
			pfkey_supported_build(&extensions_reply[
						  K_SADB_EXT_SUPPORTED_AUTH],
					      K_SADB_EXT_SUPPORTED_AUTH,
					      alg_num_a,
					      alg_a),
				extensions_reply)) &&
	      (alg_num_e == 0 ||
	       pfkey_safe_build(error =
			pfkey_supported_build(&extensions_reply[
						  K_SADB_EXT_SUPPORTED_ENCRYPT],
					      K_SADB_EXT_SUPPORTED_ENCRYPT,
					      alg_num_e,
					      alg_e),
				 extensions_reply)))) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_register_reply: "
			    "failed to build the register message extensions_reply\n");
		SENDERR(-error);
	}

	if ((error = pfkey_msg_build(&pfkey_reply, extensions_reply,
				     EXT_BITS_OUT))) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_register_reply: "
			    "failed to build the register message\n");
		SENDERR(-error);
	}
	/* this should go to all registered sockets for that satype only */
	for (pfkey_socketsp = pfkey_registered_sockets[satype];
	     pfkey_socketsp;
	     pfkey_socketsp = pfkey_socketsp->next) {
		if ((error = pfkey_upmsg(pfkey_socketsp->socketp,
					 pfkey_reply))) {
			KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_register_reply: "
				    "sending up acquire message for satype=%d(%s) to socket=0p%p failed with error=%d.\n",
				    satype,
				    satype2name(satype),
				    pfkey_socketsp->socketp,
				    error);
			SENDERR(-error);
		}
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_register_reply: "
			    "sending up register message for satype=%d(%s) to socket=0p%p succeeded.\n",
			    satype,
			    satype2name(satype),
			    pfkey_socketsp->socketp);
	}

errlab:
	if (alg_a)
		kfree(alg_a);
	if (alg_e)
		kfree(alg_e);

	if (pfkey_reply)
		pfkey_msg_free(&pfkey_reply);
	pfkey_extensions_free(extensions_reply);
	return error;
}

DEBUG_NO_STATIC int pfkey_expire_parse(struct sock *sk,
				       struct sadb_ext **extensions,
				       struct pfkey_extracted_data *extr)
{
	int error = 0;
	struct socket_list *pfkey_socketsp;
	uint8_t satype =
		((struct sadb_msg*)extensions[K_SADB_EXT_RESERVED])->
		sadb_msg_satype;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_expire_parse: .\n");

	if (pfkey_open_sockets) {
		for (pfkey_socketsp = pfkey_open_sockets;
		     pfkey_socketsp;
		     pfkey_socketsp = pfkey_socketsp->next) {
			if ((error = pfkey_upmsg(pfkey_socketsp->socketp,
						 ((struct sadb_msg*)extensions[
							  K_SADB_EXT_RESERVED]))))
			{
				KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_expire_parse: "
					    "sending up expire reply message for satype=%d(%s) to socket=0p%p failed with error=%d.\n",
					    satype,
					    satype2name(satype),
					    pfkey_socketsp->socketp,
					    error);
				SENDERR(-error);
			}
			KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_expire_parse: "
				    "sending up expire reply message for satype=%d(%s) to socket=0p%p succeeded.\n",
				    satype,
				    satype2name(satype),
				    pfkey_socketsp->socketp);
		}
	}

errlab:
	return error;
}

/*
 *
 * flush all SAs from the table
 */
DEBUG_NO_STATIC int pfkey_flush_parse(struct sock *sk,
				      struct sadb_ext **extensions,
				      struct pfkey_extracted_data *extr)
{
	int error = 0;
	struct socket_list *pfkey_socketsp;
	uint8_t satype =
		((struct sadb_msg*)extensions[K_SADB_EXT_RESERVED])->
		sadb_msg_satype;
	uint8_t proto = 0;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_flush_parse: "
		    "flushing type %d SAs\n",
		    satype);

	if (satype && !(proto = satype2proto(satype))) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_flush_parse: "
			    "satype %d lookup failed.\n",
			    ((struct sadb_msg*)extensions[K_SADB_EXT_RESERVED])->sadb_msg_satype);
		SENDERR(EINVAL);
	}

	if ((error = ipsec_sadb_cleanup(proto)))
		SENDERR(-error);

	if (pfkey_open_sockets) {
		for (pfkey_socketsp = pfkey_open_sockets;
		     pfkey_socketsp;
		     pfkey_socketsp = pfkey_socketsp->next) {
			if ((error = pfkey_upmsg(pfkey_socketsp->socketp,
						 ((struct sadb_msg*)extensions[
							  K_SADB_EXT_RESERVED]))))
			{
				KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_flush_parse: "
					    "sending up flush reply message for satype=%d(%s) (proto=%d) to socket=0p%p failed with error=%d.\n",
					    satype,
					    satype2name(satype),
					    proto,
					    pfkey_socketsp->socketp,
					    error);
				SENDERR(-error);
			}
			KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_flush_parse: "
				    "sending up flush reply message for satype=%d(%s) to socket=0p%p succeeded.\n",
				    satype,
				    satype2name(satype),
				    pfkey_socketsp->socketp);
		}
	}

errlab:
	return error;
}

DEBUG_NO_STATIC int pfkey_dump_parse(struct sock *sk,
				     struct sadb_ext **extensions,
				     struct pfkey_extracted_data *extr)
{
	int error = 0;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_dump_parse: .\n");

	SENDERR(ENOSYS);
errlab:
	return error;
}

DEBUG_NO_STATIC int pfkey_x_promisc_parse(struct sock *sk,
					  struct sadb_ext **extensions,
					  struct pfkey_extracted_data *extr)
{
	int error = 0;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_promisc_parse: .\n");

	SENDERR(ENOSYS);
errlab:
	return error;
}

DEBUG_NO_STATIC int pfkey_x_pchange_parse(struct sock *sk,
					  struct sadb_ext **extensions,
					  struct pfkey_extracted_data *extr)
{
	int error = 0;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_x_pchange_parse: .\n");

	SENDERR(ENOSYS);
errlab:
	return error;
}

DEBUG_NO_STATIC int pfkey_x_grpsa_parse(struct sock *sk,
					struct sadb_ext **extensions,
					struct pfkey_extracted_data *extr)
{
	struct ipsec_sa *ips1p, *ips2p, *ipsp;
	struct sadb_ext *extensions_reply[K_SADB_EXT_MAX + 1];
	struct sadb_msg *pfkey_reply = NULL;
	struct socket_list *pfkey_socketsp;
	uint8_t satype =
		((struct sadb_msg*)extensions[K_SADB_EXT_RESERVED])->
		sadb_msg_satype;
	char sa1[SATOT_BUF], sa2[SATOT_BUF];
	size_t sa_len1, sa_len2 = 0;
	int error = 0;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_x_grpsa_parse: .\n");

	pfkey_extensions_init(extensions_reply);

	if (extr == NULL || extr->ips == NULL) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_x_grpsa_parse: "
			    "extr or extr->ips is NULL, fatal.\n");
		SENDERR(EINVAL);
	}

	sa_len1 = KLIPS_SATOT(debug_pfkey, &extr->ips->ips_said, 0, sa1,
			      sizeof(sa1));
	if (extr->ips2 != NULL)
		sa_len2 = KLIPS_SATOT(debug_pfkey, &extr->ips2->ips_said, 0,
				      sa2, sizeof(sa2));

	spin_lock_bh(&tdb_lock);

	ips1p = ipsec_sa_getbyid(&(extr->ips->ips_said), IPSEC_REFSA);
	if (ips1p == NULL) {
		spin_unlock_bh(&tdb_lock);
		KLIPS_ERROR(debug_pfkey,
			    "klips_debug:pfkey_x_grpsa_parse: "
			    "reserved ipsec_sa for SA1: %s not found.  Call K_SADB_ADD/UPDATE first.\n",
			    sa_len1 ? sa1 : " (error)");
		SENDERR(ENOENT);
	}

	if (extr->ips2) { /* GRPSA */

		/* group ips2p to be after ips1p */

		ips2p = ipsec_sa_getbyid(&(extr->ips2->ips_said), IPSEC_REFSA);
		if (ips2p == NULL) {
			ipsec_sa_put(ips1p, IPSEC_REFSA);
			spin_unlock_bh(&tdb_lock);
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_x_grpsa_parse: "
				    "reserved ipsec_sa for SA2: %s not found.  Call K_SADB_ADD/UPDATE first.\n",
				    sa_len2 ? sa2 : " (error)");
			SENDERR(ENOENT);
		}

		/* userspace puts things in inner to outer order */
		if (ips2p->ips_flags & EMT_INBOUND) {
			struct ipsec_sa *t;

			/* exchange ips and ips2 */
			t = ips1p;
			ips1p = ips2p;
			ips2p = t;
		}

		/* Is ips1p already linked? */
		if (ips1p->ips_next) {
			ipsec_sa_put(ips1p, IPSEC_REFSA);
			ipsec_sa_put(ips2p, IPSEC_REFSA);
			spin_unlock_bh(&tdb_lock);
			KLIPS_ERROR(debug_pfkey,
				    "klips_debug:pfkey_x_grpsa_parse: "
				    "ipsec_sa for SA: %s is already linked.\n",
				    sa_len1 ? sa1 : " (error)");
			SENDERR(EEXIST);
		}

		/* Is extr->ips already linked to extr->ips2? */
		ipsp = ips2p;
		while (ipsp) {
			if (ipsp == ips1p) {
				ipsec_sa_put(ips1p, IPSEC_REFSA);
				ipsec_sa_put(ips2p, IPSEC_REFSA);
				spin_unlock_bh(&tdb_lock);
				KLIPS_ERROR(debug_pfkey,
					    "klips_debug:pfkey_x_grpsa_parse: "
					    "ipsec_sa for SA: %s is already linked to %s.\n",
					    sa_len1 ? sa1 : " (error)",
					    sa_len2 ? sa2 : " (error)");
				SENDERR(EEXIST);
			}
			ipsp = ipsp->ips_next;
		}

		/* link 'em */
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_x_grpsa_parse: "
			    "linking ipsec_sa SA: %s with %s.\n",
			    sa_len1 ? sa1 : " (error)",
			    sa_len2 ? sa2 : " (error)");
		ips1p->ips_next = ips2p;
		ips2p->ips_prev = ips1p;
		ipsec_sa_put(ips1p, IPSEC_REFSA);
		ipsec_sa_put(ips2p, IPSEC_REFSA);
	} else { /* UNGRPSA */
		while (ips1p) {
			struct ipsec_sa *ipsn;

			/* take the reference to next */
			ipsn = ips1p->ips_next;
			if (ipsn)
				ipsn->ips_prev = NULL;
			ips1p->ips_next = NULL;
			ips1p->ips_prev = NULL;

			/* drop reference to current */
			ipsec_sa_put(ips1p, IPSEC_REFSA);

			ips1p = ipsn;
		}

		/* note: we have dropped reference to ips1p, and
		 * it is now NULL
		 */
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_x_grpsa_parse: "
			    "unlinking ipsec_sa SA: %s.\n",
			    sa_len1 ? sa1 : " (error)");
	}

	spin_unlock_bh(&tdb_lock);

	/* MCR: not only is this ugly to read, and impossible
	 *   to debug through, but it's also really inefficient.
	 * XXX simplify me.
	 */
	if (!(pfkey_safe_build(error = pfkey_msg_hdr_build(&extensions_reply[0],
							   K_SADB_X_GRPSA,
							   satype,
							   0,
							   ((struct sadb_msg*)
							    extensions[
								    K_SADB_EXT_RESERVED
							    ])->sadb_msg_seq,
							   ((struct sadb_msg*)
							    extensions[
								    K_SADB_EXT_RESERVED
							    ])->sadb_msg_pid),
			       extensions_reply) &&
	      pfkey_safe_build(error = pfkey_sa_build(&extensions_reply[
							      K_SADB_EXT_SA],
						      K_SADB_EXT_SA,
						      extr->ips->ips_said.spi,
						      extr->ips->ips_replaywin,
						      extr->ips->ips_state,
						      extr->ips->ips_authalg,
						      extr->ips->ips_encalg,
						      extr->ips->ips_flags),
			       extensions_reply) &&
	      pfkey_safe_build(error = pfkey_address_build(&extensions_reply[
								   K_SADB_EXT_ADDRESS_DST
							   ],
							   K_SADB_EXT_ADDRESS_DST,
							   0,   /*extr->ips->ips_said.proto,*/
							   0,
							   extr->ips->
							   ips_addr_d),
			       extensions_reply) &&
	      (extr->ips2 == 0 ||
	       (pfkey_safe_build(error = pfkey_x_satype_build(&extensions_reply
							      [
								      K_SADB_X_EXT_SATYPE2
							      ],
							      ((struct
								sadb_x_satype*)
							       extensions[
								       K_SADB_X_EXT_SATYPE2
							       ])->
							      sadb_x_satype_satype
							      /* proto2satype(extr->ips2->ips_said.proto) */),
				 extensions_reply) &&
		pfkey_safe_build(error = pfkey_sa_build(&extensions_reply[
								K_SADB_X_EXT_SA2
							],
							K_SADB_X_EXT_SA2,
							extr->ips2->ips_said.
							spi,
							extr->ips2->
							ips_replaywin,
							extr->ips2->ips_state,
							extr->ips2->
							ips_authalg,
							extr->ips2->
							ips_encalg,
							extr->ips2->ips_flags),
				 extensions_reply) &&
		pfkey_safe_build(error = pfkey_address_build(&extensions_reply[
								     K_SADB_X_EXT_ADDRESS_DST2
							     ],
							     K_SADB_X_EXT_ADDRESS_DST2,
							     0,        /*extr->ips->ips_said.proto,*/
							     0,
							     extr->ips2->
							     ips_addr_d),
				 extensions_reply) ))
	      )) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_x_grpsa_parse: "
			    "failed to build the x_grpsa reply message extensions\n");
		SENDERR(-error);
	}

	if ((error = pfkey_msg_build(&pfkey_reply, extensions_reply,
				     EXT_BITS_OUT))) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_x_grpsa_parse: "
			    "failed to build the x_grpsa reply message\n");
		SENDERR(-error);
	}

	for (pfkey_socketsp = pfkey_open_sockets;
	     pfkey_socketsp;
	     pfkey_socketsp = pfkey_socketsp->next) {
		if ((error = pfkey_upmsg(pfkey_socketsp->socketp,
					 pfkey_reply))) {
			KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_x_grpsa_parse: "
				    "sending up x_grpsa reply message for satype=%d(%s) to socket=0p%p failed with error=%d.\n",
				    satype,
				    satype2name(satype),
				    pfkey_socketsp->socketp,
				    error);
			SENDERR(-error);
		}
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_x_grpsa_parse: "
			    "sending up x_grpsa reply message for satype=%d(%s) to socket=0p%p succeeded.\n",
			    satype,
			    satype2name(satype),
			    pfkey_socketsp->socketp);
	}

	KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_x_grpsa_parse: "
		    "succeeded in sending x_grpsa reply message.\n");

errlab:
	if (pfkey_reply)
		pfkey_msg_free(&pfkey_reply);
	pfkey_extensions_free(extensions_reply);
	return error;
}

DEBUG_NO_STATIC int pfkey_x_addflow_parse(struct sock *sk,
					  struct sadb_ext **extensions,
					  struct pfkey_extracted_data *extr)
{
	int error = 0;
	struct sadb_ext *extensions_reply[K_SADB_EXT_MAX + 1];
	struct sadb_msg *pfkey_reply = NULL;
	struct socket_list *pfkey_socketsp;
	uint8_t satype =
		((struct sadb_msg*)extensions[K_SADB_EXT_RESERVED])->
		sadb_msg_satype;
	ip_address srcflow, dstflow, srcmask, dstmask;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_x_addflow_parse: .\n");

	pfkey_extensions_init(extensions_reply);

	memset((caddr_t)&srcflow, 0, sizeof(srcflow));
	memset((caddr_t)&dstflow, 0, sizeof(dstflow));
	memset((caddr_t)&srcmask, 0, sizeof(srcmask));
	memset((caddr_t)&dstmask, 0, sizeof(dstmask));

	if (!extr || !(extr->ips) || !(extr->eroute)) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_x_addflow_parse: "
			    "missing extr, ipsec_sa or eroute data.\n");
		SENDERR(EINVAL);
	}

	if (extr->eroute->er_eaddr.sen_type == SENT_IP6) {
		srcflow.u.v6.sin6_family = AF_INET6;
		dstflow.u.v6.sin6_family = AF_INET6;
		srcmask.u.v6.sin6_family = AF_INET6;
		dstmask.u.v6.sin6_family = AF_INET6;

		srcflow.u.v6.sin6_addr = extr->eroute->er_eaddr.sen_ip6_src;
		dstflow.u.v6.sin6_addr = extr->eroute->er_eaddr.sen_ip6_dst;
		srcmask.u.v6.sin6_addr = extr->eroute->er_emask.sen_ip6_src;
		dstmask.u.v6.sin6_addr = extr->eroute->er_emask.sen_ip6_dst;
	} else {
		srcflow.u.v4.sin_family = AF_INET;
		dstflow.u.v4.sin_family = AF_INET;
		srcmask.u.v4.sin_family = AF_INET;
		dstmask.u.v4.sin_family = AF_INET;

		srcflow.u.v4.sin_addr = extr->eroute->er_eaddr.sen_ip_src;
		dstflow.u.v4.sin_addr = extr->eroute->er_eaddr.sen_ip_dst;
		srcmask.u.v4.sin_addr = extr->eroute->er_emask.sen_ip_src;
		dstmask.u.v4.sin_addr = extr->eroute->er_emask.sen_ip_dst;
	}

	if (debug_pfkey) {
		char buf1[64], buf2[64];
		if (extr->eroute->er_eaddr.sen_type == SENT_IP6) {
			subnet6toa(&extr->eroute->er_eaddr.sen_ip6_src,
				   &extr->eroute->er_emask.sen_ip6_src, 0,
				   buf1, sizeof(buf1));
			subnet6toa(&extr->eroute->er_eaddr.sen_ip6_dst,
				   &extr->eroute->er_emask.sen_ip6_dst, 0,
				   buf2, sizeof(buf2));
		} else {
			subnettoa(extr->eroute->er_eaddr.sen_ip_src,
				  extr->eroute->er_emask.sen_ip_src, 0, buf1,
				  sizeof(buf1));
			subnettoa(extr->eroute->er_eaddr.sen_ip_dst,
				  extr->eroute->er_emask.sen_ip_dst, 0, buf2,
				  sizeof(buf2));
		}
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_x_addflow_parse: "
			    "calling breakeroute and/or makeroute for %s->%s\n",
			    buf1, buf2);
	}

	if (extr->ips->ips_flags & SADB_X_SAFLAGS_INFLOW ||
	    extr->ips->ips_flags & SADB_X_SAFLAGS_POLICYONLY) {
		struct ipsec_sa *ipsp, *ipsq;
		char sa[SATOT_BUF];
		size_t sa_len;

		spin_lock_bh(&tdb_lock);

		ipsq = ipsec_sa_getbyid(&(extr->ips->ips_said), IPSEC_REFSA);
		if (ipsq == NULL) {
			spin_unlock_bh(&tdb_lock);
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_x_addflow_parse: "
				    "ipsec_sa not found, cannot set incoming policy.\n");
			SENDERR(ENOENT);
		}

		ipsp = ipsq;
		while (ipsp && ipsp->ips_said.proto != IPPROTO_IPIP)
			ipsp = ipsp->ips_next;

		if (ipsp == NULL) {
			ipsec_sa_put(ipsq, IPSEC_REFSA);
			spin_unlock_bh(&tdb_lock);
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_x_addflow_parse: "
				    "SA chain does not have an IPIP SA, cannot set incoming policy.\n");
			SENDERR(ENOENT);
		}

		sa_len = KLIPS_SATOT(debug_pfkey, &extr->ips->ips_said, 0, sa,
				     sizeof(sa));

		ipsp->ips_flags |= extr->ips->ips_flags &
				   (SADB_X_SAFLAGS_INFLOW |
				    SADB_X_SAFLAGS_POLICYONLY);
		ipsp->ips_flow_s = srcflow;
		ipsp->ips_flow_d = dstflow;
		ipsp->ips_mask_s = srcmask;
		ipsp->ips_mask_d = dstmask;

		ipsec_sa_put(ipsq, IPSEC_REFSA);

		spin_unlock_bh(&tdb_lock);

		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_x_addflow_parse: "
			    "inbound eroute, setting incoming policy information in IPIP ipsec_sa for SA: %s.\n",
			    sa_len ? sa : " (error)");
	} else {
		struct sk_buff *first = NULL, *last = NULL;

		if (extr->ips->ips_flags & SADB_X_SAFLAGS_REPLACEFLOW) {
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_x_addflow_parse: "
				    "REPLACEFLOW flag set, calling breakeroute.\n");
			if ((error = ipsec_breakroute(&(extr->eroute->er_eaddr),
						      &(extr->eroute->er_emask),
						      &first, &last))) {
				KLIPS_PRINT(debug_pfkey,
					    "klips_debug:pfkey_x_addflow_parse: "
					    "breakeroute returned %d.  first=0p%p, last=0p%p\n",
					    error,
					    first,
					    last);
				if (first != NULL)
					ipsec_kfree_skb(first);
				if (last != NULL)
					ipsec_kfree_skb(last);
				SENDERR(-error);
			}
		}

		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_x_addflow_parse: "
			    "calling makeroute.\n");

		if ((error = ipsec_makeroute(&(extr->eroute->er_eaddr),
					     &(extr->eroute->er_emask),
					     extr->ips->ips_said,
					     ((struct sadb_msg*)extensions[
						      K_SADB_EXT_RESERVED])->
					     sadb_msg_pid,
					     NULL,
					     &(extr->ips->ips_ident_s),
					     &(extr->ips->ips_ident_d)))) {
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_x_addflow_parse: "
				    "makeroute returned %d.\n", error);
			SENDERR(-error);
		}
		if (first != NULL) {
			KLIPS_PRINT(debug_eroute,
				    "klips_debug:pfkey_x_addflow_parse: "
				    "first=0p%p HOLD packet re-injected.\n",
				    first);
			dev_queue_xmit(first);
		}
		if (last != NULL) {
			KLIPS_PRINT(debug_eroute,
				    "klips_debug:pfkey_x_addflow_parse: "
				    "last=0p%p HOLD packet re-injected.\n",
				    last);
			dev_queue_xmit(last);
		}
	}

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_x_addflow_parse: "
		    "makeroute call successful.\n");

	if (!(pfkey_safe_build(error = pfkey_msg_hdr_build(&extensions_reply[0],
							   K_SADB_X_ADDFLOW,
							   satype,
							   0,
							   ((struct sadb_msg*)
							    extensions[
								    K_SADB_EXT_RESERVED
							    ])->sadb_msg_seq,
							   ((struct sadb_msg*)
							    extensions[
								    K_SADB_EXT_RESERVED
							    ])->sadb_msg_pid),
			       extensions_reply) &&
	      pfkey_safe_build(error = pfkey_sa_build(&extensions_reply[
							      K_SADB_EXT_SA],
						      K_SADB_EXT_SA,
						      extr->ips->ips_said.spi,
						      extr->ips->ips_replaywin,
						      extr->ips->ips_state,
						      extr->ips->ips_authalg,
						      extr->ips->ips_encalg,
						      extr->ips->ips_flags),
			       extensions_reply) &&
	      (extensions[K_SADB_EXT_ADDRESS_SRC] == NULL ||
	       pfkey_safe_build(error = pfkey_address_build(&extensions_reply[
								    K_SADB_EXT_ADDRESS_SRC
							    ],
							    K_SADB_EXT_ADDRESS_SRC,
							    0,     /*extr->ips->ips_said.proto,*/
							    0,
							    extr->ips->
							    ips_addr_s),
				extensions_reply)) &&
	      (extensions[K_SADB_EXT_ADDRESS_DST] == NULL ||
	       pfkey_safe_build(error = pfkey_address_build(&extensions_reply[
								    K_SADB_EXT_ADDRESS_DST
							    ],
							    K_SADB_EXT_ADDRESS_DST,
							    0,     /*extr->ips->ips_said.proto,*/
							    0,
							    extr->ips->
							    ips_addr_d),
				extensions_reply)) &&
	      pfkey_safe_build(error = pfkey_address_build(&extensions_reply[
								   K_SADB_X_EXT_ADDRESS_SRC_FLOW
							   ],
							   K_SADB_X_EXT_ADDRESS_SRC_FLOW,
							   0,   /*extr->ips->ips_said.proto,*/
							   0,
							   (struct sockaddr*)&
							   srcflow),
			       extensions_reply) &&
	      pfkey_safe_build(error = pfkey_address_build(&extensions_reply[
								   K_SADB_X_EXT_ADDRESS_DST_FLOW
							   ],
							   K_SADB_X_EXT_ADDRESS_DST_FLOW,
							   0,   /*extr->ips->ips_said.proto,*/
							   0,
							   (struct sockaddr*)&
							   dstflow),
			       extensions_reply) &&
	      pfkey_safe_build(error = pfkey_address_build(&extensions_reply[
								   K_SADB_X_EXT_ADDRESS_SRC_MASK
							   ],
							   K_SADB_X_EXT_ADDRESS_SRC_MASK,
							   0,   /*extr->ips->ips_said.proto,*/
							   0,
							   (struct sockaddr*)&
							   srcmask),
			       extensions_reply) &&
	      pfkey_safe_build(error = pfkey_address_build(&extensions_reply[
								   K_SADB_X_EXT_ADDRESS_DST_MASK
							   ],
							   K_SADB_X_EXT_ADDRESS_DST_MASK,
							   0,   /*extr->ips->ips_said.proto,*/
							   0,
							   (struct sockaddr*)&
							   dstmask),
			       extensions_reply)
	      )) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_x_addflow_parse: "
			    "failed to build the x_addflow reply message extensions\n");
		SENDERR(-error);
	}

	if ((error = pfkey_msg_build(&pfkey_reply, extensions_reply,
				     EXT_BITS_OUT))) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_x_addflow_parse: "
			    "failed to build the x_addflow reply message\n");
		SENDERR(-error);
	}

	for (pfkey_socketsp = pfkey_open_sockets;
	     pfkey_socketsp;
	     pfkey_socketsp = pfkey_socketsp->next) {
		if ((error = pfkey_upmsg(pfkey_socketsp->socketp,
					 pfkey_reply))) {
			KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_x_addflow_parse: "
				    "sending up x_addflow reply message for satype=%d(%s) to socket=0p%p failed with error=%d.\n",
				    satype,
				    satype2name(satype),
				    pfkey_socketsp->socketp,
				    error);
			SENDERR(-error);
		}
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_x_addflow_parse: "
			    "sending up x_addflow reply message for satype=%d(%s) (proto=%d) to socket=0p%p succeeded.\n",
			    satype,
			    satype2name(satype),
			    extr->ips->ips_said.proto,
			    pfkey_socketsp->socketp);
	}

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_x_addflow_parse: "
		    "extr->ips cleaned up and freed.\n");

errlab:
	if (pfkey_reply)
		pfkey_msg_free(&pfkey_reply);
	pfkey_extensions_free(extensions_reply);
	return error;
}

DEBUG_NO_STATIC int pfkey_x_delflow_parse(struct sock *sk,
					  struct sadb_ext **extensions,
					  struct pfkey_extracted_data *extr)
{
	int error = 0;
	struct sadb_ext *extensions_reply[K_SADB_EXT_MAX + 1];
	struct sadb_msg *pfkey_reply = NULL;
	struct socket_list *pfkey_socketsp;
	uint8_t satype =
		((struct sadb_msg*)extensions[K_SADB_EXT_RESERVED])->
		sadb_msg_satype;
	ip_address srcflow, dstflow, srcmask, dstmask;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_x_delflow_parse: .\n");

	pfkey_extensions_init(extensions_reply);

	memset((caddr_t)&srcflow, 0, sizeof(srcflow));
	memset((caddr_t)&dstflow, 0, sizeof(dstflow));
	memset((caddr_t)&srcmask, 0, sizeof(srcmask));
	memset((caddr_t)&dstmask, 0, sizeof(dstmask));

	if (!extr || !(extr->ips)) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_x_delflow_parse: "
			    "extr, or extr->ips is NULL, fatal\n");
		SENDERR(EINVAL);
	}

	if (extr->ips->ips_flags & SADB_X_SAFLAGS_POLICYONLY) {
		/* nothing else to do */
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_x_delflow_parse: "
			    "POLICYONLY flag set, done.\n");
	} else if (extr->ips->ips_flags & SADB_X_SAFLAGS_CLEARFLOW) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_x_delflow_parse: "
			    "CLEARFLOW flag set, calling cleareroutes.\n");
		if ((error = ipsec_cleareroutes())) {
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_x_delflow_parse: "
				    "cleareroutes returned %d.\n", error);
			SENDERR(-error);
		}
	} else {
		struct sk_buff *first = NULL, *last = NULL;

		if (!(extr->eroute)) {
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_x_delflow_parse: "
				    "extr->eroute is NULL, fatal.\n");
			SENDERR(EINVAL);
		}

		if (extr->eroute->er_eaddr.sen_type == SENT_IP6) {
			srcflow.u.v6.sin6_family = AF_INET6;
			dstflow.u.v6.sin6_family = AF_INET6;
			srcmask.u.v6.sin6_family = AF_INET6;
			dstmask.u.v6.sin6_family = AF_INET6;

			srcflow.u.v6.sin6_addr =
				extr->eroute->er_eaddr.sen_ip6_src;
			dstflow.u.v6.sin6_addr =
				extr->eroute->er_eaddr.sen_ip6_dst;
			srcmask.u.v6.sin6_addr =
				extr->eroute->er_emask.sen_ip6_src;
			dstmask.u.v6.sin6_addr =
				extr->eroute->er_emask.sen_ip6_dst;
		} else {
			srcflow.u.v4.sin_family = AF_INET;
			dstflow.u.v4.sin_family = AF_INET;
			srcmask.u.v4.sin_family = AF_INET;
			dstmask.u.v4.sin_family = AF_INET;

			srcflow.u.v4.sin_addr =
				extr->eroute->er_eaddr.sen_ip_src;
			dstflow.u.v4.sin_addr =
				extr->eroute->er_eaddr.sen_ip_dst;
			srcmask.u.v4.sin_addr =
				extr->eroute->er_emask.sen_ip_src;
			dstmask.u.v4.sin_addr =
				extr->eroute->er_emask.sen_ip_dst;
		}

		if (debug_pfkey) {
			char buf1[64], buf2[64];
			if (extr->eroute->er_eaddr.sen_type == SENT_IP6) {
				subnet6toa(&extr->eroute->er_eaddr.sen_ip6_src,
					   &extr->eroute->er_emask.sen_ip6_src,
					   0, buf1, sizeof(buf1));
				subnet6toa(&extr->eroute->er_eaddr.sen_ip6_dst,
					   &extr->eroute->er_emask.sen_ip6_dst,
					   0, buf2, sizeof(buf2));
			} else {
				subnettoa(extr->eroute->er_eaddr.sen_ip_src,
					  extr->eroute->er_emask.sen_ip_src, 0,
					  buf1, sizeof(buf1));
				subnettoa(extr->eroute->er_eaddr.sen_ip_dst,
					  extr->eroute->er_emask.sen_ip_dst, 0,
					  buf2, sizeof(buf2));
			}
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_x_delflow_parse: "
				    "calling breakeroute for %s->%s\n",
				    buf1, buf2);
		}
		error = ipsec_breakroute(&(extr->eroute->er_eaddr),
					 &(extr->eroute->er_emask),
					 &first, &last);
		if (error) {
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_x_delflow_parse: "
				    "breakeroute returned %d.  first=0p%p, last=0p%p\n",
				    error,
				    first,
				    last);
		}
		if (first != NULL)
			ipsec_kfree_skb(first);
		if (last != NULL)
			ipsec_kfree_skb(last);
		if (error)
			SENDERR(-error);
	}

	error = pfkey_msg_hdr_build(&extensions_reply[0],
				    K_SADB_X_DELFLOW,
				    satype,
				    0,
				    ((struct sadb_msg*)extensions[
					     K_SADB_EXT_RESERVED])->sadb_msg_seq,
				    ((struct sadb_msg*)extensions[
					     K_SADB_EXT_RESERVED])->sadb_msg_pid);

	if (pfkey_safe_build(error, extensions_reply)) {
		error = pfkey_sa_build(&extensions_reply[K_SADB_EXT_SA],
				       K_SADB_EXT_SA,
				       extr->ips->ips_said.spi,
				       extr->ips->ips_replaywin,
				       extr->ips->ips_state,
				       extr->ips->ips_authalg,
				       extr->ips->ips_encalg,
				       extr->ips->ips_flags);
	}

	if (!(extr->ips->ips_flags &
	      (SADB_X_SAFLAGS_CLEARFLOW | SADB_X_SAFLAGS_POLICYONLY))) {
		if (pfkey_safe_build(error, extensions_reply)) {
			error = pfkey_address_build(
					&extensions_reply[
						K_SADB_X_EXT_ADDRESS_SRC_FLOW],
					K_SADB_X_EXT_ADDRESS_SRC_FLOW,
					0,                      /*extr->ips->ips_said.proto,*/
					0,
					(struct sockaddr*)&srcflow);
		}

		if (pfkey_safe_build(error, extensions_reply)) {
			error = pfkey_address_build(
					&extensions_reply[
						K_SADB_X_EXT_ADDRESS_DST_FLOW],
					K_SADB_X_EXT_ADDRESS_DST_FLOW,
					0,                      /*extr->ips->ips_said.proto,*/
					0,
					(struct sockaddr*)&dstflow);
		}

		if (pfkey_safe_build(error, extensions_reply)) {
			error = pfkey_address_build(
					&extensions_reply[
						K_SADB_X_EXT_ADDRESS_SRC_MASK],
					K_SADB_X_EXT_ADDRESS_SRC_MASK,
					0,                      /*extr->ips->ips_said.proto,*/
					0,
					(struct sockaddr*)&srcmask);
		}

		if (pfkey_safe_build(error, extensions_reply)) {
			error = pfkey_address_build(
					&extensions_reply[
						K_SADB_X_EXT_ADDRESS_DST_MASK],
					K_SADB_X_EXT_ADDRESS_DST_MASK,
					0,                      /*extr->ips->ips_said.proto,*/
					0,
					(struct sockaddr*)&dstmask);
		}
	}

	if (!pfkey_safe_build(error, extensions_reply)) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_x_delflow_parse: "
			    "failed to build the x_delflow reply message extensions\n");
		SENDERR(-error);
	}

	if ((error = pfkey_msg_build(&pfkey_reply, extensions_reply,
				     EXT_BITS_OUT))) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_x_delflow_parse: "
			    "failed to build the x_delflow reply message\n");
		SENDERR(-error);
	}

	for (pfkey_socketsp = pfkey_open_sockets;
	     pfkey_socketsp;
	     pfkey_socketsp = pfkey_socketsp->next) {
		if ((error = pfkey_upmsg(pfkey_socketsp->socketp,
					 pfkey_reply))) {
			KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_x_delflow_parse: "
				    "sending up x_delflow reply message for satype=%d(%s) to socket=0p%p failed with error=%d.\n",
				    satype,
				    satype2name(satype),
				    pfkey_socketsp->socketp,
				    error);
			SENDERR(-error);
		}
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_x_delflow_parse: "
			    "sending up x_delflow reply message for satype=%d(%s) to socket=0p%p succeeded.\n",
			    satype,
			    satype2name(satype),
			    pfkey_socketsp->socketp);
	}

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_x_delflow_parse: "
		    "extr->ips cleaned up and freed.\n");

errlab:
	if (pfkey_reply)
		pfkey_msg_free(&pfkey_reply);
	pfkey_extensions_free(extensions_reply);
	return error;
}

DEBUG_NO_STATIC int pfkey_x_msg_debug_parse(struct sock *sk,
					    struct sadb_ext **extensions,
					    struct pfkey_extracted_data *extr)
{
	int error = 0;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_x_msg_debug_parse: .\n");

/* errlab:*/
	return error;
}

/* pfkey_expire expects the ipsec_sa table to be locked before being called. */
int pfkey_expire(struct ipsec_sa *ipsp, int hard)
{
	struct sadb_ext *extensions[K_SADB_EXT_MAX + 1];
	struct sadb_msg *pfkey_msg = NULL;
	struct socket_list *pfkey_socketsp;
	int error = 0;
	uint8_t satype;

	pfkey_extensions_init(extensions);

	if (!(satype = proto2satype(ipsp->ips_said.proto))) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_expire: "
			    "satype lookup for protocol %d lookup failed.\n",
			    ipsp->ips_said.proto);
		SENDERR(EINVAL);
	}

	if (!pfkey_open_sockets) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_expire: "
			    "no sockets listening.\n");
		SENDERR(EPROTONOSUPPORT);
	}

	if (!(pfkey_safe_build(error = pfkey_msg_hdr_build(&extensions[0],
							   K_SADB_EXPIRE,
							   satype,
							   0,
							   ++pfkey_msg_seq,
							   0),
			       extensions) &&
	      pfkey_safe_build(error = pfkey_sa_build(&extensions[K_SADB_EXT_SA
						      ],
						      K_SADB_EXT_SA,
						      ipsp->ips_said.spi,
						      ipsp->ips_replaywin,
						      ipsp->ips_state,
						      ipsp->ips_authalg,
						      ipsp->ips_encalg,
						      ipsp->ips_flags),
			       extensions) &&
	      pfkey_safe_build(error = pfkey_lifetime_build(&extensions[
								    K_SADB_EXT_LIFETIME_CURRENT
							    ],
							    K_SADB_EXT_LIFETIME_CURRENT,
							    ipsp->ips_life.
							    ipl_allocations.
							    ipl_count,
							    ipsp->ips_life.
							    ipl_bytes.ipl_count,
							    ipsp->ips_life.
							    ipl_addtime.
							    ipl_count,
							    ipsp->ips_life.
							    ipl_usetime.
							    ipl_count,
							    ipsp->ips_life.
							    ipl_packets.
							    ipl_count),
			       extensions) &&
	      (hard ?
	       pfkey_safe_build(error = pfkey_lifetime_build(&extensions[
								     K_SADB_EXT_LIFETIME_HARD
							     ],
							     K_SADB_EXT_LIFETIME_HARD,
							     ipsp->ips_life.
							     ipl_allocations.
							     ipl_hard,
							     ipsp->ips_life.
							     ipl_bytes.ipl_hard,
							     ipsp->ips_life.
							     ipl_addtime.
							     ipl_hard,
							     ipsp->ips_life.
							     ipl_usetime.
							     ipl_hard,
							     ipsp->ips_life.
							     ipl_packets.
							     ipl_hard),
				extensions) :
	       pfkey_safe_build(error = pfkey_lifetime_build(&extensions[
								     K_SADB_EXT_LIFETIME_SOFT
							     ],
							     K_SADB_EXT_LIFETIME_SOFT,
							     ipsp->ips_life.
							     ipl_allocations.
							     ipl_soft,
							     ipsp->ips_life.
							     ipl_bytes.ipl_soft,
							     ipsp->ips_life.
							     ipl_addtime.
							     ipl_soft,
							     ipsp->ips_life.
							     ipl_usetime.
							     ipl_soft,
							     ipsp->ips_life.
							     ipl_packets.
							     ipl_soft),
				extensions)) &&
	      pfkey_safe_build(error = pfkey_address_build(&extensions[
								   K_SADB_EXT_ADDRESS_SRC
							   ],
							   K_SADB_EXT_ADDRESS_SRC,
							   0,    /* ipsp->ips_said.proto, */
							   0,
							   ipsp->ips_addr_s),
			       extensions) &&
	      pfkey_safe_build(error = pfkey_address_build(&extensions[
								   K_SADB_EXT_ADDRESS_DST
							   ],
							   K_SADB_EXT_ADDRESS_DST,
							   0,    /* ipsp->ips_said.proto, */
							   0,
							   ipsp->ips_addr_d),
			       extensions))) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_expire: "
			    "failed to build the expire message extensions\n");
		spin_unlock_bh(&tdb_lock);
		goto errlab;
	}

	if ((error = pfkey_msg_build(&pfkey_msg, extensions, EXT_BITS_OUT))) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_expire: "
			    "failed to build the expire message\n");
		SENDERR(-error);
	}

	for (pfkey_socketsp = pfkey_open_sockets;
	     pfkey_socketsp;
	     pfkey_socketsp = pfkey_socketsp->next) {
		if ((error = pfkey_upmsg(pfkey_socketsp->socketp,
					 pfkey_msg))) {
			KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_expire: "
				    "sending up expire message for satype=%d(%s) to socket=0p%p failed with error=%d.\n",
				    satype,
				    satype2name(satype),
				    pfkey_socketsp->socketp,
				    error);
			SENDERR(-error);
		}
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_expire: "
			    "sending up expire message for satype=%d(%s) (proto=%d) to socket=0p%p succeeded.\n",
			    satype,
			    satype2name(satype),
			    ipsp->ips_said.proto,
			    pfkey_socketsp->socketp);
	}

errlab:
	if (pfkey_msg)
		pfkey_msg_free(&pfkey_msg);
	pfkey_extensions_free(extensions);
	return error;
}

int pfkey_acquire(struct ipsec_sa *ipsp)
{
	struct sadb_ext *extensions[K_SADB_EXT_MAX + 1];
	struct sadb_msg *pfkey_msg = NULL;
	struct socket_list *pfkey_socketsp;
	int error = 0;
	struct sadb_comb comb[] = {
		/* auth; encrypt; flags; */
		/* auth_minbits; auth_maxbits; encrypt_minbits; encrypt_maxbits; */
		/* reserved; soft_allocations; hard_allocations; soft_bytes; hard_bytes; */
		/* soft_addtime; hard_addtime; soft_usetime; hard_usetime; */
		/* soft_packets; hard_packets; */
		{ K_SADB_AALG_MD5HMAC,  K_SADB_EALG_3DESCBC, SADB_SAFLAGS_PFS,
		  128, 128, 168, 168,
		  0, 0, 0, 0, 0,
		  16*secs_per_hour, secs_per_day, 16*secs_per_hour, secs_per_day },
		{ K_SADB_AALG_SHA1HMAC, K_SADB_EALG_3DESCBC, SADB_SAFLAGS_PFS,
		  160, 160, 168, 168,
		  0, 0, 0, 0, 0,
		  16*secs_per_hour, secs_per_day, 16*secs_per_hour, secs_per_day },
	};

	/* XXX This should not be hard-coded.  It should be taken from the spdb */
	uint8_t satype = K_SADB_SATYPE_ESP;

	pfkey_extensions_init(extensions);

	if ((satype == 0) || (satype > K_SADB_SATYPE_MAX)) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_acquire: "
			    "SAtype=%d unspecified or unknown.\n",
			    satype);
		SENDERR(EINVAL);
	}

	if (!(pfkey_registered_sockets[satype])) {
		KLIPS_PRINT(1 | debug_pfkey, "klips_debug:pfkey_acquire: "
			    "no sockets registered for SAtype=%d(%s).\n",
			    satype,
			    satype2name(satype));
		SENDERR(EPROTONOSUPPORT);
	}

	if (!(pfkey_safe_build(error = pfkey_msg_hdr_build(&extensions[0],
							   K_SADB_ACQUIRE,
							   satype,
							   0,
							   ++pfkey_msg_seq,
							   0),
			       extensions) &&
	      pfkey_safe_build(error = pfkey_address_build(&extensions[
								   K_SADB_EXT_ADDRESS_SRC
							   ],
							   K_SADB_EXT_ADDRESS_SRC,
							   ipsp->
							   ips_transport_protocol,
							   0,
							   ipsp->ips_addr_s),
			       extensions) &&
	      pfkey_safe_build(error = pfkey_address_build(&extensions[
								   K_SADB_EXT_ADDRESS_DST
							   ],
							   K_SADB_EXT_ADDRESS_DST,
							   ipsp->
							   ips_transport_protocol,
							   0,
							   ipsp->ips_addr_d),
			       extensions)
#if 0
	      && (ipsp->ips_addr_p == NULL ||
		  pfkey_safe_build(error = pfkey_address_build(&extensions[
								       K_SADB_EXT_ADDRESS_PROXY
							       ],
							       K_SADB_EXT_ADDRESS_PROXY,
							       ipsp->
							       ips_transport_protocol,
							       0,
							       ipsp->ips_addr_p),
				   extensions))
#endif
	      && (ipsp->ips_ident_s.type == SADB_IDENTTYPE_RESERVED ||
		  pfkey_safe_build(error = pfkey_ident_build(&extensions[
								     SADB_EXT_IDENTITY_SRC
							     ],
							     K_SADB_EXT_IDENTITY_SRC,
							     ipsp->ips_ident_s.
							     type,
							     ipsp->ips_ident_s.
							     id,
							     ipsp->ips_ident_s.
							     len,
							     ipsp->ips_ident_s.
							     data),
				   extensions))

	      && (ipsp->ips_ident_d.type == SADB_IDENTTYPE_RESERVED ||
		  pfkey_safe_build(error = pfkey_ident_build(&extensions[
								     K_SADB_EXT_IDENTITY_DST
							     ],
							     K_SADB_EXT_IDENTITY_DST,
							     ipsp->ips_ident_d.
							     type,
							     ipsp->ips_ident_d.
							     id,
							     ipsp->ips_ident_d.
							     len,
							     ipsp->ips_ident_d.
							     data),
				   extensions))
#if 0
		/* FIXME: This won't work yet because I have not finished it */
	      && (ipsp->ips_sens_== 0 ||
		  pfkey_safe_build(error = pfkey_sens_build(&extensions[
								    K_SADB_EXT_SENSITIVITY
							    ],
							    ipsp->ips_sens_dpd,
							    ipsp->
							    ips_sens_sens_level,
							    ipsp->
							    ips_sens_sens_len,
							    ipsp->
							    ips_sens_sens_bitmap,
							    ipsp->
							    ips_sens_integ_level,
							    ipsp->
							    ips_sens_integ_len,
							    ipsp->
							    ips_sens_integ_bitmap),
				   extensions))
#endif
	      && pfkey_safe_build(error = pfkey_prop_build(&extensions[
								   K_SADB_EXT_PROPOSAL
							   ],
							   64, /* replay */
							   sizeof(comb) /
							   sizeof(struct
								  sadb_comb),
							   &(comb[0])),
				  extensions)
	      )) {
		KLIPS_PRINT(1 | debug_pfkey, "klips_debug:pfkey_acquire: "
			    "failed to build the acquire message extensions\n");
		SENDERR(-error);
	}

	if ((error = pfkey_msg_build(&pfkey_msg, extensions, EXT_BITS_OUT))) {
		KLIPS_PRINT(1 | debug_pfkey, "klips_debug:pfkey_acquire: "
			    "failed to build the acquire message\n");
		SENDERR(-error);
	}

#ifdef KLIPS_PFKEY_ACQUIRE_LOSSAGE
#  if KLIPS_PFKEY_ACQUIRE_LOSSAGE > 0
	if (sysctl_ipsec_regress_pfkey_lossage)
		return 0;

#  endif
#endif

	/* this should go to all registered sockets for that satype only */
	for (pfkey_socketsp = pfkey_registered_sockets[satype];
	     pfkey_socketsp;
	     pfkey_socketsp = pfkey_socketsp->next) {
		if ((error = pfkey_upmsg(pfkey_socketsp->socketp,
					 pfkey_msg))) {
			KLIPS_PRINT(1 | debug_pfkey, "klips_debug:pfkey_acquire: "
				    "sending up acquire message for satype=%d(%s) to socket=0p%p failed with error=%d.\n",
				    satype,
				    satype2name(satype),
				    pfkey_socketsp->socketp,
				    error);
			SENDERR(-error);
		}
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_acquire: "
			    "sending up acquire message for satype=%d(%s) to socket=0p%p succeeded.\n",
			    satype,
			    satype2name(satype),
			    pfkey_socketsp->socketp);
	}

errlab:
	if (pfkey_msg)
		pfkey_msg_free(&pfkey_msg);
	pfkey_extensions_free(extensions);
	return error;
}

int pfkey_nat_t_new_mapping(struct ipsec_sa *ipsp, struct sockaddr *ipaddr,
			    __u16 sport)
{
	struct sadb_ext *extensions[K_SADB_EXT_MAX + 1];
	struct sadb_msg *pfkey_msg = NULL;
	struct socket_list *pfkey_socketsp;
	int error = 0;
	uint8_t satype =
		(ipsp->ips_said.proto == IPPROTO_ESP) ? K_SADB_SATYPE_ESP : 0;

	/* Construct K_SADB_X_NAT_T_NEW_MAPPING message */

	pfkey_extensions_init(extensions);

	if ((satype == 0) || (satype > K_SADB_SATYPE_MAX)) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_nat_t_new_mapping: "
			    "SAtype=%d unspecified or unknown.\n",
			    satype);
		SENDERR(EINVAL);
	}

	if (!(pfkey_registered_sockets[satype])) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_nat_t_new_mapping: "
			    "no sockets registered for SAtype=%d(%s).\n",
			    satype,
			    satype2name(satype));
		SENDERR(EPROTONOSUPPORT);
	}

	if (!(pfkey_safe_build
		      (error = pfkey_msg_hdr_build(&extensions[0],
						  K_SADB_X_NAT_T_NEW_MAPPING,
						  satype, 0, ++pfkey_msg_seq,
						  0), extensions)
	      /* SA */
	      && pfkey_safe_build
		      (error = pfkey_sa_build(&extensions[K_SADB_EXT_SA],
					      K_SADB_EXT_SA,
					      ipsp->ips_said.spi, 0, 0, 0, 0,
					      0), extensions)
	      /* ADDRESS_SRC = old addr */
	      && pfkey_safe_build
		      (error = pfkey_address_build(&extensions[
							  K_SADB_EXT_ADDRESS_SRC
						  ],
						  K_SADB_EXT_ADDRESS_SRC,
						  ipsp->ips_said.proto, 0,
						  ipsp->ips_addr_s),
		      extensions)
	      /* NAT_T_SPORT = old port */
	      && pfkey_safe_build
		      (error = pfkey_x_nat_t_port_build(&extensions[
							       K_SADB_X_EXT_NAT_T_SPORT
						       ],
						       K_SADB_X_EXT_NAT_T_SPORT,
						       ipsp->ips_natt_sport),
		      extensions)
	      /* ADDRESS_DST = new addr */
	      && pfkey_safe_build
		      (error = pfkey_address_build(&extensions[
							  K_SADB_EXT_ADDRESS_DST
						  ],
						  K_SADB_EXT_ADDRESS_DST,
						  ipsp->ips_said.proto, 0,
						  ipaddr), extensions)
	      /* NAT_T_DPORT = new port */
	      && pfkey_safe_build
		      (error = pfkey_x_nat_t_port_build(&extensions[
							       K_SADB_X_EXT_NAT_T_DPORT
						       ],
						       K_SADB_X_EXT_NAT_T_DPORT,
						       sport), extensions)
	      )) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_nat_t_new_mapping: "
			    "failed to build the nat_t_new_mapping message extensions\n");
		SENDERR(-error);
	}

	if ((error = pfkey_msg_build(&pfkey_msg, extensions, EXT_BITS_OUT))) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_nat_t_new_mapping: "
			    "failed to build the nat_t_new_mapping message\n");
		SENDERR(-error);
	}

	/* this should go to all registered sockets for that satype only */
	for (pfkey_socketsp = pfkey_registered_sockets[satype];
	     pfkey_socketsp;
	     pfkey_socketsp = pfkey_socketsp->next) {
		if ((error = pfkey_upmsg(pfkey_socketsp->socketp,
					 pfkey_msg))) {
			KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_nat_t_new_mapping: "
				    "sending up nat_t_new_mapping message for satype=%d(%s) to socket=%p failed with error=%d.\n",
				    satype,
				    satype2name(satype),
				    pfkey_socketsp->socketp,
				    error);
			SENDERR(-error);
		}
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_nat_t_new_mapping: "
			    "sending up nat_t_new_mapping message for satype=%d(%s) to socket=%p succeeded.\n",
			    satype,
			    satype2name(satype),
			    pfkey_socketsp->socketp);
	}

errlab:
	if (pfkey_msg)
		pfkey_msg_free(&pfkey_msg);
	pfkey_extensions_free(extensions);
	return error;
}

DEBUG_NO_STATIC int pfkey_x_nat_t_new_mapping_parse(struct sock *sk,
						    struct sadb_ext **extensions,
						    struct pfkey_extracted_data *extr)
{
	/* K_SADB_X_NAT_T_NEW_MAPPING not used in kernel */
	return -EINVAL;
}

/*******************************
 * EXTENSION PARSERS FOR KLIPS
 ********************************/

DEBUG_NO_STATIC int pfkey_x_outif_process(struct sadb_ext *pfkey_ext,
					  struct pfkey_extracted_data *extr)
{
	struct sadb_x_plumbif *oif;

	oif = (struct sadb_x_plumbif *)pfkey_ext;

	extr->outif = oif->sadb_x_outif_ifnum;

	return 0;
}

DEBUG_NO_STATIC int pfkey_x_saref_process(struct sadb_ext *pfkey_ext,
					  struct pfkey_extracted_data *extr)
{
	struct sadb_x_saref *saf;

	saf = (struct sadb_x_saref *)pfkey_ext;

	extr->sarefme  = saf->sadb_x_saref_me;
	extr->sarefhim = saf->sadb_x_saref_him;

	return 0;
}

/* ext_processors: array of pointer to functions
 *
 * eg.: int ext_processor_function(struct sadb_ext *pfkey_ext, struct pfkey_extracted_data *extr)
 *	returns 0 on success.
 */
DEBUG_NO_STATIC int(*ext_processors[K_SADB_EXT_MAX + 1]) (
	struct sadb_ext *pfkey_ext,
	struct pfkey_extracted_data *extr) =
{
	NULL, /* pfkey_msg_process, */
	pfkey_sa_process,
	pfkey_lifetime_process,
	pfkey_lifetime_process,
	pfkey_lifetime_process,
	pfkey_address_process,
	pfkey_address_process,
	pfkey_address_process,
	pfkey_key_process,
	pfkey_key_process,
	pfkey_ident_process,
	pfkey_ident_process,
	pfkey_sens_process,
	pfkey_prop_process,
	pfkey_supported_process,
	pfkey_supported_process,
	pfkey_spirange_process,
	pfkey_x_kmprivate_process,
	pfkey_x_satype_process,
	pfkey_sa_process,
	pfkey_address_process,
	pfkey_address_process,
	pfkey_address_process,
	pfkey_address_process,
	pfkey_address_process,
	pfkey_x_debug_process,
	pfkey_x_protocol_process,
	pfkey_x_nat_t_type_process,
	pfkey_x_nat_t_port_process,
	pfkey_x_nat_t_port_process,
	pfkey_address_process,
	pfkey_x_outif_process,
	pfkey_x_saref_process,
};

/*******************************
 * MESSAGE PARSERS FOR KLIPS
 ********************************/

DEBUG_NO_STATIC int pfkey_x_simple_reply(struct sock *sk,
					 struct sadb_ext *extensions[],
					 int err)
{
	struct sadb_msg *pfkey_reply = NULL;
	int error = 0;
	struct sadb_msg *m =
		((struct sadb_msg*)extensions[K_SADB_EXT_RESERVED]);

	/* err is either 0 (success) or a negative 'errno' value */
	if (err <= 0 && err >= -255)
		m->sadb_msg_errno = -err;
	else
		/* out of range for a uint8_t */
		m->sadb_msg_errno = 255;

	if ((error = pfkey_msg_build(&pfkey_reply, extensions,
				     EXT_BITS_OUT))) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_expire: "
			    "failed to build the expire message\n");
		SENDERR(-error);
	}

	error = pfkey_upmsgsk(sk, pfkey_reply);

	if (error) {
		KLIPS_ERROR(debug_pfkey, "pfkey_simple reply:"
			    "sending up simple reply to pid=%d error=%d.\n",
			    m->sadb_msg_pid, err);
	}

errlab:
	if (pfkey_reply)
		pfkey_msg_free(&pfkey_reply);

	return error;
}

/*
 * this is a request to create a new device. Figure out which kind, and call appropriate
 * routine in mast or tunnel code.
 */
DEBUG_NO_STATIC int pfkey_x_plumb_parse(struct sock *sk,
					struct sadb_ext *extensions[],
					struct pfkey_extracted_data *extr)
{
	unsigned int vifnum;
	int err;

	vifnum = extr->outif;
	if (vifnum > IPSECDEV_OFFSET)
		err = ipsec_tunnel_createnum(vifnum - IPSECDEV_OFFSET);
	else
		err = ipsec_mast_createnum(vifnum);

	return pfkey_x_simple_reply(sk, extensions, err);
}

DEBUG_NO_STATIC int pfkey_x_unplumb_parse(struct sock *sk,
					  struct sadb_ext *extensions[],
					  struct pfkey_extracted_data *extr)
{
	unsigned int vifnum;
	int err;

	vifnum = extr->outif;
	if (vifnum > IPSECDEV_OFFSET)
		err =  ipsec_tunnel_deletenum(vifnum - IPSECDEV_OFFSET);
	else
		err = ipsec_mast_deletenum(vifnum);

	return pfkey_x_simple_reply(sk, extensions, err);
}

/* msg_parsers: array of pointers to functions */
DEBUG_NO_STATIC int(*msg_parsers[K_SADB_MAX + 1]) (
	struct sock *sk,
	struct sadb_ext *extensions[],
	struct pfkey_extracted_data *extr)
	=
{
	NULL, /* RESERVED */
	pfkey_getspi_parse,
	pfkey_update_parse,
	pfkey_add_parse,
	pfkey_delete_parse,
	pfkey_get_parse,
	pfkey_acquire_parse,
	pfkey_register_parse,
	pfkey_expire_parse,
	pfkey_flush_parse,
	pfkey_dump_parse,
	pfkey_x_promisc_parse,
	pfkey_x_pchange_parse,
	pfkey_x_grpsa_parse,
	pfkey_x_addflow_parse,
	pfkey_x_delflow_parse,
	pfkey_x_msg_debug_parse,
	pfkey_x_nat_t_new_mapping_parse,
	pfkey_x_plumb_parse,
	pfkey_x_unplumb_parse,
};

int pfkey_build_reply(struct sadb_msg *pfkey_msg,
		      struct pfkey_extracted_data *extr,
		      struct sadb_msg **pfkey_reply)
{
	struct sadb_ext *extensions[K_SADB_EXT_MAX + 1];
	int error = 0;
	int msg_type = pfkey_msg->sadb_msg_type;
	int seq = pfkey_msg->sadb_msg_seq;

	KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_build_reply: "
		    "building reply with type: %d\n",
		    msg_type);
	pfkey_extensions_init(extensions);
	if (!extr || !extr->ips) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_build_reply: "
			    "bad ipsec_sa passed\n");
		return EINVAL;         /* TODO: should this not be negative? */
	}
	error = pfkey_safe_build(pfkey_msg_hdr_build(&extensions[0],
						     msg_type,
						     proto2satype(extr->ips->
								  ips_said.
								  proto),
						     0,
						     seq,
						     pfkey_msg->sadb_msg_pid),
				 extensions);

	if (!error &&
	    pfkey_required_extension(EXT_BITS_OUT, msg_type, K_SADB_EXT_SA)) {

		error = pfkey_sa_build(&extensions[K_SADB_EXT_SA],
				       K_SADB_EXT_SA,
				       extr->ips->ips_said.spi,
				       extr->ips->ips_replaywin,
				       extr->ips->ips_state,
				       extr->ips->ips_authalg,
				       extr->ips->ips_encalg,
				       extr->ips->ips_flags);
		pfkey_safe_build(error, extensions);
	}

	if (!error &&
	    pfkey_required_extension(EXT_BITS_OUT, msg_type,
				     K_SADB_X_EXT_SAREF)) {
		error = pfkey_saref_build(&extensions[K_SADB_X_EXT_SAREF],
					  extr->ips->ips_ref,
					  extr->ips->ips_refhim);
		pfkey_safe_build(error, extensions);
	}

	if (!error &&
	    pfkey_required_extension(EXT_BITS_OUT, msg_type,
				     K_SADB_EXT_LIFETIME_CURRENT)) {
		error = pfkey_lifetime_build(&extensions
					     [K_SADB_EXT_LIFETIME_CURRENT],
					     K_SADB_EXT_LIFETIME_CURRENT,
					     extr->ips->ips_life.ipl_allocations.ipl_count,
					     extr->ips->ips_life.ipl_bytes.ipl_count,
					     extr->ips->ips_life.ipl_addtime.ipl_count,
					     extr->ips->ips_life.ipl_usetime.ipl_count,
					     extr->ips->ips_life.ipl_packets.ipl_count);
		pfkey_safe_build(error, extensions);
	}

	if (!error &&
	    pfkey_required_extension(EXT_BITS_OUT, msg_type,
				     K_SADB_EXT_ADDRESS_SRC)) {
		error = pfkey_address_build(
			&extensions[K_SADB_EXT_ADDRESS_SRC],
			K_SADB_EXT_ADDRESS_SRC,
			extr->ips->ips_said.proto,
			0,
			extr->ips->ips_addr_s);
		pfkey_safe_build(error, extensions);
	}

	if (!error &&
	    pfkey_required_extension(EXT_BITS_OUT, msg_type,
				     K_SADB_EXT_ADDRESS_DST)) {
		error = pfkey_address_build(
			&extensions[K_SADB_EXT_ADDRESS_DST],
			K_SADB_EXT_ADDRESS_DST,
			extr->ips->ips_said.proto,
			0,
			extr->ips->ips_addr_d);
		pfkey_safe_build(error, extensions);
	}

	if (error == 0) {
		KLIPS_PRINT(debug_pfkey, "klips_debug:pfkey_build_reply: "
			    "building extensions failed\n");
		return EINVAL;
	}

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_build_reply: "
		    "built extensions, proceed to build the message\n");
	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_build_reply: "
		    "extensions[1]=0p%p\n",
		    extensions[1]);
	error = pfkey_msg_build(pfkey_reply, extensions, EXT_BITS_OUT);
	pfkey_extensions_free(extensions);

	return error;
}

/*
 * interpret a pfkey message for klips usage.
 * it used to be that we provided a reply in a seperate buffer,
 * but now we overwrite the request buffer and return it.
 */
int pfkey_msg_interp(struct sock *sk, struct sadb_msg *pfkey_msg)
{
	int error = 0;
	int i;
	struct sadb_ext *extensions[K_SADB_EXT_MAX + 1];    /* should be kalloc */
	struct pfkey_extracted_data extr;

	memset(&extr, 0, sizeof(extr));

	pfkey_extensions_init(extensions);
	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_msg_interp: "
		    "parsing message ver=%d, type=%d, errno=%d, satype=%d(%s), len=%d, res=%d, seq=%d, pid=%d.\n",
		    pfkey_msg->sadb_msg_version,
		    pfkey_msg->sadb_msg_type,
		    pfkey_msg->sadb_msg_errno,
		    pfkey_msg->sadb_msg_satype,
		    satype2name(pfkey_msg->sadb_msg_satype),
		    pfkey_msg->sadb_msg_len,
		    pfkey_msg->sadb_msg_reserved,
		    pfkey_msg->sadb_msg_seq,
		    pfkey_msg->sadb_msg_pid);

	extr.ips = ipsec_sa_alloc(&error); /* pass in error var by pointer */
	if (extr.ips == NULL) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_msg_interp: "
			    "memory allocation error.\n");
		SENDERR(-error);
	}

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_msg_interp: "
		    "allocated extr->ips=0p%p.\n",
		    extr.ips);

	if (pfkey_msg->sadb_msg_satype > K_SADB_SATYPE_MAX) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_msg_interp: "
			    "satype %d > max %d\n",
			    pfkey_msg->sadb_msg_satype,
			    K_SADB_SATYPE_MAX);
		SENDERR(EINVAL);
	}

	switch (pfkey_msg->sadb_msg_type) {
	case K_SADB_GETSPI:
	case K_SADB_UPDATE:
	case K_SADB_ADD:
	case K_SADB_DELETE:
	case K_SADB_X_GRPSA:
	case K_SADB_X_ADDFLOW:
		if (!(extr.ips->ips_said.proto =
			      satype2proto(pfkey_msg->sadb_msg_satype))) {
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_msg_interp: "
				    "satype %d lookup failed.\n",
				    pfkey_msg->sadb_msg_satype);
			SENDERR(EINVAL);
		} else {
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_msg_interp: "
				    "satype %d lookups to proto=%d.\n",
				    pfkey_msg->sadb_msg_satype,
				    extr.ips->ips_said.proto);
		}
		break;
	default:
		break;
	}

	/* The NULL below causes the default extension parsers to be used */
	/* Parse the extensions */
	if ((error = pfkey_msg_parse(pfkey_msg, NULL, extensions,
				     EXT_BITS_IN))) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_msg_interp: "
			    "message parsing failed with error %d.\n",
			    error);
		SENDERR(-error);
	}

	/* Process the extensions */
	for (i = 1; i <= K_SADB_EXT_MAX; i++) {
		if (extensions[i] != NULL && ext_processors[i] != NULL) {
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_msg_interp: "
				    "processing ext %d 0p%p with processor 0p%p.\n",
				    i, extensions[i], ext_processors[i]);
			if ((error = ext_processors[i](extensions[i],
						       &extr))) {
				KLIPS_PRINT(debug_pfkey,
					    "klips_debug:pfkey_msg_interp: "
					    "extension processing for type %d failed with error %d.\n",
					    i,
					    error);
				SENDERR(-error);
			}
		}
	}

	/* Parse the message types */
	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_msg_interp: "
		    "parsing message type %d(%s) with msg_parser 0p%p.\n",
		    pfkey_msg->sadb_msg_type,
		    pfkey_v2_sadb_type_string(pfkey_msg->sadb_msg_type),
		    msg_parsers[pfkey_msg->sadb_msg_type]);
	if ((error = msg_parsers[pfkey_msg->sadb_msg_type](sk, extensions,
							   &extr))) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_msg_interp: "
			    "message parsing failed with error %d.\n",
			    error);
		SENDERR(-error);
	}

errlab:
	if (extr.ips != NULL)
		ipsec_sa_put(extr.ips, IPSEC_REFALLOC);
	if (extr.ips2 != NULL)
		ipsec_sa_put(extr.ips2, IPSEC_REFALLOC);
	if (extr.eroute != NULL)
		kfree(extr.eroute);
	return error;
}
