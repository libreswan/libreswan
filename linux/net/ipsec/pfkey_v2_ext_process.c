/*
 * @(#) RFC2367 PF_KEYv2 Key management API message parser
 * Copyright (C) 1998-2003   Richard Guy Briggs.
 * Copyright (C) 2004-2006   Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012  Paul Wouters  <paul@libreswan.org>
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

#include <libreswan.h>

#include <klips-crypto/des.h>

#include <linux/spinlock.h> /* *lock* */
# include <linux/in6.h>
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
#include "libreswan/ipsec_rcv.h"
#include "libreswan/ipcomp.h"

#include <libreswan/pfkeyv2.h>
#include <libreswan/pfkey.h>

#include "libreswan/ipsec_proto.h"
#include "libreswan/ipsec_alg.h"

#ifdef CONFIG_KLIPS_OCF
#include "ipsec_ocf.h"
#endif

#define SENDERR(_x) do { error = -(_x); goto errlab; } while (0)

/* returns 0 on success */
int pfkey_sa_process(struct sadb_ext *pfkey_ext,
		     struct pfkey_extracted_data *extr)
{
	struct k_sadb_sa *k_pfkey_sa = (struct k_sadb_sa *)pfkey_ext;
	struct sadb_sa *pfkey_sa = (struct sadb_sa *)pfkey_ext;
	int error = 0;
	struct ipsec_sa *ipsp;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_sa_process: .\n");

	if (!extr || !extr->ips) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_sa_process: "
			    "extr or extr->ips is NULL, fatal\n");
		SENDERR(EINVAL);
	}

	switch (pfkey_ext->sadb_ext_type) {
	case K_SADB_EXT_SA:
		ipsp = extr->ips;
		break;
	case K_SADB_X_EXT_SA2:
		if (extr->ips2 == NULL)
			extr->ips2 = ipsec_sa_alloc(&error); /* pass error var by pointer */
		if (extr->ips2 == NULL)
			SENDERR(-error);
		ipsp = extr->ips2;
		break;
	default:
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_sa_process: "
			    "invalid exttype=%d.\n",
			    pfkey_ext->sadb_ext_type);
		SENDERR(EINVAL);
	}

	ipsp->ips_said.spi = pfkey_sa->sadb_sa_spi;
	ipsp->ips_replaywin = pfkey_sa->sadb_sa_replay;
	ipsp->ips_state = pfkey_sa->sadb_sa_state;
	ipsp->ips_flags = pfkey_sa->sadb_sa_flags;
	ipsp->ips_replaywin_lastseq = ipsp->ips_replaywin_bitmap = 0;

	if (k_pfkey_sa->sadb_sa_len > sizeof(struct sadb_sa) /
	    IPSEC_PFKEYv2_ALIGN)
		ipsp->ips_ref = k_pfkey_sa->sadb_x_sa_ref;

	switch (ipsp->ips_said.proto) {
	case IPPROTO_AH:
		ipsp->ips_authalg = pfkey_sa->sadb_sa_auth;
		ipsp->ips_encalg = K_SADB_EALG_NONE;
#ifdef CONFIG_KLIPS_OCF
		if (ipsec_ocf_sa_init(ipsp, ipsp->ips_authalg, 0))
			break;
#endif
		break;
	case IPPROTO_ESP:
		ipsp->ips_authalg = pfkey_sa->sadb_sa_auth;
		ipsp->ips_encalg = pfkey_sa->sadb_sa_encrypt;
#ifdef CONFIG_KLIPS_OCF
		if (ipsec_ocf_sa_init(ipsp, ipsp->ips_authalg,
				      ipsp->ips_encalg))
			break;
#endif
		break;
	case IPPROTO_IPIP:
		ipsp->ips_authalg = AH_NONE;
		ipsp->ips_encalg = ESP_NONE;
		break;
#ifdef CONFIG_KLIPS_IPCOMP
	case IPPROTO_COMP:
		ipsp->ips_authalg = AH_NONE;
		ipsp->ips_encalg = pfkey_sa->sadb_sa_encrypt;
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_sa_process: "
			    "IPPROTO_COMP ips_encalg=%d.\n",
			    ipsp->ips_encalg);
		break;
#endif          /* CONFIG_KLIPS_IPCOMP */
	case IPPROTO_INT:
		ipsp->ips_authalg = AH_NONE;
		ipsp->ips_encalg = ESP_NONE;
		break;
	case 0:
		break;
	default:
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_sa_process: "
			    "unknown proto=%d.\n",
			    ipsp->ips_said.proto);
		SENDERR(EINVAL);
	}

errlab:
	return error;
}

int pfkey_lifetime_process(struct sadb_ext *pfkey_ext,
			   struct pfkey_extracted_data *extr)
{
	int error = 0;
	struct sadb_lifetime *pfkey_lifetime =
		(struct sadb_lifetime *)pfkey_ext;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_lifetime_process: .\n");

	if (!extr || !extr->ips) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_lifetime_process: "
			    "extr or extr->ips is NULL, fatal\n");
		SENDERR(EINVAL);
	}

	switch (pfkey_lifetime->sadb_lifetime_exttype) {
	case K_SADB_EXT_LIFETIME_CURRENT:
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_lifetime_process: "
			    "lifetime_current not supported yet.\n");
		SENDERR(EINVAL);
		break;
	case K_SADB_EXT_LIFETIME_HARD:
		ipsec_lifetime_update_hard(
			&extr->ips->ips_life.ipl_allocations,
			pfkey_lifetime->sadb_lifetime_allocations);

		ipsec_lifetime_update_hard(&extr->ips->ips_life.ipl_bytes,
					   pfkey_lifetime->sadb_lifetime_bytes);

		ipsec_lifetime_update_hard(&extr->ips->ips_life.ipl_addtime,
					   pfkey_lifetime->sadb_lifetime_addtime);

		ipsec_lifetime_update_hard(&extr->ips->ips_life.ipl_usetime,
					   pfkey_lifetime->sadb_lifetime_usetime);

		break;

	case K_SADB_EXT_LIFETIME_SOFT:
		ipsec_lifetime_update_soft(
			&extr->ips->ips_life.ipl_allocations,
			pfkey_lifetime->sadb_lifetime_allocations);

		ipsec_lifetime_update_soft(&extr->ips->ips_life.ipl_bytes,
					   pfkey_lifetime->sadb_lifetime_bytes);

		ipsec_lifetime_update_soft(&extr->ips->ips_life.ipl_addtime,
					   pfkey_lifetime->sadb_lifetime_addtime);

		ipsec_lifetime_update_soft(&extr->ips->ips_life.ipl_usetime,
					   pfkey_lifetime->sadb_lifetime_usetime);

		break;
	default:
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_lifetime_process: "
			    "invalid exttype=%d.\n",
			    pfkey_ext->sadb_ext_type);
		SENDERR(EINVAL);
	}

errlab:
	return error;
}

int pfkey_address_process(struct sadb_ext *pfkey_ext,
			  struct pfkey_extracted_data *extr)
{
	int error = 0;
	int saddr_len = 0;
	char ipaddr_txt[ADDRTOA_BUF];
	unsigned char **sap;
	unsigned short * portp = 0;
	struct sadb_address *pfkey_address = (struct sadb_address *)pfkey_ext;
	struct sockaddr *s = (struct sockaddr*)
		((char*)pfkey_address + sizeof(*pfkey_address));
	struct ipsec_sa *ipsp;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_address_process:\n");

	if (!extr || !extr->ips) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_address_process: "
			    "extr or extr->ips is NULL, fatal\n");
		SENDERR(EINVAL);
	}

	switch (s->sa_family) {
	case AF_INET:
		saddr_len = sizeof(struct sockaddr_in);
		if (debug_pfkey)
			sin_addrtot(s, 0, ipaddr_txt, sizeof(ipaddr_txt));
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_address_process: "
			    "found address family=%d, AF_INET, %s.\n",
			    s->sa_family,
			    ipaddr_txt);
		break;
#if defined(CONFIG_KLIPS_IPV6)
	case AF_INET6:
		saddr_len = sizeof(struct sockaddr_in6);
		if (debug_pfkey)
			sin_addrtot(s, 0, ipaddr_txt, sizeof(ipaddr_txt));
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_address_process: "
			    "found address family=%d, AF_INET6, %s.\n",
			    s->sa_family,
			    ipaddr_txt);
		break;
#endif          /* defined(CONFIG_KLIPS_IPV6) */
	default:
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_address_process: "
			    "s->sa_family=%d not supported.\n",
			    s->sa_family);
		SENDERR(EPFNOSUPPORT);
	}

	switch (pfkey_address->sadb_address_exttype) {
	case K_SADB_EXT_ADDRESS_SRC:
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_address_process: "
			    "found src address.\n");
		sap = (unsigned char **)&(extr->ips->ips_addr_s);
		extr->ips->ips_addr_s_size = saddr_len;
		break;
	case K_SADB_EXT_ADDRESS_DST:
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_address_process: "
			    "found dst address.\n");
		sap = (unsigned char **)&(extr->ips->ips_addr_d);
		extr->ips->ips_addr_d_size = saddr_len;
		break;
	case K_SADB_EXT_ADDRESS_PROXY:
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_address_process: "
			    "found proxy address.\n");
		sap = (unsigned char **)&(extr->ips->ips_addr_p);
		extr->ips->ips_addr_p_size = saddr_len;
		break;
	case K_SADB_X_EXT_ADDRESS_DST2:
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_address_process: "
			    "found 2nd dst address.\n");
		if (extr->ips2 == NULL)
			extr->ips2 = ipsec_sa_alloc(&error); /* pass error var by pointer */
		if (extr->ips2 == NULL)
			SENDERR(-error);
		sap = (unsigned char **)&(extr->ips2->ips_addr_d);
		extr->ips2->ips_addr_d_size = saddr_len;
		break;
	case K_SADB_X_EXT_ADDRESS_SRC_FLOW:
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_address_process: "
			    "found src flow address.\n");
		if (pfkey_alloc_eroute(&(extr->eroute)) == ENOMEM)
			SENDERR(ENOMEM);
		if (s->sa_family == AF_INET6) {
			sap = (unsigned char **)
				&(extr->eroute->er_eaddr.sen_ip6_src);
			portp = &(extr->eroute->er_eaddr.sen_sport6);
			extr->eroute->er_eaddr.sen_type = SENT_IP6;
		} else {
			sap = (unsigned char **)
				&(extr->eroute->er_eaddr.sen_ip_src);
			portp = &(extr->eroute->er_eaddr.sen_sport);
			extr->eroute->er_eaddr.sen_type = SENT_IP4;
		}
		break;
	case K_SADB_X_EXT_ADDRESS_DST_FLOW:
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_address_process: "
			    "found dst flow address.\n");
		if (pfkey_alloc_eroute(&(extr->eroute)) == ENOMEM)
			SENDERR(ENOMEM);
		if (s->sa_family == AF_INET6) {
			sap = (unsigned char **)
				&(extr->eroute->er_eaddr.sen_ip6_dst);
			portp = &(extr->eroute->er_eaddr.sen_dport6);
			extr->eroute->er_eaddr.sen_type = SENT_IP6;
		} else {
			sap = (unsigned char **)
				&(extr->eroute->er_eaddr.sen_ip_dst);
			portp = &(extr->eroute->er_eaddr.sen_dport);
			extr->eroute->er_eaddr.sen_type = SENT_IP4;
		}
		break;
	case K_SADB_X_EXT_ADDRESS_SRC_MASK:
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_address_process: "
			    "found src mask address.\n");
		if (pfkey_alloc_eroute(&(extr->eroute)) == ENOMEM)
			SENDERR(ENOMEM);
		if (s->sa_family == AF_INET6) {
			sap = (unsigned char **)
				&(extr->eroute->er_emask.sen_ip6_src);
			portp = &(extr->eroute->er_emask.sen_sport6);
			extr->eroute->er_eaddr.sen_type = SENT_IP6;
		} else {
			sap = (unsigned char **)
				&(extr->eroute->er_emask.sen_ip_src);
			portp = &(extr->eroute->er_emask.sen_sport);
			extr->eroute->er_eaddr.sen_type = SENT_IP4;
		}
		break;
	case K_SADB_X_EXT_ADDRESS_DST_MASK:
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_address_process: "
			    "found dst mask address.\n");
		if (pfkey_alloc_eroute(&(extr->eroute)) == ENOMEM)
			SENDERR(ENOMEM);
		if (s->sa_family == AF_INET6) {
			sap = (unsigned char **)
				&(extr->eroute->er_emask.sen_ip6_dst);
			portp = &(extr->eroute->er_emask.sen_dport6);
			extr->eroute->er_eaddr.sen_type = SENT_IP6;
		} else {
			sap = (unsigned char **)
				&(extr->eroute->er_emask.sen_ip_dst);
			portp = &(extr->eroute->er_emask.sen_dport);
			extr->eroute->er_eaddr.sen_type = SENT_IP4;
		}
		break;
	case K_SADB_X_EXT_NAT_T_OA:
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_address_process: "
			    "found NAT-OA address.\n");
		sap = (unsigned char **)&(extr->ips->ips_natt_oa);
		extr->ips->ips_natt_oa_size = saddr_len;
		break;
	default:
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_address_process: "
			    "unrecognised ext_type=%d.\n",
			    pfkey_address->sadb_address_exttype);
		SENDERR(EINVAL);
	}

	switch (pfkey_address->sadb_address_exttype) {
	case K_SADB_EXT_ADDRESS_SRC:
	case K_SADB_EXT_ADDRESS_DST:
	case K_SADB_EXT_ADDRESS_PROXY:
	case K_SADB_X_EXT_ADDRESS_DST2:
#if 0
	case K_SADB_X_EXT_ADDRESS_SRC_FLOW:
	case K_SADB_X_EXT_ADDRESS_DST_FLOW:
	case K_SADB_X_EXT_ADDRESS_SRC_MASK:
	case K_SADB_X_EXT_ADDRESS_DST_MASK:
#endif
	case K_SADB_X_EXT_NAT_T_OA:
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_address_process: "
			    "allocating %d bytes for saddr.\n",
			    saddr_len);
		if (!(*sap = kmalloc(saddr_len, GFP_KERNEL)))
			SENDERR(ENOMEM);
		memcpy(*sap, s, saddr_len);
		break;
	default:
		if (s->sa_family != AF_INET && s->sa_family != AF_INET6) {
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_address_process: "
				    "s->sa_family=%d "
				    "sadb_address_exttype=%d "
				    "not supported.\n",
				    s->sa_family,
				    pfkey_address->sadb_address_exttype);
			SENDERR(EPFNOSUPPORT);
		}
		if (s->sa_family == AF_INET6) {
			*(struct in6_addr *)sap =
				((struct sockaddr_in6 *)s)->sin6_addr;
			if (portp != 0)
				*portp = ((struct sockaddr_in6*)s)->sin6_port;
		} else {
			*(struct in_addr *)sap =
				((struct sockaddr_in *)s)->sin_addr;
			if (portp != 0)
				*portp = ((struct sockaddr_in*)s)->sin_port;
		}

		if (extr->eroute) {
			if (debug_pfkey) {
				char buf1[64], buf2[64];
				unsigned short sp, dp;

				if (extr->eroute->er_eaddr.sen_type ==
				    SENT_IP6) {
					subnet6toa(
						&extr->eroute->er_eaddr.sen_ip6_src,
						&extr->eroute->er_emask.sen_ip6_src, 0, buf1,
						sizeof(buf1));
					subnet6toa(
						&extr->eroute->er_eaddr.sen_ip6_dst,
						&extr->eroute->er_emask.sen_ip6_dst, 0, buf2,
						sizeof(buf2));
					sp = extr->eroute->er_eaddr.sen_sport6;
					dp = extr->eroute->er_eaddr.sen_dport6;
				} else {
					subnettoa(
						extr->eroute->er_eaddr.sen_ip_src,
						extr->eroute->er_emask.sen_ip_src, 0, buf1,
						sizeof(buf1));
					subnettoa(
						extr->eroute->er_eaddr.sen_ip_dst,
						extr->eroute->er_emask.sen_ip_dst, 0, buf2,
						sizeof(buf2));
					sp = extr->eroute->er_eaddr.sen_sport;
					dp = extr->eroute->er_eaddr.sen_dport;
				}
				KLIPS_PRINT(debug_pfkey,
					    "klips_debug:pfkey_address_parse: "
					    "extr->eroute set to %s:%d->%s:%d\n",
					    buf1, ntohs(sp), buf2, ntohs(dp));
			}
		}
	}

	ipsp = extr->ips;
	switch (pfkey_address->sadb_address_exttype) {
	case K_SADB_X_EXT_ADDRESS_DST2:
		ipsp = extr->ips2;
	case K_SADB_EXT_ADDRESS_DST:
		if (s->sa_family == AF_INET) {
			ipsp->ips_said.dst.u.v4.sin_addr.s_addr =
				((struct sockaddr_in*)(ipsp->ips_addr_d))->
				sin_addr.s_addr;
			SET_V4(ipsp->ips_said.dst);
			if (debug_pfkey)
				sin_addrtot(ipsp->ips_addr_d, 0, ipaddr_txt,
					    sizeof(ipaddr_txt));
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_address_process: "
				    "ips_said.dst set to %s.\n",
				    ipaddr_txt);
		} else if (s->sa_family == AF_INET6) {
			ipsp->ips_said.dst.u.v6.sin6_addr =
				((struct sockaddr_in6 *)(ipsp->ips_addr_d))->
				sin6_addr;
			SET_V6(ipsp->ips_said.dst);
			if (debug_pfkey)
				sin_addrtot(ipsp->ips_addr_d, 0, ipaddr_txt,
					    sizeof(ipaddr_txt));
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_address_process: "
				    "ips_said.dst set to %s.\n",
				    ipaddr_txt);
		} else {
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_address_process: "
				    "uh, ips_said.dst doesn't do address family=%d yet, said will be invalid.\n",
				    s->sa_family);
		}
	default:
		break;
	}

	/* XXX check if port!=0 */

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_address_process: successful.\n");
errlab:
	return error;
}

int pfkey_key_process(struct sadb_ext *pfkey_ext,
		      struct pfkey_extracted_data *extr)
{
	int error = 0;
	struct sadb_key *pfkey_key = (struct sadb_key *)pfkey_ext;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_key_process: .\n");

	if (!extr || !extr->ips) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_key_process: "
			    "extr or extr->ips is NULL, fatal\n");
		SENDERR(EINVAL);
	}

	switch (pfkey_key->sadb_key_exttype) {
	case K_SADB_EXT_KEY_AUTH:
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_key_process: "
			    "allocating %d bytes for authkey.\n",
			    DIVUP(pfkey_key->sadb_key_bits, 8));
		if (!(extr->ips->ips_key_a =
			      kmalloc(DIVUP(pfkey_key->sadb_key_bits,
					    8), GFP_KERNEL))) {
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_key_process: "
				    "memory allocation error.\n");
			SENDERR(ENOMEM);
		}
		extr->ips->ips_key_bits_a = pfkey_key->sadb_key_bits;
		extr->ips->ips_key_a_size = DIVUP(pfkey_key->sadb_key_bits, 8);
		memcpy(extr->ips->ips_key_a,
		       (char*)pfkey_key + sizeof(struct sadb_key),
		       extr->ips->ips_key_a_size);
		break;
	case K_SADB_EXT_KEY_ENCRYPT: /* Key(s) */
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_key_process: "
			    "allocating %d bytes for enckey.\n",
			    DIVUP(pfkey_key->sadb_key_bits, 8));
		if (!(extr->ips->ips_key_e =
			      kmalloc(DIVUP(pfkey_key->sadb_key_bits,
					    8), GFP_KERNEL))) {
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_key_process: "
				    "memory allocation error.\n");
			SENDERR(ENOMEM);
		}
		extr->ips->ips_key_bits_e = pfkey_key->sadb_key_bits;
		extr->ips->ips_key_e_size = DIVUP(pfkey_key->sadb_key_bits, 8);
		memcpy(extr->ips->ips_key_e,
		       (char*)pfkey_key + sizeof(struct sadb_key),
		       extr->ips->ips_key_e_size);
		break;
	default:
		SENDERR(EINVAL);
	}

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_key_process: "
		    "success.\n");
errlab:
	return error;
}

int pfkey_ident_process(struct sadb_ext *pfkey_ext,
			struct pfkey_extracted_data *extr)
{
	int error = 0;
	struct sadb_ident *pfkey_ident = (struct sadb_ident *)pfkey_ext;
	int data_len;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_ident_process: .\n");

	if (!extr || !extr->ips) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_ident_process: "
			    "extr or extr->ips is NULL, fatal\n");
		SENDERR(EINVAL);
	}

	switch (pfkey_ident->sadb_ident_exttype) {
	case K_SADB_EXT_IDENTITY_SRC:
		data_len = pfkey_ident->sadb_ident_len * IPSEC_PFKEYv2_ALIGN -
			   sizeof(struct sadb_ident);

		extr->ips->ips_ident_s.type = pfkey_ident->sadb_ident_type;
		extr->ips->ips_ident_s.id = pfkey_ident->sadb_ident_id;
		extr->ips->ips_ident_s.len = pfkey_ident->sadb_ident_len;
		if (data_len) {
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_ident_process: "
				    "allocating %d bytes for ident_s.\n",
				    data_len);
			if (!(extr->ips->ips_ident_s.data =
				      kmalloc(data_len, GFP_KERNEL)))
				SENDERR(ENOMEM);
			memcpy(extr->ips->ips_ident_s.data,
			       (char*)pfkey_ident + sizeof(struct sadb_ident),
			       data_len);
		} else {
			extr->ips->ips_ident_s.data = NULL;
		}
		break;
	case K_SADB_EXT_IDENTITY_DST: /* Identity(ies) */
		data_len = pfkey_ident->sadb_ident_len * IPSEC_PFKEYv2_ALIGN -
			   sizeof(struct sadb_ident);

		extr->ips->ips_ident_d.type = pfkey_ident->sadb_ident_type;
		extr->ips->ips_ident_d.id = pfkey_ident->sadb_ident_id;
		extr->ips->ips_ident_d.len = pfkey_ident->sadb_ident_len;
		if (data_len) {
			KLIPS_PRINT(debug_pfkey,
				    "klips_debug:pfkey_ident_process: "
				    "allocating %d bytes for ident_d.\n",
				    data_len);
			if (!(extr->ips->ips_ident_d.data =
				      kmalloc(data_len, GFP_KERNEL)))
				SENDERR(ENOMEM);
			memcpy(extr->ips->ips_ident_d.data,
			       (char*)pfkey_ident + sizeof(struct sadb_ident),
			       data_len);
		} else {
			extr->ips->ips_ident_d.data = NULL;
		}
		break;
	default:
		SENDERR(EINVAL);
	}
errlab:
	return error;
}

int pfkey_sens_process(struct sadb_ext *pfkey_ext,
		       struct pfkey_extracted_data *extr)
{
	int error = 0;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_sens_process: "
		    "Sorry, I can't process exttype=%d yet.\n",
		    pfkey_ext->sadb_ext_type);
	SENDERR(EINVAL); /* don't process these yet */
errlab:
	return error;
}

int pfkey_prop_process(struct sadb_ext *pfkey_ext,
		       struct pfkey_extracted_data *extr)
{
	int error = 0;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_prop_process: "
		    "Sorry, I can't process exttype=%d yet.\n",
		    pfkey_ext->sadb_ext_type);
	SENDERR(EINVAL); /* don't process these yet */

errlab:
	return error;
}

int pfkey_supported_process(struct sadb_ext *pfkey_ext,
			    struct pfkey_extracted_data *extr)
{
	int error = 0;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_supported_process: "
		    "Sorry, I can't process exttype=%d yet.\n",
		    pfkey_ext->sadb_ext_type);
	SENDERR(EINVAL); /* don't process these yet */

errlab:
	return error;
}

int pfkey_spirange_process(struct sadb_ext *pfkey_ext,
			   struct pfkey_extracted_data *extr)
{
	int error = 0;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_spirange_process: .\n");
/* errlab: */
	return error;
}

int pfkey_x_kmprivate_process(struct sadb_ext *pfkey_ext,
			      struct pfkey_extracted_data *extr)
{
	int error = 0;

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_x_kmprivate_process: "
		    "Sorry, I can't process exttype=%d yet.\n",
		    pfkey_ext->sadb_ext_type);
	SENDERR(EINVAL); /* don't process these yet */

errlab:
	return error;
}

int pfkey_x_satype_process(struct sadb_ext *pfkey_ext,
			   struct pfkey_extracted_data *extr)
{
	int error = 0;
	struct sadb_x_satype *pfkey_x_satype =
		(struct sadb_x_satype *)pfkey_ext;

	KLIPS_PRINT(debug_pfkey,
		    "pfkey_x_satype_process: .\n");

	if (!extr || !extr->ips) {
		KLIPS_PRINT(debug_pfkey,
			    "pfkey_x_satype_process: "
			    "extr or extr->ips is NULL, fatal\n");
		SENDERR(EINVAL);
	}

	if (extr->ips2 == NULL)
		extr->ips2 = ipsec_sa_alloc(&error); /* pass error var by pointer */
	if (extr->ips2 == NULL)
		SENDERR(-error);
	if (!(extr->ips2->ips_said.proto =
		      satype2proto(pfkey_x_satype->sadb_x_satype_satype))) {
		KLIPS_ERROR(debug_pfkey,
			    "pfkey_x_satype_process: "
			    "proto lookup from satype=%d failed.\n",
			    pfkey_x_satype->sadb_x_satype_satype);
		SENDERR(EINVAL);
	}
	KLIPS_PRINT(debug_pfkey,
		    "pfkey_x_satype_process: "
		    "protocol==%d decoded from satype==%d(%s).\n",
		    extr->ips2->ips_said.proto,
		    pfkey_x_satype->sadb_x_satype_satype,
		    satype2name(pfkey_x_satype->sadb_x_satype_satype));

errlab:
	return error;
}

int pfkey_x_nat_t_type_process(struct sadb_ext *pfkey_ext,
			       struct pfkey_extracted_data *extr)
{
	int error = 0;
	struct sadb_x_nat_t_type *pfkey_x_nat_t_type =
		(struct sadb_x_nat_t_type *)pfkey_ext;

	if (!pfkey_x_nat_t_type) {
		printk("klips_debug:pfkey_x_nat_t_type_process: "
		       "null pointer passed in\n");
		SENDERR(EINVAL);
	}

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_x_nat_t_type_process: %d.\n",
		    pfkey_x_nat_t_type->sadb_x_nat_t_type_type);

	if (!extr || !extr->ips) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_nat_t_type_process: "
			    "extr or extr->ips is NULL, fatal\n");
		SENDERR(EINVAL);
	}

	switch (pfkey_x_nat_t_type->sadb_x_nat_t_type_type) {
	case ESPINUDP_WITH_NON_IKE:             /* with Non-IKE (older version) */
	case ESPINUDP_WITH_NON_ESP:             /* with Non-ESP */

		extr->ips->ips_natt_type =
			pfkey_x_nat_t_type->sadb_x_nat_t_type_type;
		break;
	default:
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_x_nat_t_type_process: "
			    "unknown type %d.\n",
			    pfkey_x_nat_t_type->sadb_x_nat_t_type_type);
		SENDERR(EINVAL);
		break;
	}

errlab:
	return error;
}

int pfkey_x_nat_t_port_process(struct sadb_ext *pfkey_ext,
			       struct pfkey_extracted_data *extr)
{
	int error = 0;
	struct sadb_x_nat_t_port *pfkey_x_nat_t_port =
		(struct sadb_x_nat_t_port *)pfkey_ext;

	if (!pfkey_x_nat_t_port) {
		printk("klips_debug:pfkey_x_nat_t_port_process: "
		       "null pointer passed in\n");
		SENDERR(EINVAL);
	}

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_x_nat_t_port_process: %d/%d.\n",
		    pfkey_x_nat_t_port->sadb_x_nat_t_port_exttype,
		    pfkey_x_nat_t_port->sadb_x_nat_t_port_port);

	if (!extr || !extr->ips) {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_nat_t_type_process: "
			    "extr or extr->ips is NULL, fatal\n");
		SENDERR(EINVAL);
	}

	switch (pfkey_x_nat_t_port->sadb_x_nat_t_port_exttype) {
	case K_SADB_X_EXT_NAT_T_SPORT:
		extr->ips->ips_natt_sport =
			pfkey_x_nat_t_port->sadb_x_nat_t_port_port;
		break;
	case K_SADB_X_EXT_NAT_T_DPORT:
		extr->ips->ips_natt_dport =
			pfkey_x_nat_t_port->sadb_x_nat_t_port_port;
		break;
	default:
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_x_nat_t_port_process: "
			    "unknown exttype %d.\n",
			    pfkey_x_nat_t_port->sadb_x_nat_t_port_exttype);
		SENDERR(EINVAL);
		break;
	}

errlab:
	return error;
}

int pfkey_x_debug_process(struct sadb_ext *pfkey_ext,
			  struct pfkey_extracted_data *extr)
{
	int error = 0;
	struct sadb_x_debug *pfkey_x_debug = (struct sadb_x_debug *)pfkey_ext;

	if (!pfkey_x_debug) {
		printk("klips_debug:pfkey_x_debug_process: "
		       "null pointer passed in\n");
		SENDERR(EINVAL);
	}

	KLIPS_PRINT(debug_pfkey,
		    "klips_debug:pfkey_x_debug_process: .\n");

	if (pfkey_x_debug->sadb_x_debug_netlink >>
	    (sizeof(pfkey_x_debug->sadb_x_debug_netlink) * 8 - 1)) {
		pfkey_x_debug->sadb_x_debug_netlink &=
			~(1 <<
			  (sizeof(pfkey_x_debug->sadb_x_debug_netlink) * 8 -
			   1));
		debug_tunnel  |= pfkey_x_debug->sadb_x_debug_tunnel;
		debug_netlink |= pfkey_x_debug->sadb_x_debug_netlink;
		debug_xform   |= pfkey_x_debug->sadb_x_debug_xform;
		debug_eroute  |= pfkey_x_debug->sadb_x_debug_eroute;
		debug_spi     |= pfkey_x_debug->sadb_x_debug_spi;
		debug_radij   |= pfkey_x_debug->sadb_x_debug_radij;
		debug_esp     |= pfkey_x_debug->sadb_x_debug_esp;
		debug_ah      |= pfkey_x_debug->sadb_x_debug_ah;
		debug_rcv     |= pfkey_x_debug->sadb_x_debug_rcv;
		debug_pfkey   |= pfkey_x_debug->sadb_x_debug_pfkey;
#ifdef CONFIG_KLIPS_IPCOMP
		sysctl_ipsec_debug_ipcomp  |=
			pfkey_x_debug->sadb_x_debug_ipcomp;
#endif          /* CONFIG_KLIPS_IPCOMP */
		sysctl_ipsec_debug_verbose |=
			pfkey_x_debug->sadb_x_debug_verbose;
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_x_debug_process: "
			    "set\n");
	} else {
		KLIPS_PRINT(debug_pfkey,
			    "klips_debug:pfkey_x_debug_process: "
			    "unset\n");
		debug_tunnel  &= pfkey_x_debug->sadb_x_debug_tunnel;
		debug_netlink &= pfkey_x_debug->sadb_x_debug_netlink;
		debug_xform   &= pfkey_x_debug->sadb_x_debug_xform;
		debug_eroute  &= pfkey_x_debug->sadb_x_debug_eroute;
		debug_spi     &= pfkey_x_debug->sadb_x_debug_spi;
		debug_radij   &= pfkey_x_debug->sadb_x_debug_radij;
		debug_esp     &= pfkey_x_debug->sadb_x_debug_esp;
		debug_ah      &= pfkey_x_debug->sadb_x_debug_ah;
		debug_rcv     &= pfkey_x_debug->sadb_x_debug_rcv;
		debug_pfkey   &= pfkey_x_debug->sadb_x_debug_pfkey;
#ifdef CONFIG_KLIPS_IPCOMP
		sysctl_ipsec_debug_ipcomp  &=
			pfkey_x_debug->sadb_x_debug_ipcomp;
#endif          /* CONFIG_KLIPS_IPCOMP */
		sysctl_ipsec_debug_verbose &=
			pfkey_x_debug->sadb_x_debug_verbose;
	}

errlab:
	return error;
}
