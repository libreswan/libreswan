/*
 * receive code
 * Copyright (C) 1996, 1997  John Ioannidis.
 * Copyright (C) 1998-2003   Richard Guy Briggs.
 * Copyright (C) 2004        Michael Richardson <mcr@xelerance.com>
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
 */

char ipsec_rcv_c_version[] = "RCSID $Id: ipsec_rcv.c,v 1.178 2005/10/21 02:19:34 mcr Exp $";

#include <linux/config.h>
#include <linux/version.h>

#define __NO_VERSION__
#include <linux/module.h>
#include <linux/kernel.h> /* printk() */

#include "openswan/ipsec_param.h"

#ifdef MALLOC_SLAB
# include <linux/slab.h> /* kmalloc() */
#else /* MALLOC_SLAB */
# include <linux/malloc.h> /* kmalloc() */
#endif /* MALLOC_SLAB */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/interrupt.h> /* mark_bh */

#include <linux/netdevice.h>	/* struct device, and other headers */
#include <linux/etherdevice.h>	/* eth_type_trans */
#include <linux/ip.h>		/* struct iphdr */

#include <net/tcp.h>
#include <net/udp.h>
#include <linux/skbuff.h>
#include <openswan.h>
#ifdef SPINLOCK
# ifdef SPINLOCK_23
#  include <linux/spinlock.h> /* *lock* */
# else /* SPINLOCK_23 */
#  include <asm/spinlock.h> /* *lock* */
# endif /* SPINLOCK_23 */
#endif /* SPINLOCK */

#include <net/ip.h>

#include "openswan/ipsec_kern24.h"
#include "openswan/radij.h"
#include "openswan/ipsec_encap.h"
#include "openswan/ipsec_sa.h"

#include "openswan/ipsec_radij.h"
#include "openswan/ipsec_xform.h"
#include "openswan/ipsec_tunnel.h"
#include "openswan/ipsec_rcv.h"

#include "openswan/ipsec_auth.h"

#include "openswan/ipsec_esp.h"

#ifdef CONFIG_KLIPS_AH
#include "openswan/ipsec_ah.h"
#endif /* CONFIG_KLIPS_AH */

#ifdef CONFIG_KLIPS_IPCOMP
#include "openswan/ipsec_ipcomp.h"
#endif /* CONFIG_KLIPS_COMP */

#include <openswan/pfkeyv2.h>
#include <openswan/pfkey.h>

#include "openswan/ipsec_proto.h"
#include "openswan/ipsec_alg.h"
#include "openswan/ipsec_kern24.h"

#ifdef CONFIG_KLIPS_DEBUG
int debug_rcv = 0;
#endif /* CONFIG_KLIPS_DEBUG */

int sysctl_ipsec_inbound_policy_check = 1;

#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
#include <linux/udp.h>
#endif

/* This is a private use protocol, and AT&T should be ashamed. They should have
 * used protocol # 59, which is "no next header" instead of 0xFE.
 */
#ifndef IPPROTO_ATT_HEARTBEAT
#define IPPROTO_ATT_HEARTBEAT 0xFE
#endif

/*
 * Check-replay-window routine, adapted from the original
 * by J. Hughes, from draft-ietf-ipsec-esp-des-md5-03.txt
 *
 *  This is a routine that implements a 64 packet window. This is intend-
 *  ed on being an implementation sample.
 */

DEBUG_NO_STATIC int
ipsec_checkreplaywindow(struct ipsec_sa*ipsp, __u32 seq)
{
	__u32 diff;

	if (ipsp->ips_replaywin == 0)	/* replay shut off */
		return 1;
	if (seq == 0)
		return 0;		/* first == 0 or wrapped */

	/* new larger sequence number */
	if (seq > ipsp->ips_replaywin_lastseq) {
		return 1;		/* larger is good */
	}
	diff = ipsp->ips_replaywin_lastseq - seq;

	/* too old or wrapped */ /* if wrapped, kill off SA? */
	if (diff >= ipsp->ips_replaywin) {
		return 0;
	}
	/* this packet already seen */
	if (ipsp->ips_replaywin_bitmap & (1 << diff))
		return 0;
	return 1;			/* out of order but good */
}

DEBUG_NO_STATIC int
ipsec_updatereplaywindow(struct ipsec_sa*ipsp, __u32 seq)
{
	__u32 diff;

	if (ipsp->ips_replaywin == 0)	/* replay shut off */
		return 1;
	if (seq == 0)
		return 0;		/* first == 0 or wrapped */

	/* new larger sequence number */
	if (seq > ipsp->ips_replaywin_lastseq) {
		diff = seq - ipsp->ips_replaywin_lastseq;

		/* In win, set bit for this pkt */
		if (diff < ipsp->ips_replaywin)
			ipsp->ips_replaywin_bitmap =
				(ipsp->ips_replaywin_bitmap << diff) | 1;
		else
			/* This packet has way larger seq num */
			ipsp->ips_replaywin_bitmap = 1;

		if(seq - ipsp->ips_replaywin_lastseq - 1 > ipsp->ips_replaywin_maxdiff) {
			ipsp->ips_replaywin_maxdiff = seq - ipsp->ips_replaywin_lastseq - 1;
		}
		ipsp->ips_replaywin_lastseq = seq;
		return 1;		/* larger is good */
	}
	diff = ipsp->ips_replaywin_lastseq - seq;

	/* too old or wrapped */ /* if wrapped, kill off SA? */
	if (diff >= ipsp->ips_replaywin) {
/*
		if(seq < 0.25*max && ipsp->ips_replaywin_lastseq > 0.75*max) {
			ipsec_sa_delchain(ipsp);
		}
*/
		return 0;
	}
	/* this packet already seen */
	if (ipsp->ips_replaywin_bitmap & (1 << diff))
		return 0;
	ipsp->ips_replaywin_bitmap |= (1 << diff);	/* mark as seen */
	return 1;			/* out of order but good */
}

#ifdef CONFIG_KLIPS_AUTH_HMAC_MD5
struct auth_alg ipsec_rcv_md5[]={
	{osMD5Init, osMD5Update, osMD5Final, AHMD596_ALEN}
};

#endif /* CONFIG_KLIPS_AUTH_HMAC_MD5 */

#ifdef CONFIG_KLIPS_AUTH_HMAC_SHA1
struct auth_alg ipsec_rcv_sha1[]={
	{SHA1Init, SHA1Update, SHA1Final, AHSHA196_ALEN}
};
#endif /* CONFIG_KLIPS_AUTH_HMAC_MD5 */

/*
 * decapsulate a single layer of the system
 *
 * the following things should be setup to enter this function.
 *
 * irs->stats  == stats structure (or NULL)
 * irs->ipp    = IP header.
 * irs->len    = total length of packet
 * skb->nh.iph = ipp;
 * skb->h.raw  = start of payload
 * irs->ipsp   = NULL.
 * irs->iphlen = N/A = is recalculated.
 * irs->ilen   = 0;
 * irs->authlen = 0;
 * irs->authfuncs = NULL;
 * irs->skb    = the skb;
 *
 * proto_funcs should be from ipsec_esp.c, ipsec_ah.c or ipsec_ipcomp.c.
 *
 */
enum ipsec_rcv_value
ipsec_rcv_decap_once(struct ipsec_rcv_state *irs
		     , struct xform_functions *proto_funcs)
{
	int iphlen;
	__u8 proto;
	struct in_addr ipsaddr;
	struct in_addr ipdaddr;
	int replay = 0;	/* replay value in AH or ESP packet */
	struct ipsec_sa* ipsnext = NULL;	/* next SA towards inside of packet */
	struct ipsec_sa *newipsp;
	struct iphdr *ipp;
	struct sk_buff *skb;
	struct ipsec_alg_auth *ixt_a=NULL;

	skb = irs->skb;
	irs->len = skb->len;
	ipp = irs->ipp;
	proto = ipp->protocol;
	ipsaddr.s_addr = ipp->saddr;
	addrtoa(ipsaddr, 0, irs->ipsaddr_txt, sizeof(irs->ipsaddr_txt));
	ipdaddr.s_addr = ipp->daddr;
	addrtoa(ipdaddr, 0, irs->ipdaddr_txt, sizeof(irs->ipdaddr_txt));

	iphlen = ipp->ihl << 2;
	irs->iphlen=iphlen;
	ipp->check = 0;			/* we know the sum is good */
	
	KLIPS_PRINT(debug_rcv,
		    "klips_debug:ipsec_rcv_decap_once: "
		    "decap (%d) from %s -> %s\n",
		    proto, irs->ipsaddr_txt, irs->ipdaddr_txt);

	/*
	 * Find tunnel control block and (indirectly) call the
	 * appropriate tranform routine. The resulting sk_buf
	 * is a valid IP packet ready to go through input processing.
	 */

	irs->said.dst.u.v4.sin_addr.s_addr = ipp->daddr;
	irs->said.dst.u.v4.sin_family = AF_INET;

	/* note: rcv_checks set up the said.spi value, if appropriate */
	if(proto_funcs->rcv_checks) {
		enum ipsec_rcv_value retval =
		  (*proto_funcs->rcv_checks)(irs, skb);

		if(retval < 0) {
			return retval;
		}
	}

	irs->said.proto = proto;
	irs->sa_len = satot(&irs->said, 0, irs->sa, sizeof(irs->sa));
	if(irs->sa_len == 0) {
		strcpy(irs->sa, "(error)");
	}

	newipsp = ipsec_sa_getbyid(&irs->said);
	if (newipsp == NULL) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "no ipsec_sa for SA:%s: incoming packet with no SA dropped\n",
			    irs->sa_len ? irs->sa : " (error)");
		if(irs->stats) {
			irs->stats->rx_dropped++;
		}
		return IPSEC_RCV_SAIDNOTFOUND;
	}

	/* MCR - XXX this is bizarre. ipsec_sa_getbyid returned it, having
	 * incremented the refcount, why in the world would we decrement it
	 * here? */
	/* ipsec_sa_put(irs->ipsp);*/ /* incomplete */

	/* If it is in larval state, drop the packet, we cannot process yet. */
	if(newipsp->ips_state == K_SADB_SASTATE_LARVAL) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "ipsec_sa in larval state, cannot be used yet, dropping packet.\n");
		if(irs->stats) {
			irs->stats->rx_dropped++;
		}
		ipsec_sa_put(newipsp);
		return IPSEC_RCV_SAIDNOTLIVE;
	}

	if(newipsp->ips_state == K_SADB_SASTATE_DEAD) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "ipsec_sa in dead state, cannot be used any more, dropping packet.\n");
		if(irs->stats) {
			irs->stats->rx_dropped++;
		}
		ipsec_sa_put(newipsp);
		return IPSEC_RCV_SAIDNOTLIVE;
	}

	if(sysctl_ipsec_inbound_policy_check) {
		if(irs->ipp->saddr != ((struct sockaddr_in*)(newipsp->ips_addr_s))->sin_addr.s_addr) {
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "SA:%s, src=%s of pkt does not agree with expected SA source address policy.\n",
				    irs->sa_len ? irs->sa : " (error)",
				    irs->ipsaddr_txt);
			if(irs->stats) {
				irs->stats->rx_dropped++;
			}
			ipsec_sa_put(newipsp);
			return IPSEC_RCV_FAILEDINBOUND;
		}

		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "SA:%s, src=%s of pkt agrees with expected SA source address policy.\n",
			    irs->sa_len ? irs->sa : " (error)",
			    irs->ipsaddr_txt);

		/*
		 * at this point, we have looked up a new SA, and we want to make sure that if this
		 * isn't the first SA in the list, that the previous SA actually points at this one.
		 */
		if(irs->ipsp) {
			if(irs->ipsp->ips_inext != newipsp) {
				KLIPS_PRINT(debug_rcv,
					    "klips_debug:ipsec_rcv: "
					    "unexpected SA:%s: does not agree with ips->inext policy, dropped\n",
					    irs->sa_len ? irs->sa : " (error)");
				if(irs->stats) {
					irs->stats->rx_dropped++;
				}
				ipsec_sa_put(newipsp);
				return IPSEC_RCV_FAILEDINBOUND;
			}
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "SA:%s grouping from previous SA is OK.\n",
				    irs->sa_len ? irs->sa : " (error)");
		} else {
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "SA:%s First SA in group.\n",
				    irs->sa_len ? irs->sa : " (error)");
		}






#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
                if (proto == IPPROTO_ESP) {
                        KLIPS_PRINT(debug_rcv,
                                "klips_debug:ipsec_rcv: "
                                "natt_type=%u tdbp->ips_natt_type=%u : %s\n",
                                irs->natt_type, newipsp->ips_natt_type,
                                (irs->natt_type==newipsp->ips_natt_type)?"ok":"bad");
                        if (irs->natt_type != newipsp->ips_natt_type) {
                                KLIPS_PRINT(debug_rcv,
                                            "klips_debug:ipsec_rcv: "
                                            "SA:%s does not agree with expected NAT-T policy.\n",
                                            irs->sa_len ? irs->sa : " (error)");
                                if(irs->stats) {
                                        irs->stats->rx_dropped++;
                                }
                                ipsec_sa_put(newipsp);
                                return IPSEC_RCV_FAILEDINBOUND;
                        }
                }
#endif		 
	}

	/* okay, SA checks out, so free any previous SA, and record a new one*/

	if(irs->ipsp) {
		ipsec_sa_put(irs->ipsp);
	}
	irs->ipsp=newipsp;

	/* note that the outer code will free the irs->ipsp
	   if there is an error */


	/* now check the lifetimes */
	if(ipsec_lifetime_check(&irs->ipsp->ips_life.ipl_bytes,   "bytes",
				irs->sa, ipsec_life_countbased, ipsec_incoming,
				irs->ipsp) == ipsec_life_harddied ||
	   ipsec_lifetime_check(&irs->ipsp->ips_life.ipl_addtime, "addtime",
				irs->sa, ipsec_life_timebased,  ipsec_incoming,
				irs->ipsp) == ipsec_life_harddied ||
	   ipsec_lifetime_check(&irs->ipsp->ips_life.ipl_addtime, "usetime",
				irs->sa, ipsec_life_timebased,  ipsec_incoming,
				irs->ipsp) == ipsec_life_harddied ||
	   ipsec_lifetime_check(&irs->ipsp->ips_life.ipl_packets, "packets",
				irs->sa, ipsec_life_countbased, ipsec_incoming,
				irs->ipsp) == ipsec_life_harddied) {

		/*
		 * disconnect SA from the hash table, so it can not be
		 * found again.
		 */
		ipsec_sa_rm(irs->ipsp);
		if(irs->stats) {
			irs->stats->rx_dropped++;
		}
		
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv_decap_once: "
			    "decap (%d) failed lifetime check\n",
			    proto);

		return IPSEC_RCV_LIFETIMEFAILED;
	}

#if 0
	/*
	 * This is removed for some reasons:
	 *   1) it needs to happen *after* authentication.
	 *   2) do we really care, if it authenticates, if it came
	 *      from the wrong location?
         *   3) the NAT_KA messages in IKE will also get to pluto
	 *      and it will figure out that stuff has moved.
	 *   4) the 2.6 udp-esp encap function does not pass us
	 *      the originating port number, and I can't tell
	 *      if skb->sk is guaranteed to be valid here.
	 *  2005-04-16: mcr@xelerance.com
	 */
#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
	/*
	 *
	 * XXX we should ONLY update pluto if the SA passes all checks,
	 *     which we clearly do not now.
	 */
	if ((irs->natt_type) &&
		( (irs->ipp->saddr != (((struct sockaddr_in*)(newipsp->ips_addr_s))->sin_addr.s_addr)) ||
		  (irs->natt_sport != newipsp->ips_natt_sport)
		)) {
		struct sockaddr sipaddr;
		struct sockaddr_in *psin = (struct sockaddr_in*)(newipsp->ips_addr_s);

		/** Advertise NAT-T addr change to pluto **/
		sipaddr.sa_family = AF_INET;
		((struct sockaddr_in*)&sipaddr)->sin_addr.s_addr = irs->ipp->saddr;
		((struct sockaddr_in*)&sipaddr)->sin_port = htons(irs->natt_sport);
		pfkey_nat_t_new_mapping(newipsp, &sipaddr, irs->natt_sport);

		/**
		 * Then allow or block packet depending on
		 * sysctl_ipsec_inbound_policy_check.
		 *
		 * In all cases, pluto will update SA if new mapping is
		 * accepted.
		 */
		if (sysctl_ipsec_inbound_policy_check) {
			KLIPS_PRINT(debug_rcv,
				"klips_debug:ipsec_rcv: "
				"SA:%s, src=%s:%u of pkt does not agree with expected "
				"SA source address [%08x:%u] (notifying pluto of change).\n",
				irs->sa_len ? irs->sa : " (error)",
				    irs->ipsaddr_txt, irs->natt_sport,
				    psin->sin_addr.s_addr,
				    newipsp->ips_natt_sport);
			if(irs->stats) {
				irs->stats->rx_dropped++;
			}
			ipsec_sa_put(newipsp);
			return IPSEC_RCV_FAILEDINBOUND;
		}
	}
#endif
#endif

	irs->authfuncs=NULL;

	/* authenticate, if required */
	if ((ixt_a=irs->ipsp->ips_alg_auth)) {
		irs->authlen = AHHMAC_HASHLEN;
		irs->authfuncs = NULL;
		irs->ictx = NULL;
		irs->octx = NULL;
		irs->ictx_len = 0;
		irs->octx_len = 0;
		KLIPS_PRINT(debug_rcv,
				"klips_debug:ipsec_rcv: "
				"authalg=%d authlen=%d\n",
				irs->ipsp->ips_authalg, 
				irs->authlen);
	} else
	switch(irs->ipsp->ips_authalg) {
#ifdef CONFIG_KLIPS_AUTH_HMAC_MD5
	case AH_MD5:
		irs->authlen = AHHMAC_HASHLEN;
		irs->authfuncs = ipsec_rcv_md5;
		irs->ictx = (void *)&((struct md5_ctx*)(irs->ipsp->ips_key_a))->ictx;
		irs->octx = (void *)&((struct md5_ctx*)(irs->ipsp->ips_key_a))->octx;
		irs->ictx_len = sizeof(((struct md5_ctx*)(irs->ipsp->ips_key_a))->ictx);
		irs->octx_len = sizeof(((struct md5_ctx*)(irs->ipsp->ips_key_a))->octx);
		break;
#endif /* CONFIG_KLIPS_AUTH_HMAC_MD5 */
#ifdef CONFIG_KLIPS_AUTH_HMAC_SHA1
	case AH_SHA:
		irs->authlen = AHHMAC_HASHLEN;
		irs->authfuncs = ipsec_rcv_sha1;
		irs->ictx = (void *)&((struct sha1_ctx*)(irs->ipsp->ips_key_a))->ictx;
		irs->octx = (void *)&((struct sha1_ctx*)(irs->ipsp->ips_key_a))->octx;
		irs->ictx_len = sizeof(((struct sha1_ctx*)(irs->ipsp->ips_key_a))->ictx);
		irs->octx_len = sizeof(((struct sha1_ctx*)(irs->ipsp->ips_key_a))->octx);
		break;
#endif /* CONFIG_KLIPS_AUTH_HMAC_SHA1 */
	case AH_NONE:
		irs->authlen = 0;
		irs->authfuncs = NULL;
		irs->ictx = NULL;
		irs->octx = NULL;
		irs->ictx_len = 0;
		irs->octx_len = 0;
		break;
	default:
		irs->ipsp->ips_errs.ips_alg_errs += 1;
		if(irs->stats) {
			irs->stats->rx_errors++;
		}
		return IPSEC_RCV_BADAUTH;
	}

	/* ilen counts number of bytes in ESP portion */
	irs->ilen = ((skb->data + skb->len) - skb->h.raw) - irs->authlen;
	if(irs->ilen <= 0) {
	  KLIPS_PRINT(debug_rcv,
		      "klips_debug:ipsec_rcv: "
		      "runt %s packet with no data, dropping.\n",
		      (proto == IPPROTO_ESP ? "esp" : "ah"));
	  if(irs->stats) {
	    irs->stats->rx_dropped++;
	  }
	  return IPSEC_RCV_BADLEN;
	}

	if(irs->authfuncs || ixt_a) {
		unsigned char *authenticator = NULL;

		if(proto_funcs->rcv_setup_auth) {
			enum ipsec_rcv_value retval
			    = (*proto_funcs->rcv_setup_auth)(irs, skb,
							 &replay,
							 &authenticator);
			if(retval < 0) {
				return retval;
			}
		}

		if(!authenticator) {
			irs->ipsp->ips_errs.ips_auth_errs += 1;
			if(irs->stats) {
				irs->stats->rx_dropped++;
			}
			return IPSEC_RCV_BADAUTH;
		}

		if(!ipsec_checkreplaywindow(irs->ipsp, replay)) {
			irs->ipsp->ips_errs.ips_replaywin_errs += 1;
			KLIPS_PRINT(debug_rcv & DB_RX_REPLAY,
				    "klips_debug:ipsec_rcv: "
				    "duplicate frame from %s, packet dropped\n",
				    irs->ipsaddr_txt);
			if(irs->stats) {
				irs->stats->rx_dropped++;
			}
			return IPSEC_RCV_REPLAYFAILED;
		}

		/*
		 * verify authenticator
		 */

		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "encalg = %d, authalg = %d.\n",
			    irs->ipsp->ips_encalg,
			    irs->ipsp->ips_authalg);

		/* calculate authenticator */
		if(proto_funcs->rcv_calc_auth == NULL) {
			return IPSEC_RCV_BADAUTH;
		}
		(*proto_funcs->rcv_calc_auth)(irs, skb);

		if (memcmp(irs->hash, authenticator, irs->authlen)) {
			irs->ipsp->ips_errs.ips_auth_errs += 1;
			KLIPS_PRINT(debug_rcv & DB_RX_INAU,
				    "klips_debug:ipsec_rcv: "
				    "auth failed on incoming packet from %s: hash=%08x%08x%08x auth=%08x%08x%08x, dropped\n",
				    irs->ipsaddr_txt,
				    ntohl(*(__u32*)&irs->hash[0]),
				    ntohl(*(__u32*)&irs->hash[4]),
				    ntohl(*(__u32*)&irs->hash[8]),
				    ntohl(*(__u32*)authenticator),
				    ntohl(*((__u32*)authenticator + 1)),
				    ntohl(*((__u32*)authenticator + 2)));
			if(irs->stats) {
				irs->stats->rx_dropped++;
			}
			return IPSEC_RCV_AUTHFAILED;
		} else {
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "authentication successful.\n");
		}

		/* Crypto hygiene: clear memory used to calculate autheticator.
		 * The length varies with the algorithm.
		 */
		memset(irs->hash, 0, irs->authlen);

		/* If the sequence number == 0, expire SA, it had rolled */
		if(irs->ipsp->ips_replaywin && !replay /* !irs->ipsp->ips_replaywin_lastseq */) {

		        /* we need to remove it from the sadb hash, so that it can't be found again */
			ipsec_sa_rm(irs->ipsp);

			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "replay window counter rolled, expiring SA.\n");
			if(irs->stats) {
				irs->stats->rx_dropped++;
			}
			return IPSEC_RCV_REPLAYROLLED;
		}

		/* now update the replay counter */
		if (!ipsec_updatereplaywindow(irs->ipsp, replay)) {
			irs->ipsp->ips_errs.ips_replaywin_errs += 1;
			KLIPS_PRINT(debug_rcv & DB_RX_REPLAY,
				    "klips_debug:ipsec_rcv: "
				    "duplicate frame from %s, packet dropped\n",
				    irs->ipsaddr_txt);
			if(irs->stats) {
				irs->stats->rx_dropped++;
			}
			return IPSEC_RCV_REPLAYROLLED;
		}
	}

	if(proto_funcs->rcv_decrypt) {
		enum ipsec_rcv_value retval =
		  (*proto_funcs->rcv_decrypt)(irs);

		if(retval != IPSEC_RCV_OK) {
			return retval;
		}
	}

	/*
	 *	Adjust pointers
	 */
	skb = irs->skb;
	irs->len = skb->len;
	ipp = irs->ipp = skb->nh.iph;
	iphlen = ipp->ihl<<2;
	skb->h.raw = skb->nh.raw + iphlen;
	
	/* zero any options that there might be */
	memset(&(IPCB(skb)->opt), 0, sizeof(struct ip_options));

	ipsaddr.s_addr = ipp->saddr;
	addrtoa(ipsaddr, 0, irs->ipsaddr_txt, sizeof(irs->ipsaddr_txt));
	ipdaddr.s_addr = ipp->daddr;
	addrtoa(ipdaddr, 0, irs->ipdaddr_txt, sizeof(irs->ipdaddr_txt));

	/*
	 *	Discard the original ESP/AH header
	 */
	ipp->protocol = irs->next_header;

	ipp->check = 0;	/* NOTE: this will be included in checksum */
	ipp->check = ip_fast_csum((unsigned char *)skb->nh.iph, iphlen >> 2);

	KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
		    "klips_debug:ipsec_rcv: "
		    "after <%s%s%s>, SA:%s:\n",
		    IPS_XFORM_NAME(irs->ipsp),
		    irs->sa_len ? irs->sa : " (error)");
	KLIPS_IP_PRINT(debug_rcv & DB_RX_PKTRX, ipp);

	skb->protocol = htons(ETH_P_IP);
	skb->ip_summed = 0;

	ipsnext = irs->ipsp->ips_inext;
	if(sysctl_ipsec_inbound_policy_check) {
		if(ipsnext) {
			if(
				ipp->protocol != IPPROTO_AH
				&& ipp->protocol != IPPROTO_ESP
#ifdef CONFIG_KLIPS_IPCOMP
				&& ipp->protocol != IPPROTO_COMP
				&& (ipsnext->ips_said.proto != IPPROTO_COMP
				    || ipsnext->ips_inext)
#endif /* CONFIG_KLIPS_IPCOMP */
				&& ipp->protocol != IPPROTO_IPIP
				&& ipp->protocol != IPPROTO_ATT_HEARTBEAT  /* heartbeats to AT&T SIG/GIG */
				) {
				KLIPS_PRINT(debug_rcv,
					    "klips_debug:ipsec_rcv: "
					    "packet with incomplete policy dropped, last successful SA:%s.\n",
					    irs->sa_len ? irs->sa : " (error)");
				if(irs->stats) {
					irs->stats->rx_dropped++;
				}
				return IPSEC_RCV_FAILEDINBOUND;
			}
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "SA:%s, Another IPSEC header to process.\n",
				    irs->sa_len ? irs->sa : " (error)");
		} else {
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "No ips_inext from this SA:%s.\n",
				    irs->sa_len ? irs->sa : " (error)");
		}
	}

#ifdef CONFIG_KLIPS_IPCOMP
	/* update ipcomp ratio counters, even if no ipcomp packet is present */
	if (ipsnext
	    && ipsnext->ips_said.proto == IPPROTO_COMP
	    && ipp->protocol != IPPROTO_COMP) {
		ipsnext->ips_comp_ratio_cbytes += ntohs(ipp->tot_len);
		ipsnext->ips_comp_ratio_dbytes += ntohs(ipp->tot_len);
	}
#endif /* CONFIG_KLIPS_IPCOMP */

	irs->ipsp->ips_life.ipl_bytes.ipl_count += irs->len;
	irs->ipsp->ips_life.ipl_bytes.ipl_last   = irs->len;

	if(!irs->ipsp->ips_life.ipl_usetime.ipl_count) {
		irs->ipsp->ips_life.ipl_usetime.ipl_count = jiffies / HZ;
	}
	irs->ipsp->ips_life.ipl_usetime.ipl_last = jiffies / HZ;
	irs->ipsp->ips_life.ipl_packets.ipl_count += 1;

#ifdef CONFIG_NETFILTER
	if(proto == IPPROTO_ESP || proto == IPPROTO_AH) {
		skb->nfmark = (skb->nfmark & (~(IPsecSAref2NFmark(IPSEC_SA_REF_MASK))))
			| IPsecSAref2NFmark(IPsecSA2SAref(irs->ipsp));
		KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
			    "klips_debug:ipsec_rcv: "
			    "%s SA sets skb->nfmark=0x%x.\n",
			    proto == IPPROTO_ESP ? "ESP" : "AH",
			    (unsigned)skb->nfmark);
	}
#endif /* CONFIG_NETFILTER */

	return IPSEC_RCV_OK;
}


/*
 * core decapsulation loop for all protocols.
 *
 * the following things should be setup to enter this function.
 *
 * irs->stats  == stats structure (or NULL)
 * irs->ipp    = IP header.
 * irs->ipsp   = NULL.
 * irs->ilen   = 0;
 * irs->authlen = 0;
 * irs->authfuncs = NULL;
 * irs->skb    = skb;
 * skb->nh.iph = ipp;
 * skb->h.raw  = start of payload
 *
 */
int ipsec_rcv_decap(struct ipsec_rcv_state *irs)
{
	struct ipsec_sa *ipsp = NULL;
	struct ipsec_sa* ipsnext = NULL;
	struct in_addr ipsaddr;
	struct in_addr ipdaddr;
	struct iphdr *ipp;
	struct sk_buff *skb = NULL;

	/* begin decapsulating loop here */

	/*
	  The spinlock is to prevent any other process from
	  accessing or deleting the ipsec_sa hash table or any of the
	  ipsec_sa s while we are using and updating them.

	  This is not optimal, but was relatively straightforward
	  at the time.  A better way to do it has been planned for
	  more than a year, to lock the hash table and put reference
	  counts on each ipsec_sa instead.  This is not likely to happen
	  in KLIPS1 unless a volunteer contributes it, but will be
	  designed into KLIPS2.
	*/
	spin_lock(&tdb_lock);

	do {
	        int decap_stat;
		struct xform_functions *proto_funcs;

		switch(irs->ipp->protocol) {
		case IPPROTO_ESP:
		  proto_funcs = esp_xform_funcs;
		  break;
		  
#ifdef CONFIG_KLIPS_AH
		case IPPROTO_AH:
		  proto_funcs = ah_xform_funcs;
		  break;
#endif /* !CONFIG_KLIPS_AH */
		  
#ifdef CONFIG_KLIPS_IPCOMP
		case IPPROTO_COMP:
		  proto_funcs = ipcomp_xform_funcs;
		  break;
#endif /* !CONFIG_KLIPS_IPCOMP */
		default:
		  if(irs->stats) {
		    irs->stats->rx_errors++;
		  }
		  decap_stat = IPSEC_RCV_BADPROTO;
		  goto rcvleave;
		}

	        decap_stat = ipsec_rcv_decap_once(irs, proto_funcs);

		if(decap_stat != IPSEC_RCV_OK) {
			spin_unlock(&tdb_lock);
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: decap_once failed: %d\n",
				    decap_stat);
		
			goto rcvleave;
		}
	/* end decapsulation loop here */
	} while(   (irs->ipp->protocol == IPPROTO_ESP )
		|| (irs->ipp->protocol == IPPROTO_AH  )
#ifdef CONFIG_KLIPS_IPCOMP
		|| (irs->ipp->protocol == IPPROTO_COMP)
#endif /* CONFIG_KLIPS_IPCOMP */
		);

	/* set up for decap loop */
	ipp  =irs->ipp;
	ipsp =irs->ipsp;
	ipsnext = ipsp->ips_inext;
	skb = irs->skb;

	/* if there is an IPCOMP, but we don't have an IPPROTO_COMP,
	 * then we can just skip it
	 */
#ifdef CONFIG_KLIPS_IPCOMP
	if(ipsnext && ipsnext->ips_said.proto == IPPROTO_COMP) {
		ipsp = ipsnext;
		ipsnext = ipsp->ips_inext;
	}
#endif /* CONFIG_KLIPS_IPCOMP */

#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
	if ((irs->natt_type) && (ipp->protocol != IPPROTO_IPIP)) {
	  /**
	   * NAT-Traversal and Transport Mode:
	   *   we need to correct TCP/UDP checksum
	   *
	   * If we've got NAT-OA, we can fix checksum without recalculation.
	   */
	  __u32 natt_oa = ipsp->ips_natt_oa ?
	    ((struct sockaddr_in*)(ipsp->ips_natt_oa))->sin_addr.s_addr : 0;
	  __u16 pkt_len = skb->tail - (unsigned char *)ipp;
	  __u16 data_len = pkt_len - (ipp->ihl << 2);
	  
	  switch (ipp->protocol) {
	  case IPPROTO_TCP:
	    if (data_len >= sizeof(struct tcphdr)) {
	      struct tcphdr *tcp = skb->h.th;
	      if (natt_oa) {
		__u32 buff[2] = { ~natt_oa, ipp->saddr };
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "NAT-T & TRANSPORT: "
			    "fix TCP checksum using NAT-OA\n");
		tcp->check = csum_fold(
				       csum_partial((unsigned char *)buff, sizeof(buff),
						    tcp->check^0xffff));
	      }
	      else {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "NAT-T & TRANSPORT: recalc TCP checksum\n");
		if (pkt_len > (ntohs(ipp->tot_len)))
		  data_len -= (pkt_len - ntohs(ipp->tot_len));
		tcp->check = 0;
		tcp->check = csum_tcpudp_magic(ipp->saddr, ipp->daddr,
					       data_len, IPPROTO_TCP,
					       csum_partial((unsigned char *)tcp, data_len, 0));
	      }
	    }
	    else {
	      KLIPS_PRINT(debug_rcv,
			  "klips_debug:ipsec_rcv: "
			  "NAT-T & TRANSPORT: can't fix TCP checksum\n");
	    }
	    break;
	  case IPPROTO_UDP:
	    if (data_len >= sizeof(struct udphdr)) {
	      struct udphdr *udp = skb->h.uh;
	      if (udp->check == 0) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "NAT-T & TRANSPORT: UDP checksum already 0\n");
	      }
	      else if (natt_oa) {
		__u32 buff[2] = { ~natt_oa, ipp->saddr };
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "NAT-T & TRANSPORT: "
			    "fix UDP checksum using NAT-OA\n");
		udp->check = csum_fold(
				       csum_partial((unsigned char *)buff, sizeof(buff),
						    udp->check^0xffff));
	      }
	      else {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "NAT-T & TRANSPORT: zero UDP checksum\n");
		udp->check = 0;
	      }
	    }
	    else {
	      KLIPS_PRINT(debug_rcv,
			  "klips_debug:ipsec_rcv: "
			  "NAT-T & TRANSPORT: can't fix UDP checksum\n");
	    }
	    break;
	  default:
	    KLIPS_PRINT(debug_rcv,
			"klips_debug:ipsec_rcv: "
			"NAT-T & TRANSPORT: non TCP/UDP packet -- do nothing\n");
	    break;
	  }
	}
#endif

	/*
	 * XXX this needs to be locked from when it was first looked
	 * up in the decapsulation loop.  Perhaps it is better to put
	 * the IPIP decap inside the loop.
	 */
	if(ipsnext) {
		ipsp = ipsnext;
		irs->sa_len = satot(&irs->said, 0, irs->sa, sizeof(irs->sa));
		if((ipp->protocol != IPPROTO_IPIP) && 
                   (ipp->protocol != IPPROTO_ATT_HEARTBEAT)) {  /* AT&T heartbeats to SIG/GIG */
			spin_unlock(&tdb_lock);
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "SA:%s, Hey!  How did this get through?  Dropped.\n",
				    irs->sa_len ? irs->sa : " (error)");
			if(irs->stats) {
				irs->stats->rx_dropped++;
			}
			goto rcvleave;
		}
		if(sysctl_ipsec_inbound_policy_check) {
			struct sockaddr_in *psin = (struct sockaddr_in*)(ipsp->ips_addr_s);
			if((ipsnext = ipsp->ips_inext)) {
				char sa2[SATOT_BUF];
				size_t sa_len2;
				sa_len2 = satot(&ipsnext->ips_said, 0, sa2, sizeof(sa2));
				spin_unlock(&tdb_lock);
				KLIPS_PRINT(debug_rcv,
					    "klips_debug:ipsec_rcv: "
					    "unexpected SA:%s after IPIP SA:%s\n",
					    sa_len2 ? sa2 : " (error)",
					    irs->sa_len ? irs->sa : " (error)");
				if(irs->stats) {
					irs->stats->rx_dropped++;
				}
				goto rcvleave;
			}
			if(ipp->saddr != psin->sin_addr.s_addr) {
				spin_unlock(&tdb_lock);
				KLIPS_PRINT(debug_rcv,
					    "klips_debug:ipsec_rcv: "
					    "SA:%s, src=%s(%08x) does match expected 0x%08x.\n",
					    irs->sa_len ? irs->sa : " (error)",
					    irs->ipsaddr_txt, 
					    ipp->saddr, psin->sin_addr.s_addr);
				if(irs->stats) {
					irs->stats->rx_dropped++;
				}
				goto rcvleave;
			}
		}

	if(ipp->protocol == IPPROTO_IPIP)  /* added to support AT&T heartbeats to SIG/GIG */
	{  
		/*
		 * XXX this needs to be locked from when it was first looked
		 * up in the decapsulation loop.  Perhaps it is better to put
		 * the IPIP decap inside the loop.
		 */
		ipsp->ips_life.ipl_bytes.ipl_count += skb->len;
		ipsp->ips_life.ipl_bytes.ipl_last   = skb->len;

		if(!ipsp->ips_life.ipl_usetime.ipl_count) {
			ipsp->ips_life.ipl_usetime.ipl_count = jiffies / HZ;
		}
		ipsp->ips_life.ipl_usetime.ipl_last = jiffies / HZ;
		ipsp->ips_life.ipl_packets.ipl_count += 1;

		if(skb->len < irs->iphlen) {
			spin_unlock(&tdb_lock);
			printk(KERN_WARNING "klips_debug:ipsec_rcv: "
			       "tried to skb_pull iphlen=%d, %d available.  This should never happen, please report.\n",
			       irs->iphlen,
			       (int)(skb->len));

			goto rcvleave;
		}

		/*
		 * we need to pull up by size of IP header,
		 * options, but also by any UDP/ESP encap there might
		 * have been, and this deals with all cases.
		 */
		skb_pull(skb, (skb->h.raw - skb->nh.raw));

		/* new L3 header is where L4 payload was */
		skb->nh.raw = skb->h.raw;

		/* now setup new L4 payload location */
		ipp = (struct iphdr *)skb->nh.raw;
		skb->h.raw = skb->nh.raw + (ipp->ihl << 2);


		/* remove any saved options that we might have,
		 * since we have a new IP header.
		 */
		memset(&(IPCB(skb)->opt), 0, sizeof(struct ip_options));

#if 0
		KLIPS_PRINT(debug_rcv, "csum: %d\n", ip_fast_csum((u8 *)ipp, ipp->ihl));
#endif

		/* re-do any strings for debugging */
		ipsaddr.s_addr = ipp->saddr;
		addrtoa(ipsaddr, 0, irs->ipsaddr_txt, sizeof(irs->ipsaddr_txt));
		ipdaddr.s_addr = ipp->daddr;
		addrtoa(ipdaddr, 0, irs->ipdaddr_txt, sizeof(irs->ipdaddr_txt));

		skb->protocol = htons(ETH_P_IP);
		skb->ip_summed = 0;
		KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
			    "klips_debug:ipsec_rcv: "
			    "IPIP tunnel stripped.\n");
		KLIPS_IP_PRINT(debug_rcv & DB_RX_PKTRX, ipp);
  }

		if(sysctl_ipsec_inbound_policy_check
		   /*
		      Note: "xor" (^) logically replaces "not equal"
		      (!=) and "bitwise or" (|) logically replaces
		      "boolean or" (||).  This is done to speed up
		      execution by doing only bitwise operations and
		      no branch operations
		   */
		   && (((ipp->saddr & ipsp->ips_mask_s.u.v4.sin_addr.s_addr)
				    ^ ipsp->ips_flow_s.u.v4.sin_addr.s_addr)
		       | ((ipp->daddr & ipsp->ips_mask_d.u.v4.sin_addr.s_addr)
				      ^ ipsp->ips_flow_d.u.v4.sin_addr.s_addr)) )
		{
			char sflow_txt[SUBNETTOA_BUF], dflow_txt[SUBNETTOA_BUF];

			subnettoa(ipsp->ips_flow_s.u.v4.sin_addr,
				ipsp->ips_mask_s.u.v4.sin_addr,
				0, sflow_txt, sizeof(sflow_txt));
			subnettoa(ipsp->ips_flow_d.u.v4.sin_addr,
				ipsp->ips_mask_d.u.v4.sin_addr,
				0, dflow_txt, sizeof(dflow_txt));
			spin_unlock(&tdb_lock);
			KLIPS_PRINT(debug_rcv,
				    "klips_debug:ipsec_rcv: "
				    "SA:%s, inner tunnel policy [%s -> %s] does not agree with pkt contents [%s -> %s].\n",
				    irs->sa_len ? irs->sa : " (error)",
				    sflow_txt,
				    dflow_txt,
				    irs->ipsaddr_txt,
				    irs->ipdaddr_txt);
			if(irs->stats) {
				irs->stats->rx_dropped++;
			}
			goto rcvleave;
		}
#ifdef CONFIG_NETFILTER
		skb->nfmark = (skb->nfmark & (~(IPsecSAref2NFmark(IPSEC_SA_REF_TABLE_MASK))))
			| IPsecSAref2NFmark(IPsecSA2SAref(ipsp));
		KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
			    "klips_debug:ipsec_rcv: "
			    "IPIP SA sets skb->nfmark=0x%x.\n",
			    (unsigned)skb->nfmark);
#endif /* CONFIG_NETFILTER */
	}

	spin_unlock(&tdb_lock);

	if(irs->stats) {
		irs->stats->rx_bytes += skb->len;
	}
	if(skb->dst) {
		dst_release(skb->dst);
		skb->dst = NULL;
	}
	skb->pkt_type = PACKET_HOST;
	if(irs->hard_header_len &&
	   (skb->mac.raw != (skb->nh.raw - irs->hard_header_len)) &&
	   (irs->hard_header_len <= skb_headroom(skb))) {
		/* copy back original MAC header */
		memmove(skb->nh.raw - irs->hard_header_len,
			skb->mac.raw, irs->hard_header_len);
		skb->mac.raw = skb->nh.raw - irs->hard_header_len;
	}

#ifdef CONFIG_KLIPS_IPCOMP
	if(ipp->protocol == IPPROTO_COMP) {
		unsigned int flags = 0;

		if(sysctl_ipsec_inbound_policy_check) {
			KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
				"klips_debug:ipsec_rcv: "
				"inbound policy checking enabled, IPCOMP follows IPIP, dropped.\n");
			if (irs->stats) {
				irs->stats->rx_errors++;
			}
			goto rcvleave;
		}
		/*
		  XXX need a ipsec_sa for updating ratio counters but it is not
		  following policy anyways so it is not a priority
		*/
		skb = skb_decompress(skb, NULL, &flags);
		if (!skb || flags) {
			KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
				"klips_debug:ipsec_rcv: "
				"skb_decompress() returned error flags: %d, dropped.\n",
				flags);
			if (irs->stats) {
				irs->stats->rx_errors++;
			}
			goto rcvleave;
		}
	}
#endif /* CONFIG_KLIPS_IPCOMP */

	/*
	 * make sure that data now starts at IP header, since we are going
	 * to pass this back to ip_input (aka netif_rx). Rules for what the
	 * pointers wind up a different for 2.6 vs 2.4, so we just fudge it here.
	 */
#ifdef NET_26
	skb->data = skb_push(skb, skb->h.raw - skb->nh.raw);
#else
	skb->data = skb->nh.raw;
	{
	  struct iphdr *iph = skb->nh.iph;
	  int len = ntohs(iph->tot_len);
	  skb->len  = len;
	}
#endif

#ifdef SKB_RESET_NFCT
	nf_conntrack_put(skb->nfct);
	skb->nfct = NULL;
#if defined(CONFIG_NETFILTER_DEBUG) && defined(HAVE_SKB_NF_DEBUG)
	skb->nf_debug = 0;
#endif /* CONFIG_NETFILTER_DEBUG */
#endif /* SKB_RESET_NFCT */
	KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
		    "klips_debug:ipsec_rcv: "
		    "netif_rx() called.\n");
	netif_rx(skb);
	skb=NULL;

 rcvleave:
	if(skb) {
		ipsec_kfree_skb(skb);
	}

	return(0);
}

struct sk_buff *ipsec_rcv_unclone(struct sk_buff *skb,
				  struct ipsec_rcv_state *irs)
{
	/* if skb was cloned (most likely due to a packet sniffer such as
	   tcpdump being momentarily attached to the interface), make
	   a copy of our own to modify */
	if(skb_cloned(skb)) {
		/* include any mac header while copying.. */
		if(skb_headroom(skb) < irs->hard_header_len) {
			printk(KERN_WARNING "klips_error:ipsec_rcv: "
			       "tried to skb_push hhlen=%d, %d available.  This should never happen, please report.\n",
			       irs->hard_header_len,
			       skb_headroom(skb));
			goto rcvleave;
		}
		skb_push(skb, irs->hard_header_len);
		if
#ifdef SKB_COW_NEW
		  (skb_cow(skb, skb_headroom(skb)) != 0)
#else /* SKB_COW_NEW */
		  ((skb = skb_cow(skb, skb_headroom(skb))) == NULL)
#endif /* SKB_COW_NEW */
		{
			goto rcvleave;
		}
		if(skb->len < irs->hard_header_len) {
			printk(KERN_WARNING "klips_error:ipsec_rcv: "
			       "tried to skb_pull hhlen=%d, %d available.  This should never happen, please report.\n",
			       irs->hard_header_len,
			       skb->len);
			goto rcvleave;
		}
		skb_pull(skb, irs->hard_header_len);
	}
	return skb;

rcvleave:
	ipsec_kfree_skb(skb);
	return NULL;
}


#if !defined(NET_26) && defined(CONFIG_IPSEC_NAT_TRAVERSAL)
/*
 * decapsulate a UDP encapsulated ESP packet
 */
struct sk_buff *ipsec_rcv_natt_decap(struct sk_buff *skb
				     , struct ipsec_rcv_state *irs
				     , int *udp_decap_ret_p)
{
	*udp_decap_ret_p = 0;
	if (skb->sk && skb->nh.iph && skb->nh.iph->protocol==IPPROTO_UDP) {
		/**
		 * Packet comes from udp_queue_rcv_skb so it is already defrag,
		 * checksum verified, ... (ie safe to use)
		 *
		 * If the packet is not for us, return -1 and udp_queue_rcv_skb
		 * will continue to handle it (do not kfree skb !!).
		 */

#ifndef UDP_OPT_IN_SOCK
		struct udp_opt {
			__u32 esp_in_udp;
		};
		struct udp_opt *tp =  (struct udp_opt *)&(skb->sk->tp_pinfo.af_tcp);
#else
		struct udp_opt *tp =  &(skb->sk->tp_pinfo.af_udp);
#endif

		struct iphdr *ip = (struct iphdr *)skb->nh.iph;
		struct udphdr *udp = (struct udphdr *)((__u32 *)ip+ip->ihl);
		__u8 *udpdata = (__u8 *)udp + sizeof(struct udphdr);
		__u32 *udpdata32 = (__u32 *)udpdata;
		
		irs->natt_sport = ntohs(udp->source);
		irs->natt_dport = ntohs(udp->dest);
	  
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "suspected ESPinUDP packet (NAT-Traversal) [%d].\n",
			    tp->esp_in_udp);
		KLIPS_IP_PRINT(debug_rcv, ip);
	  
		if (udpdata < skb->tail) {
			unsigned int len = skb->tail - udpdata;
			if ((len==1) && (udpdata[0]==0xff)) {
				KLIPS_PRINT(debug_rcv,
					    "klips_debug:ipsec_rcv: "
					    /* not IPv6 compliant message */
					    "NAT-keepalive from %d.%d.%d.%d.\n", NIPQUAD(ip->saddr));
				*udp_decap_ret_p = 0;
				return NULL;
			}
			else if ( (tp->esp_in_udp == ESPINUDP_WITH_NON_IKE) &&
				  (len > (2*sizeof(__u32) + sizeof(struct esphdr))) &&
				  (udpdata32[0]==0) && (udpdata32[1]==0) ) {
				/* ESP Packet with Non-IKE header */
				KLIPS_PRINT(debug_rcv, 
					    "klips_debug:ipsec_rcv: "
					    "ESPinUDP pkt with Non-IKE - spi=0x%x\n",
					    ntohl(udpdata32[2]));
				irs->natt_type = ESPINUDP_WITH_NON_IKE;
				irs->natt_len = sizeof(struct udphdr)+(2*sizeof(__u32));
			}
			else if ( (tp->esp_in_udp == ESPINUDP_WITH_NON_ESP) &&
				  (len > sizeof(struct esphdr)) &&
				  (udpdata32[0]!=0) ) {
				/* ESP Packet without Non-ESP header */
				irs->natt_type = ESPINUDP_WITH_NON_ESP;
				irs->natt_len = sizeof(struct udphdr);
				KLIPS_PRINT(debug_rcv, 
					    "klips_debug:ipsec_rcv: "
					    "ESPinUDP pkt without Non-ESP - spi=0x%x\n",
					    ntohl(udpdata32[0]));
			}
			else {
				KLIPS_PRINT(debug_rcv,
					    "klips_debug:ipsec_rcv: "
					    "IKE packet - not handled here\n");
				*udp_decap_ret_p = -1;
				return NULL;
			}
		}
		else {
			return NULL;
		}
	}
	return skb;
}
#endif

/* management of buffers */
static struct ipsec_rcv_state * ipsec_rcv_state_new (void);
static void ipsec_rcv_state_delete (struct ipsec_rcv_state *irs);

int
ipsec_rcv(struct sk_buff *skb
#ifndef PROTO_HANDLER_SINGLE_PARM
	  unsigned short xlen
#endif /* PROTO_HANDLER_SINGLE_PARM */
	  )
{
#ifdef CONFIG_KLIPS_DEBUG
	struct net_device *dev = skb->dev;
#endif /* CONFIG_KLIPS_DEBUG */
	unsigned char protoc;
	struct net_device_stats *stats = NULL;		/* This device's statistics */
	struct net_device *ipsecdev = NULL, *prvdev;
	struct ipsecpriv *prv;
	struct ipsec_rcv_state *irs = NULL;
	struct iphdr *ipp;
	char name[9];
	int i;

	/* Don't unlink in the middle of a turnaround */
	KLIPS_INC_USE;

	if (skb == NULL) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "NULL skb passed in.\n");
		goto error_no_skb;
	}

	if (skb->data == NULL) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "NULL skb->data passed in, packet is bogus, dropping.\n");
		goto error_bad_skb;
	}

        irs = ipsec_rcv_state_new ();
        if (unlikely (! irs)) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "failled to allocate a rcv state object\n");
                goto error_alloc;
        }

#if defined(CONFIG_IPSEC_NAT_TRAVERSAL) && !defined(NET_26)
	{
		/* NET_26 NAT-T is handled by seperate function */
		struct sk_buff *nskb;
		int udp_decap_ret = 0;

		nskb = ipsec_rcv_natt_decap(skb, irs, &udp_decap_ret);
		if(nskb == NULL) {
			/* return with non-zero, because UDP.c code
			 * need to send it upstream.
			 */
			if(skb && udp_decap_ret == 0) {
				ipsec_kfree_skb(skb);
			}
			KLIPS_DEC_USE;
			return(udp_decap_ret);
		}
		skb = nskb;
	}
#endif /* NAT_T */

	/* dev->hard_header_len is unreliable and should not be used */
	irs->hard_header_len = skb->mac.raw ? (skb->nh.raw - skb->mac.raw) : 0;
	if((irs->hard_header_len < 0) || (irs->hard_header_len > skb_headroom(skb)))
		irs->hard_header_len = 0;

	skb = ipsec_rcv_unclone(skb, irs);
	if(skb == NULL) {
		goto rcvleave;
	}

#if IP_FRAGMENT_LINEARIZE
	/* In Linux 2.4.4, we may have to reassemble fragments. They are
	   not assembled automatically to save TCP from having to copy
	   twice.
	*/
	if (skb_is_nonlinear(skb)) {
#ifdef HAVE_NEW_SKB_LINEARIZE
		if (skb_linearize_cow(skb) != 0)
#else
		if (skb_linearize(skb, GFP_ATOMIC) != 0) 
#endif
		{
			goto rcvleave;
		}
	}
#endif /* IP_FRAGMENT_LINEARIZE */

#if defined(CONFIG_IPSEC_NAT_TRAVERSAL) && !defined(NET_26)
	if (irs->natt_len) {
		/**
		 * Now, we are sure packet is ESPinUDP, and we have a private
		 * copy that has been linearized, remove natt_len bytes
		 * from packet and modify protocol to ESP.
		 */
		if (((unsigned char *)skb->data > (unsigned char *)skb->nh.iph)
		    && ((unsigned char *)skb->nh.iph > (unsigned char *)skb->head))
		{
			unsigned int _len = (unsigned char *)skb->data -
				(unsigned char *)skb->nh.iph;
			KLIPS_PRINT(debug_rcv,
				"klips_debug:ipsec_rcv: adjusting skb: skb_push(%u)\n",
				_len);
			skb_push(skb, _len);
		}
		KLIPS_PRINT(debug_rcv,
		    "klips_debug:ipsec_rcv: "
			"removing %d bytes from ESPinUDP packet\n", irs->natt_len);
		ipp = skb->nh.iph;
		irs->iphlen = ipp->ihl << 2;
		ipp->tot_len = htons(ntohs(ipp->tot_len) - irs->natt_len);
		if (skb->len < irs->iphlen + irs->natt_len) {
			printk(KERN_WARNING
		       "klips_error:ipsec_rcv: "
		       "ESPinUDP packet is too small (%d < %d+%d). "
			   "This should never happen, please report.\n",
		       (int)(skb->len), irs->iphlen, irs->natt_len);
			goto rcvleave;
		}

		/* advance payload pointer to point past the UDP header */
		skb->h.raw = skb->h.raw + irs->natt_len;

		/* modify protocol */
		ipp->protocol = IPPROTO_ESP;

		skb->sk = NULL;

		KLIPS_IP_PRINT(debug_rcv, skb->nh.iph);
	}
#endif

	ipp = skb->nh.iph;

	{
	  	struct in_addr ipsaddr;
		struct in_addr ipdaddr;

		ipsaddr.s_addr = ipp->saddr;
		addrtoa(ipsaddr, 0, irs->ipsaddr_txt
			, sizeof(irs->ipsaddr_txt));
		ipdaddr.s_addr = ipp->daddr;
		addrtoa(ipdaddr, 0, irs->ipdaddr_txt
			, sizeof(irs->ipdaddr_txt));
	}

	irs->iphlen = ipp->ihl << 2;

	KLIPS_PRINT(debug_rcv,
		    "klips_debug:ipsec_rcv: "
		    "<<< Info -- ");
	KLIPS_PRINTMORE(debug_rcv && skb->dev, "skb->dev=%s ",
			skb->dev->name ? skb->dev->name : "NULL");
	KLIPS_PRINTMORE(debug_rcv && dev, "dev=%s ",
			dev->name ? dev->name : "NULL");
	KLIPS_PRINTMORE(debug_rcv, "\n");

	KLIPS_PRINT(debug_rcv && !(skb->dev && dev && (skb->dev == dev)),
		    "klips_debug:ipsec_rcv: "
		    "Informational -- **if this happens, find out why** skb->dev:%s is not equal to dev:%s\n",
		    skb->dev ? (skb->dev->name ? skb->dev->name : "NULL") : "NULL",
		    dev ? (dev->name ? dev->name : "NULL") : "NULL");

	protoc = ipp->protocol;
#ifndef NET_21
	if((!protocol) || (protocol->protocol != protoc)) {
		KLIPS_PRINT(debug_rcv & DB_RX_IPSA,
			    "klips_debug:ipsec_rcv: "
			    "protocol arg is NULL or unequal to the packet contents, this is odd, using value in packet.\n");
	}
#endif /* !NET_21 */

	if( (protoc != IPPROTO_AH) &&
#ifdef CONFIG_KLIPS_IPCOMP_disabled_until_we_register_IPCOMP_HANDLER
	    (protoc != IPPROTO_COMP) &&
#endif /* CONFIG_KLIPS_IPCOMP */
	    (protoc != IPPROTO_ESP) ) {
		KLIPS_PRINT(debug_rcv & DB_RX_IPSA,
			    "klips_debug:ipsec_rcv: Why the hell is someone "
			    "passing me a non-ipsec protocol = %d packet? -- dropped.\n",
			    protoc);
		goto rcvleave;
	}

	if(skb->dev) {
		for(i = 0; i < IPSEC_NUM_IF; i++) {
			sprintf(name, IPSEC_DEV_FORMAT, i);
			if(!strcmp(name, skb->dev->name)) {
				prv = (struct ipsecpriv *)(skb->dev->priv);
				if(prv) {
					stats = (struct net_device_stats *) &(prv->mystats);
				}
				ipsecdev = skb->dev;
				KLIPS_PRINT(debug_rcv,
					    "klips_debug:ipsec_rcv: "
					    "Info -- pkt already proc'ed a group of ipsec headers, processing next group of ipsec headers.\n");
				break;
			}
			if((ipsecdev = __ipsec_dev_get(name)) == NULL) {
				KLIPS_PRINT(debug_rcv,
					    "klips_error:ipsec_rcv: "
					    "device %s does not exist\n",
					    name);
			}
			prv = ipsecdev ? (struct ipsecpriv *)(ipsecdev->priv) : NULL;
			prvdev = prv ? (struct net_device *)(prv->dev) : NULL;

#if 0
			KLIPS_PRINT(debug_rcv && prvdev,
				    "klips_debug:ipsec_rcv: "
				    "physical device for device %s is %s\n",
				    name,
				    prvdev->name);
#endif
			if(prvdev && skb->dev &&
			   !strcmp(prvdev->name, skb->dev->name)) {
				stats = prv ? ((struct net_device_stats *) &(prv->mystats)) : NULL;
				skb->dev = ipsecdev;
				KLIPS_PRINT(debug_rcv && prvdev,
					    "klips_debug:ipsec_rcv: "
					    "assigning packet ownership to virtual device %s from physical device %s.\n",
					    name, prvdev->name);
				if(stats) {
					stats->rx_packets++;
				}
				break;
			}
		}
	} else {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "device supplied with skb is NULL\n");
	}

	if(stats == NULL) {
		KLIPS_PRINT((debug_rcv),
			    "klips_error:ipsec_rcv: "
			    "packet received from physical I/F (%s) not connected to ipsec I/F.  Cannot record stats.  May not have SA for decoding.  Is IPSEC traffic expected on this I/F?  Check routing.\n",
			    skb->dev ? (skb->dev->name ? skb->dev->name : "NULL") : "NULL");
	}
		
	KLIPS_IP_PRINT(debug_rcv, ipp);

	/* set up for decap loop */
	irs->stats= stats;
	irs->ipp  = ipp;
	irs->ipsp = NULL;
	irs->ilen = 0;
	irs->authlen=0;
	irs->authfuncs=NULL;
	irs->skb = skb;

	(void)ipsec_rcv_decap(irs);

        ipsec_rcv_state_delete (irs);
        KLIPS_DEC_USE;
	return(0);

rcvleave:
        ipsec_rcv_state_delete (irs);

error_alloc:
error_bad_skb:
        ipsec_kfree_skb(skb);
error_no_skb:

	KLIPS_DEC_USE;
	return(0);

}

#ifdef NET_26
/*
 * this entry point is not a protocol entry point, so the entry
 * is a bit different.
 *
 * skb->iph->tot_len has been byte-swapped, and reduced by the size of
 *              the IP header (and options).
 * 
 * skb->h.raw has been pulled up the ESP header.
 *
 * skb->iph->protocol = 50 IPPROTO_ESP;
 *
 */
int klips26_rcv_encap(struct sk_buff *skb, __u16 encap_type)
{
	struct ipsec_rcv_state *irs = NULL;
	struct iphdr *ipp;

	/* Don't unlink in the middle of a turnaround */
	KLIPS_INC_USE;

        irs = ipsec_rcv_state_new ();
        if (unlikely (! irs)) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "failled to allocate a rcv state object\n");
                goto error_alloc;
        }

	/* XXX fudge it so that all nat-t stuff comes from ipsec0    */
	/*     eventually, the SA itself will determine which device
	 *     it comes from
	 */ 
	{
	  skb->dev = ipsec_get_device(0);
	}

	/* set up for decap loop */
	irs->hard_header_len = skb->dev->hard_header_len;

	skb = ipsec_rcv_unclone(skb, irs);

#if IP_FRAGMENT_LINEARIZE
	/* In Linux 2.4.4, we may have to reassemble fragments. They are
	   not assembled automatically to save TCP from having to copy
	   twice.
	*/
	if (skb_is_nonlinear(skb)) {
#ifdef HAVE_NEW_SKB_LINEARIZE
		if (skb_linearize_cow(skb) != 0) 
#else
		if (skb_linearize(skb, GFP_ATOMIC) != 0) 
#endif
		{
			goto rcvleave;
		}
	}
#endif /* IP_FRAGMENT_LINEARIZE */

	ipp = skb->nh.iph;

	{
	  	struct in_addr ipsaddr;
		struct in_addr ipdaddr;

		ipsaddr.s_addr = ipp->saddr;
		addrtoa(ipsaddr, 0, irs->ipsaddr_txt
			, sizeof(irs->ipsaddr_txt));
		ipdaddr.s_addr = ipp->daddr;
		addrtoa(ipdaddr, 0, irs->ipdaddr_txt
			, sizeof(irs->ipdaddr_txt));
	}

	irs->iphlen = ipp->ihl << 2;

	KLIPS_IP_PRINT(debug_rcv, ipp);

	irs->stats= NULL;
	irs->ipp  = ipp;
	irs->ipsp = NULL;
	irs->ilen = 0;
	irs->authlen=0;
	irs->authfuncs=NULL;
	irs->skb = skb;

#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
	switch(encap_type) {
	case UDP_ENCAP_ESPINUDP:
	  irs->natt_type = ESPINUDP_WITH_NON_ESP;
	  break;
	  
	case UDP_ENCAP_ESPINUDP_NON_IKE:
	  irs->natt_type = ESPINUDP_WITH_NON_IKE;
	  break;
	  
	default:
	  if(printk_ratelimit()) {
	    printk(KERN_INFO "KLIPS received unknown UDP-ESP encap type %u\n",
		   encap_type);
	  }
	  return -1;
	}

#endif
	ipsec_rcv_decap(irs);

	KLIPS_DEC_USE;
        ipsec_rcv_state_delete (irs);
	return 0;

rcvleave:
	if(skb) {
		ipsec_kfree_skb(skb);
	}
        ipsec_rcv_state_delete (irs);
error_alloc:
	KLIPS_DEC_USE;
	return 0;
}
#endif

// ------------------------------------------------------------------------
// this handles creating and managing state for recv path

static spinlock_t irs_cache_lock = SPIN_LOCK_UNLOCKED;
static kmem_cache_t *irs_cache_allocator = NULL;
static unsigned  irs_cache_allocated_count = 0;

int
ipsec_rcv_state_cache_init (void)
{
        if (irs_cache_allocator)
                return -EBUSY;

        spin_lock_init(&irs_cache_lock);

        irs_cache_allocator = kmem_cache_create ("ipsec_irs",
                sizeof (struct ipsec_rcv_state), 0,
                0, NULL, NULL);
        if (! irs_cache_allocator)
                return -ENOMEM;

        return 0;
}

void
ipsec_rcv_state_cache_cleanup (void)
{
        if (unlikely (irs_cache_allocated_count))
                printk ("ipsec: deleting ipsec_irs kmem_cache while in use\n");

        if (irs_cache_allocator) {
                kmem_cache_destroy (irs_cache_allocator);
                irs_cache_allocator = NULL;
        }
        irs_cache_allocated_count = 0;
}

static struct ipsec_rcv_state *
ipsec_rcv_state_new (void)
{
	struct ipsec_rcv_state *irs;

        spin_lock_bh (&irs_cache_lock);

        irs = kmem_cache_alloc (irs_cache_allocator, GFP_ATOMIC);

        if (likely (irs != NULL))
                irs_cache_allocated_count++;

        spin_unlock_bh (&irs_cache_lock);

        if (unlikely (NULL == irs))
                goto bail;

        // initialize the object
        memset((caddr_t)irs, 0, sizeof(*irs));

bail:
        return irs;
}

static void
ipsec_rcv_state_delete (struct ipsec_rcv_state *irs)
{
        if (unlikely (! irs))
                return;

        spin_lock_bh (&irs_cache_lock);

        irs_cache_allocated_count--;
        kmem_cache_free (irs_cache_allocator, irs);

        spin_unlock_bh (&irs_cache_lock);
}

/*
 * $Log: ipsec_rcv.c,v $
 * Revision 1.178  2005/10/21 02:19:34  mcr
 * 	on 2.4 systems, we have to fix up the length as well.
 *
 * Revision 1.171.2.7  2006/04/20 16:33:07  mcr
 * remove all of CONFIG_KLIPS_ALG --- one can no longer build without it.
 * Fix in-kernel module compilation. Sub-makefiles do not work.
 *
 * Revision 1.171.2.6  2005/12/07 06:07:04  paul
 * comment out KLIPS_DEC_USE in ipsec_rcv_decap. Likely an artifact from
 * refactoring. http://bugs.xelerance.com/view.php?id=454
 *
 * Revision 1.171.2.5  2005/10/21 02:22:29  mcr
 * 	pull up of another try at 2.4.x kernel fix
 *
 * Revision 1.171.2.4  2005/10/21 01:39:56  mcr
 *     nat-t fix is 2.4/2.6 specific
 *
 * Revision 1.178  2005/10/21 02:19:34  mcr
 * 	on 2.4 systems, we have to fix up the length as well.
 *
 * Revision 1.177  2005/10/21 00:18:31  mcr
 * 	nat-t fix is 2.4 specific.
 *
 * Revision 1.176  2005/10/20 21:06:11  mcr
 * 	possible fix for nat-t problem on 2.4 kernels.
 *
 * Revision 1.175  2005/10/13 02:49:24  mcr
 * 	tested UDP-encapsulated ESP packets that were not actually ESP,
 * 	(but IKE) were being eaten.
 *
 * Revision 1.174  2005/10/13 01:25:22  mcr
 * 	UDP-encapsulated ESP packets that were not actually ESP,
 * 	(but IKE) were being eaten.
 *
 * Revision 1.173  2005/08/31 23:26:11  mcr
 * 	fixes for 2.6.13
 *
 * Revision 1.172  2005/08/05 08:44:54  mcr
 * 	ipsec_kern24.h (compat code for 2.4) must be include
 * 	explicitely now.
 *
 * Revision 1.171  2005/07/08 23:56:06  ken
 * #ifdef
 *
 * Revision 1.170  2005/07/08 23:50:05  ken
 * Don't attempt to decapsulate if NAT-T isn't available in the code
 *
 * Revision 1.169  2005/06/06 00:27:31  mcr
 * 	fix for making tcpdump (packet capture) work correctly for
 * 	nat-t received packets.
 *
 * Revision 1.168  2005/06/04 16:06:06  mcr
 * 	better patch for nat-t rcv-device code.
 *
 * Revision 1.167  2005/06/03 17:04:46  mcr
 * 	nat-t packets are forced to arrive from ipsec0.
 *
 * Revision 1.166  2005/04/29 05:10:22  mcr
 * 	removed from extraenous includes to make unit testing easier.
 *
 * Revision 1.165  2005/04/20 17:11:32  mcr
 * 	fixed to compile on 2.4.
 *
 * Revision 1.164  2005/04/18 03:09:50  ken
 * Fix typo
 *
 * Revision 1.163  2005/04/17 05:32:58  mcr
 * 	remove extraneous debugging
 * 	make sure to return success from klips26_encap_rcv().
 *
 * Revision 1.162  2005/04/17 04:37:01  mcr
 * 	make sure that irs->ipp is still set.
 *
 * Revision 1.161  2005/04/17 03:51:52  mcr
 * 	removed old comment about removed code.
 * 	added translation from udp.c/2.6 to KLIPS NAT-ESP naming.
 * 	comment about check for origin address/port for incoming NAT-ESP packets.
 *
 * Revision 1.160  2005/04/15 19:55:58  mcr
 * 	adjustments to use proper skb fields for data.
 *
 * Revision 1.159  2005/04/10 22:58:20  mcr
 * 	refactoring of receive functions to make it easier to
 * 	call the ESP decap.
 *
 * Revision 1.158  2005/04/08 18:27:53  mcr
 * 	refactored ipsec_rcv() into ipsec_rcv() and ipsec_rcv_decap().
 *
 * Revision 1.157  2004/12/28 23:13:09  mcr
 * 	use consistent CONFIG_IPSEC_NAT_TRAVERSAL.
 *
 * Revision 1.156  2004/12/03 21:34:51  mcr
 * 	mistype of KLIPS_USE_COUNT -> KLIPS_INC_USE;
 *
 * Revision 1.155  2004/12/03 21:25:57  mcr
 * 	compile time fixes for running on 2.6.
 * 	still experimental.
 *
 * Revision 1.154  2004/09/08 17:21:36  ken
 * Rename MD5* -> osMD5 functions to prevent clashes with other symbols exported by kernel modules (CIFS in 2.6 initiated this)
 *
 * Revision 1.153  2004/08/22 20:10:00  mcr
 * 	removed check for incorrect setting of NET_26.
 *
 * Revision 1.152  2004/08/21 15:22:39  mcr
 * 	added #defines for ATT heartbeat.
 *
 * Revision 1.151  2004/08/21 02:16:32  ken
 * Patch from Jochen Eisinger for AT&T MTS Heartbeat packet support
 *
 * Revision 1.150  2004/08/21 00:44:48  mcr
 * 	CONFIG_KLIPS_NAT was wrong, also need to include udp.h.
 *
 * Revision 1.149  2004/08/20 21:45:45  mcr
 * 	CONFIG_KLIPS_NAT_TRAVERSAL is not used in an attempt to
 * 	be 26sec compatible. But, some defines where changed.
 *
 * Revision 1.148  2004/08/17 03:27:23  mcr
 * 	klips 2.6 edits.
 *
 * Revision 1.147  2004/08/05 23:29:27  mcr
 * 	fixed nesting of #ifdef vs {} in ipsec_rcv().
 *
 * Revision 1.146  2004/08/04 15:57:07  mcr
 * 	moved des .h files to include/des/ *
 * 	included 2.6 protocol specific things
 * 	started at NAT-T support, but it will require a kernel patch.
 *
 * Revision 1.145  2004/08/03 18:19:08  mcr
 * 	in 2.6, use "net_device" instead of #define device->net_device.
 * 	this probably breaks 2.0 compiles.
 *
 * Revision 1.144  2004/07/10 19:11:18  mcr
 * 	CONFIG_IPSEC -> CONFIG_KLIPS.
 *
 * Revision 1.143  2004/05/10 22:27:00  mcr
 * 	fix for ESP-3DES-noauth test case.
 *
 * Revision 1.142  2004/05/10 22:25:57  mcr
 * 	reformat of calls to ipsec_lifetime_check().
 *
 * Revision 1.141  2004/04/06 02:49:26  mcr
 * 	pullup of algo code from alg-branch.
 *
 * Revision 1.140  2004/02/03 03:12:53  mcr
 * 	removed erroneously, double patched code.
 *
 * Revision 1.139  2004/01/05 23:21:29  mcr
 * 	initialize sin_family in ipsec_rcv.c
 *
 * Revision 1.138  2003/12/24 19:46:52  mcr
 * 	if sock.h patch has not been applied, then define appropriate
 * 	structure so we can use it. This is serious inferior, and
 * 	depends upon the concept that the structure in question is
 * 	smaller than the other members of that union.
 * 	getting rid of differing methods is a better solution.
 *
 * Revision 1.137  2003/12/22 19:40:57  mcr
 * 	NAT-T patches 0.6c.
 *
 * Revision 1.136  2003/12/15 18:13:12  mcr
 * 	when compiling with NAT traversal, don't assume that the
 * 	kernel has been patched, unless CONFIG_IPSEC_NAT_NON_ESP
 * 	is set.
 *
 * Revision 1.135  2003/12/13 19:10:21  mcr
 * 	refactored rcv and xmit code - same as FS 2.05.
 *
 * Revision 1.134.2.1  2003/12/22 15:25:52  jjo
 *      Merged algo-0.8.1-rc11-test1 into alg-branch
 *
 * Revision 1.134  2003/12/10 01:14:27  mcr
 * 	NAT-traversal patches to KLIPS.
 *
 * Revision 1.133  2003/10/31 02:27:55  mcr
 * 	pulled up port-selector patches and sa_id elimination.
 *
 * Revision 1.132.2.1  2003/10/29 01:30:41  mcr
 * 	elimited "struct sa_id".
 *
 * Revision 1.132  2003/09/02 19:51:48  mcr
 * 	fixes for PR#252.
 *
 * Revision 1.131  2003/07/31 22:47:16  mcr
 * 	preliminary (untested by FS-team) 2.5 patches.
 *
 * Revision 1.130  2003/04/03 17:38:25  rgb
 * Centralised ipsec_kfree_skb and ipsec_dev_{get,put}.
 * Clarified logic for non-connected devices.
 *
 * Revision 1.129  2003/02/06 02:21:34  rgb
 *
 * Moved "struct auth_alg" from ipsec_rcv.c to ipsec_ah.h .
 * Changed "struct ah" to "struct ahhdr" and "struct esp" to "struct esphdr".
 * Removed "#ifdef INBOUND_POLICY_CHECK_eroute" dead code.
 *
 * Revision 1.128  2002/12/13 20:58:03  rgb
 * Relegated MCR's recent "_dmp" routine to debug_verbose.
 * Cleaned up printing of source and destination addresses in debug output.
 *
 * Revision 1.127  2002/12/04 16:00:16  rgb
 *
 * Fixed AH decapsulation pointer update bug and added some comments and
 * debugging.
 * This bug was caught by west-ah-0[12].
 *
 * Revision 1.126  2002/11/04 05:03:43  mcr
 * 	fixes for IPCOMP. There were two problems:
 * 	1) the irs->ipp pointer was not being updated properly after
 * 	   the ESP descryption. The meant nothing for IPIP, as the
 * 	   later IP header overwrote the earlier one.
 *  	2) the more serious problem was that skb_decompress will
 * 	   usually allocate a new SKB, so we have to make sure that
 * 	   it doesn't get lost.
 * 	#2 meant removing the skb argument from the ->decrypt routine
 * 	and moving it to the irs->skb, so it could be value/result.
 *
 * Revision 1.125  2002/11/01 01:53:35  dhr
 *
 * fix typo
 *
 * Revision 1.124  2002/10/31 22:49:01  dhr
 *
 * - eliminate unused variable "hash"
 * - reduce scope of variable "authenticator"
 * - add comment on a couple of tricky bits
 *
 * Revision 1.123  2002/10/31 22:39:56  dhr
 *
 * use correct type for result of function calls
 *
 * Revision 1.122  2002/10/31 22:36:25  dhr
 *
 * simplify complex test
 *
 * Revision 1.121  2002/10/31 22:34:04  dhr
 *
 * ipsprev is never used: ditch it
 *
 * Revision 1.120  2002/10/31 22:30:21  dhr
 *
 * eliminate redundant assignments
 *
 * Revision 1.119  2002/10/31 22:27:43  dhr
 *
 * make whitespace canonical
 *
 * Revision 1.118  2002/10/30 05:47:17  rgb
 * Fixed cut-and-paste error mis-identifying comp runt as ah.
 *
 * Revision 1.117  2002/10/17 16:37:45  rgb
 * Remove compp intermediate variable and in-line its contents
 * where used
 *
 * Revision 1.116  2002/10/12 23:11:53  dhr
 *
 * [KenB + DHR] more 64-bit cleanup
 *
 * Revision 1.115  2002/10/07 19:06:58  rgb
 * Minor fixups and activation to west-rcv-nfmark-set-01 test to check for SA reference properly set on incoming.
 *
 * Revision 1.114  2002/10/07 18:31:31  rgb
 * Set saref on incoming packets.
 *
 * Revision 1.113  2002/09/16 21:28:12  mcr
 * 	adjust hash length for HMAC calculation - must look at whether
 * 	it is MD5 or SHA1.
 *
 * Revision 1.112  2002/09/16 21:19:15  mcr
 * 	fixes for west-ah-icmp-01 - length of AH header must be
 * 	calculated properly, and next_header field properly copied.
 *
 * Revision 1.111  2002/09/10 02:45:56  mcr
 * 	re-factored the ipsec_rcv function into several functions,
 * 	ipsec_rcv_decap_once, and a set of functions for AH, ESP and IPCOMP.
 * 	In addition, the MD5 and SHA1 functions are replaced with pointers.
 *
 * Revision 1.110  2002/08/30 06:34:33  rgb
 * Fix scope of shift in AH header length check.
 *
 * Revision 1.109  2002/08/27 16:49:20  rgb
 * Fixed ESP short packet DOS (and AH and IPCOMP).
 *
 * Revision 1.108  2002/07/24 18:44:54  rgb
 * Type fiddling to tame ia64 compiler.
 *
 * Revision 1.107  2002/05/27 18:58:18  rgb
 * Convert to dynamic ipsec device allocation.
 * Remove final vistiges of tdb references via IPSEC_KLIPS1_COMPAT.
 *
 * Revision 1.106  2002/05/23 07:15:21  rgb
 * Pointer clean-up.
 * Added refcount code.
 *
 * Revision 1.105  2002/05/14 02:35:06  rgb
 * Change all references to tdb, TDB or Tunnel Descriptor Block to ips,
 * ipsec_sa or ipsec_sa.
 * Change references to _TDB to _IPSA.
 *
 * Revision 1.104  2002/04/24 07:55:32  mcr
 * 	#include patches and Makefiles for post-reorg compilation.
 *
 * Revision 1.103  2002/04/24 07:36:30  mcr
 * Moved from ./klips/net/ipsec/ipsec_rcv.c,v
 *
 * Revision 1.102  2002/01/29 17:17:56  mcr
 * 	moved include of ipsec_param.h to after include of linux/kernel.h
 * 	otherwise, it seems that some option that is set in ipsec_param.h
 * 	screws up something subtle in the include path to kernel.h, and
 * 	it complains on the snprintf() prototype.
 *
 * Revision 1.101  2002/01/29 04:00:52  mcr
 * 	more excise of kversions.h header.
 *
 * Revision 1.100  2002/01/29 02:13:17  mcr
 * 	introduction of ipsec_kversion.h means that include of
 * 	ipsec_param.h must preceed any decisions about what files to
 * 	include to deal with differences in kernel source.
 *
 * Revision 1.99  2002/01/28 21:40:59  mcr
 * 	should use #if to test boolean option rather than #ifdef.
 *
 * Revision 1.98  2002/01/20 20:19:36  mcr
 * 	renamed option to IP_FRAGMENT_LINEARIZE.
 *
 * Revision 1.97  2002/01/12 02:55:36  mcr
 * 	fix for post-2.4.4 to linearize skb's when ESP packet
 * 	was assembled from fragments.
 *
 * Revision 1.96  2001/11/26 09:23:49  rgb
 * Merge MCR's ipsec_sa, eroute, proc and struct lifetime changes.
 *
 * Revision 1.93.2.2  2001/10/22 20:54:07  mcr
 * 	include des.h, removed phony prototypes and fixed calling
 * 	conventions to match real prototypes.
 *
 * Revision 1.93.2.1  2001/09/25 02:22:22  mcr
 * 	struct tdb -> struct ipsec_sa.
 * 	lifetime checks moved to ipsec_life.c
 * 	some sa(tdb) manipulation functions renamed.
 *
 * Revision 1.95  2001/11/06 19:49:07  rgb
 * Added variable descriptions.
 * Removed unauthenticated sequence==0 check to prevent DoS.
 *
 * Revision 1.94  2001/10/18 04:45:20  rgb
 * 2.4.9 kernel deprecates linux/malloc.h in favour of linux/slab.h,
 * lib/freeswan.h version macros moved to lib/kversions.h.
 * Other compiler directive cleanups.
 *
 * Revision 1.93  2001/09/07 22:17:24  rgb
 * Fix for removal of transport layer protocol handler arg in 2.4.4.
 * Fix to accomodate peer non-conformance to IPCOMP rfc2393.
 *
 * Revision 1.92  2001/08/27 19:44:41  rgb
 * Fix error in comment.
 *
 * Revision 1.91  2001/07/20 19:31:48  dhr
 * [DHR] fix source and destination subnets of policy in diagnostic
 *
 * Revision 1.90  2001/07/06 19:51:09  rgb
 * Added inbound policy checking code for IPIP SAs.
 * Renamed unused function argument for ease and intuitive naming.
 *
 * Revision 1.89  2001/06/22 19:35:23  rgb
 * Disable ipcomp processing if we are handed a ipcomp packet with no esp
 * or ah header.
 * Print protocol if we are handed a non-ipsec packet.
 *
 * Revision 1.88  2001/06/20 06:30:47  rgb
 * Fixed transport mode IPCOMP policy check bug.
 *
 * Revision 1.87  2001/06/13 20:58:40  rgb
 * Added parentheses around assignment used as truth value to silence
 * compiler.
 *
 * Revision 1.86  2001/06/07 22:25:23  rgb
 * Added a source address policy check for tunnel mode.  It still does
 * not check client addresses and masks.
 * Only decapsulate IPIP if it is expected.
 *
 * Revision 1.85  2001/05/30 08:14:02  rgb
 * Removed vestiges of esp-null transforms.
 *
 * Revision 1.84  2001/05/27 06:12:11  rgb
 * Added structures for pid, packet count and last access time to eroute.
 * Added packet count to beginning of /proc/net/ipsec_eroute.
 *
 * Revision 1.83  2001/05/04 16:45:47  rgb
 * Remove unneeded code.  ipp is not used after this point.
 *
 * Revision 1.82  2001/05/04 16:36:00  rgb
 * Fix skb_cow() call for 2.4.4. (SS)
 *
 * Revision 1.81  2001/05/02 14:46:53  rgb
 * Fix typo for compiler directive to pull IPH back.
 *
 * Revision 1.80  2001/04/30 19:46:34  rgb
 * Update for 2.4.4.  We now receive the skb with skb->data pointing to
 * h.raw.
 *
 * Revision 1.79  2001/04/23 15:01:15  rgb
 * Added spin_lock() check to prevent double-locking for multiple
 * transforms and hence kernel lock-ups with SMP kernels.
 * Minor spin_unlock() adjustments to unlock before non-dependant prints
 * and IPSEC device stats updates.
 *
 * Revision 1.78  2001/04/21 23:04:24  rgb
 * Check if soft expire has already been sent before sending another to
 * prevent ACQUIRE flooding.
 *
 * Revision 1.77  2001/03/16 07:35:20  rgb
 * Ditch extra #if 1 around now permanent policy checking code.
 *
 * Revision 1.76  2001/02/27 22:24:54  rgb
 * Re-formatting debug output (line-splitting, joining, 1arg/line).
 * Check for satoa() return codes.
 *
 * Revision 1.75  2001/02/19 22:28:30  rgb
 * Minor change to virtual device discovery code to assert which I/F has
 * been found.
 *
 * Revision 1.74  2000/11/25 03:50:36  rgb
 * Oops fix by minor re-arrangement of code to avoid accessing a freed tdb.
 *
 * Revision 1.73  2000/11/09 20:52:15  rgb
 * More spinlock shuffling, locking earlier and unlocking later in rcv to
 * include ipcomp and prevent races, renaming some tdb variables that got
 * forgotten, moving some unlocks to include tdbs and adding a missing
 * unlock.  Thanks to Svenning for some of these.
 *
 * Revision 1.72  2000/11/09 20:11:22  rgb
 * Minor shuffles to fix non-standard kernel config option selection.
 *
 * Revision 1.71  2000/11/06 04:36:18  rgb
 * Ditched spin_lock_irqsave in favour of spin_lock.
 * Minor initial protocol check rewrite.
 * Clean up debug printing.
 * Clean up tdb handling on ipcomp.
 * Fixed transport mode null pointer de-reference without ipcomp.
 * Add Svenning's adaptive content compression.
 * Disabled registration of ipcomp handler.
 *
 * Revision 1.70  2000/10/30 23:41:43  henry
 * Hans-Joerg Hoexer's null-pointer fix
 *
 * Revision 1.69  2000/10/10 18:54:16  rgb
 * Added a fix for incoming policy check with ipcomp enabled but
 * uncompressible.
 *
 * Revision 1.68  2000/09/22 17:53:12  rgb
 * Fixed ipcomp tdb pointers update for policy checking.
 *
 * Revision 1.67  2000/09/21 03:40:58  rgb
 * Added more debugging to try and track down the cpi outward copy problem.
 *
 * Revision 1.66  2000/09/20 04:00:10  rgb
 * Changed static functions to DEBUG_NO_STATIC to reveal function names for
 * debugging oopsen.
 *
 * Revision 1.65  2000/09/19 07:07:16  rgb
 * Added debugging to inbound policy check for ipcomp.
 * Added missing spin_unlocks (thanks Svenning!).
 * Fixed misplaced tdbnext pointers causing mismatched ipip policy check.
 * Protect ipcomp policy check following ipip decap with sysctl switch.
 *
 * Revision 1.64  2000/09/18 21:27:29  rgb
 * 2.0 fixes.
 *
 * Revision 1.63  2000/09/18 02:35:50  rgb
 * Added policy checking to ipcomp and re-enabled policy checking by
 * default.
 * Optimised satoa calls.
 *
 * Revision 1.62  2000/09/17 21:02:32  rgb
 * Clean up debugging, removing slow timestamp debug code.
 *
 * Revision 1.61  2000/09/16 01:07:55  rgb
 * Fixed erroneous ref from struct ipcomp to struct ipcomphdr.
 *
 * Revision 1.60  2000/09/15 11:37:01  rgb
 * Merge in heavily modified Svenning Soerensen's <svenning@post5.tele.dk>
 * IPCOMP zlib deflate code.
 *
 * Revision 1.59  2000/09/15 04:56:20  rgb
 * Remove redundant satoa() call, reformat comment.
 *
 * Revision 1.58  2000/09/13 08:00:52  rgb
 * Flick on inbound policy checking.
 *
 * Revision 1.57  2000/09/12 03:22:19  rgb
 * Converted inbound_policy_check to sysctl.
 * Re-enabled policy backcheck.
 * Moved policy checks to top and within tdb lock.
 *
 * Revision 1.56  2000/09/08 19:12:56  rgb
 * Change references from DEBUG_IPSEC to CONFIG_IPSEC_DEBUG.
 *
 * Revision 1.55  2000/08/28 18:15:46  rgb
 * Added MB's nf-debug reset patch.
 *
 * Revision 1.54  2000/08/27 01:41:26  rgb
 * More minor tweaks to the bad padding debug code.
 *
 * Revision 1.53  2000/08/24 16:54:16  rgb
 * Added KLIPS_PRINTMORE macro to continue lines without KERN_INFO level
 * info.
 * Tidied up device reporting at the start of ipsec_rcv.
 * Tidied up bad padding debugging and processing.
 *
 * Revision 1.52  2000/08/20 21:36:03  rgb
 * Activated pfkey_expire() calls.
 * Added a hard/soft expiry parameter to pfkey_expire().
 * Added sanity checking to avoid propagating zero or smaller-length skbs
 * from a bogus decryption.
 * Re-arranged the order of soft and hard expiry to conform to RFC2367.
 * Clean up references to CONFIG_IPSEC_PFKEYv2.
 *
 * Revision 1.51  2000/08/18 21:23:30  rgb
 * Improve bad padding warning so that the printk buffer doesn't get
 * trampled.
 *
 * Revision 1.50  2000/08/01 14:51:51  rgb
 * Removed _all_ remaining traces of DES.
 *
 * Revision 1.49  2000/07/28 13:50:53  rgb
 * Changed enet_statistics to net_device_stats and added back compatibility
 * for pre-2.1.19.
 *
 * Revision 1.48  2000/05/10 19:14:40  rgb
 * Only check usetime against soft and hard limits if the tdb has been
 * used.
 * Cast output of ntohl so that the broken prototype doesn't make our
 * compile noisy.
 *
 * Revision 1.47  2000/05/09 17:45:43  rgb
 * Fix replay bitmap corruption bug upon receipt of bogus packet
 * with correct SPI.  This was a DoS.
 *
 * Revision 1.46  2000/03/27 02:31:58  rgb
 * Fixed authentication failure printout bug.
 *
 * Revision 1.45  2000/03/22 16:15:37  rgb
 * Fixed renaming of dev_get (MB).
 *
 * Revision 1.44  2000/03/16 08:17:24  rgb
 * Hardcode PF_KEYv2 support.
 * Fixed minor bug checking AH header length.
 *
 * Revision 1.43  2000/03/14 12:26:59  rgb
 * Added skb->nfct support for clearing netfilter conntrack bits (MB).
 *
 * Revision 1.42  2000/01/26 10:04:04  rgb
 * Fixed inbound policy checking on transport mode bug.
 * Fixed noisy 2.0 printk arguments.
 *
 * Revision 1.41  2000/01/24 20:58:02  rgb
 * Improve debugging/reporting support for (disabled) inbound
 * policy checking.
 *
 * Revision 1.40  2000/01/22 23:20:10  rgb
 * Fixed up inboud policy checking code.
 * Cleaned out unused crud.
 *
 * Revision 1.39  2000/01/21 06:15:29  rgb
 * Added sanity checks on skb_push(), skb_pull() to prevent panics.
 * Fixed cut-and-paste debug_tunnel to debug_rcv.
 * Added inbound policy checking code, disabled.
 * Simplified output code by updating ipp to post-IPIP decapsulation.
 *
 * elided pre-2000 comments. Use "cvs log"
 *
 *
 * Local Variables:
 * c-set-style: linux
 * End:
 *
 */
