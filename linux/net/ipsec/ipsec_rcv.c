/*
 * receive code
 * Copyright (C) 1996, 1997  John Ioannidis.
 * Copyright (C) 1998-2003   Richard Guy Briggs.
 * Copyright (C) 2004-2007   Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007-2008   Paul Wouters <paul@xelerance.com>
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

#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
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
#include <net/xfrm.h>
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
#include "openswan/ipsec_mast.h"
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

static inline void ipsec_rcv_redodebug(struct ipsec_rcv_state *irs)
{
	struct iphdr * ipp = irs->ipp;
	struct in_addr ipsaddr, ipdaddr;

	ipsaddr.s_addr = ipp->saddr;
	addrtoa(ipsaddr, 0, irs->ipsaddr_txt, sizeof(irs->ipsaddr_txt));
	ipdaddr.s_addr = ipp->daddr;
	addrtoa(ipdaddr, 0, irs->ipdaddr_txt, sizeof(irs->ipdaddr_txt));
}
		
/*
 * look up the SA from the said in the header.
 *
 */
enum ipsec_rcv_value
ipsec_rcv_decap_lookup(struct ipsec_rcv_state *irs
		       , struct xform_functions *proto_funcs
		       , struct ipsec_sa **pnewipsp)
{
	__u8 proto;
	struct ipsec_sa *newipsp;
	struct iphdr *ipp;
	struct sk_buff *skb;

	skb      = irs->skb;
	ipp      = irs->ipp;
	proto    = ipp->protocol;

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
			KLIPS_ERROR(debug_rcv,
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
		 * at this point, we have looked up a new SA, and we want to
		 * make sure that if this isn't the first SA in the list,
		 * that the previous SA actually points at this one.
		 */
		if(irs->ipsp) {
			if(irs->ipsp->ips_next != newipsp) {
				KLIPS_ERROR(debug_rcv,
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

	/* *pnewipsp = newipsp; */
	if (newipsp != *pnewipsp) {
		    if(irs->lastipsp) {
			ipsec_sa_put(irs->lastipsp);
		    }
		    irs->lastipsp = irs->ipsp;
		    irs->ipsp=newipsp;
	} else {
		    /* we already have a refcount for it */
		    ipsec_sa_put(newipsp);
	}

	return IPSEC_RCV_OK;
}

void ip_cmsg_recv_ipsec(struct msghdr *msg, struct sk_buff *skb)
{
	struct ipsec_sa *sa1;
	struct sec_path *sp;
	xfrm_sec_unique_t refs[2];

	sp = skb->sp;

	if(sp==NULL) return;

	KLIPS_PRINT(debug_rcv, "retrieving saref=%u from skb=%p\n",
		    sp->ref, skb);

	sa1 = ipsec_sa_getbyref(sp->ref);
	if(sa1) {
		refs[1]= sa1->ips_refhim;
	} else {
		refs[1]=0;
	}
	refs[0]=sp->ref;

	put_cmsg(msg, SOL_IP, IP_IPSEC_REFINFO,
		 sizeof(xfrm_sec_unique_t)*2, &refs);
	if (sa1) {
		ipsec_sa_put(sa1);
	}
}

		       
/*
 * decapsulate a single layer of ESP/AH/IPCOMP.
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
	struct ipsec_sa* ipsnext = NULL; /* next SA towards inside of packet */
	int    replay = 0;	         /* replay value in AH or ESP packet */
	struct iphdr *ipp;
	struct sk_buff *skb;
	struct ipsec_alg_auth *ixt_a=NULL;

	skb      = irs->skb;
	irs->len = skb->len;
	ipp      = irs->ipp;
	proto    = ipp->protocol;
	ipsec_rcv_redodebug(irs);

	iphlen   = ipp->ihl << 2;
	irs->iphlen=iphlen;
	ipp->check= 0;			/* we know the sum is good */
	
	/* note: rcv_checks set up the said.spi value, if appropriate */
	if(proto_funcs->rcv_checks) {
		enum ipsec_rcv_value retval =
		  (*proto_funcs->rcv_checks)(irs, skb);

		if(retval < 0) {
			return retval;
		}
	}

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
	irs->ilen = ((irs->skb->data + irs->skb->len) - skb_transport_header(irs->skb)) - irs->authlen;
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
			KLIPS_ERROR(debug_rcv & DB_RX_INAU,
				    "klips_debug:ipsec_rcv: "
				    "auth failed on incoming packet from %s (replay=%d): calculated hash=%08x%08x%08x received hash=%08x%08x%08x, dropped\n",
				    irs->ipsaddr_txt,
				    replay,
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

			KLIPS_ERROR(debug_rcv,
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
			KLIPS_ERROR(debug_rcv & DB_RX_REPLAY,
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
	ipp = irs->ipp = ip_hdr(skb);
	irs->iphlen = ipp->ihl<<2;
	skb_set_transport_header(skb, ipsec_skb_offset(skb, skb_network_header(skb) + irs->iphlen));
	
	/* zero any options that there might be */
	memset(&(IPCB(skb)->opt), 0, sizeof(struct ip_options));
	ipsec_rcv_redodebug(irs);

	/*
	 *	Discard the original ESP/AH header
	 */
	ipp->protocol = irs->next_header;

	ipp->check = 0;	/* NOTE: this will be included in checksum */
	ipp->check = ip_fast_csum((unsigned char *)ip_hdr(skb), irs->iphlen >> 2);

	KLIPS_PRINT(debug_rcv & DB_RX_PKTRX,
		    "klips_debug:ipsec_rcv: "
		    "after <%s%s%s>, SA:%s:\n",
		    IPS_XFORM_NAME(irs->ipsp),
		    irs->sa_len ? irs->sa : " (error)");
	KLIPS_IP_PRINT(debug_rcv & DB_RX_PKTRX, ipp);

	skb->protocol = htons(ETH_P_IP);
	skb->ip_summed = 0;

	ipsnext = irs->ipsp->ips_next;
	if(sysctl_ipsec_inbound_policy_check) {
		if(ipsnext) {
			if(
				ipp->protocol != IPPROTO_AH
				&& ipp->protocol != IPPROTO_ESP
#ifdef CONFIG_KLIPS_IPCOMP
				&& ipp->protocol != IPPROTO_COMP
				&& (ipsnext->ips_said.proto != IPPROTO_COMP
				    || ipsnext->ips_next)
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

void ipsec_rcv_setoutif(struct ipsec_rcv_state *irs)
{
	struct sk_buff *skb = irs->skb;

	if(skb!=NULL && irs->ipsp->ips_out) {
		if(skb->dev != irs->ipsp->ips_out) {
			KLIPS_PRINT(debug_rcv,
				    "changing originating interface from %s to %s\n",
				    skb->dev->name,
				    irs->ipsp->ips_out->name);
		}
		skb->dev = irs->ipsp->ips_out;
		
		if(skb->dev && skb->dev->get_stats) {
			struct net_device_stats *stats = skb->dev->get_stats(skb->dev);
			irs->stats = stats;
		}
	} 
}

static enum ipsec_rcv_value
ipsec_rcv_decap_ipip(struct ipsec_rcv_state *irs)
{
	struct ipsec_sa *ipsp;
	struct ipsec_sa* ipsnext = NULL;
	struct iphdr *ipp;
	struct sk_buff *skb;
	enum ipsec_rcv_value result = IPSEC_RCV_DECAPFAIL;

	ipp  = irs->ipp;
	ipsp = irs->ipsp;
	skb  = irs->skb;
	irs->sa_len = satot(&irs->said, 0, irs->sa, sizeof(irs->sa));
	if((ipp->protocol != IPPROTO_IPIP) && 
	   (ipp->protocol != IPPROTO_ATT_HEARTBEAT)) {  /* AT&T heartbeats to SIG/GIG */
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
		if((ipsnext = ipsp->ips_next)) {
			char sa2[SATOT_BUF];
			size_t sa_len2;
			sa_len2 = satot(&ipsnext->ips_said, 0, sa2, sizeof(sa2));
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
	
	ipsec_rcv_setoutif(irs);

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
		skb_pull(skb, (skb_transport_header(skb) - skb_network_header(skb)));
		
		/* new L3 header is where L4 payload was */
		skb_set_network_header(skb, ipsec_skb_offset(skb, skb_transport_header(skb)));
		
		/* now setup new L4 payload location */
		ipp = (struct iphdr *)skb_network_header(skb);
		skb_set_transport_header(skb, ipsec_skb_offset(skb, skb_network_header(skb) + (ipp->ihl << 2)));

		
		/* remove any saved options that we might have,
		 * since we have a new IP header.
		 */
		memset(&(IPCB(skb)->opt), 0, sizeof(struct ip_options));
		
#if 0
		KLIPS_PRINT(debug_rcv, "csum: %d\n", ip_fast_csum((u8 *)ipp, ipp->ihl));
#endif
		
		/* re-do any strings for debugging */
		irs->ipp = ipp;
                ipsec_rcv_redodebug(irs);

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

	result = IPSEC_RCV_OK;

rcvleave:
	return result;
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
enum ipsec_rcv_value
ipsec_rcv_decap(struct ipsec_rcv_state *irs)
{
	struct iphdr *ipp;
	struct sk_buff *skb = NULL;
	struct ipsec_sa *lastipsp;
	enum ipsec_rcv_value irv;
	struct xform_functions *proto_funcs;
	int decap_stat;

	lastipsp=NULL;

	/* begin decapsulating loop here */

	/*
	  The spinlock is to prevent any other process from
	  accessing or deleting the ipsec_sa hash table or any of the
	  ipsec_sa s while we are using and updating them.
	*/

	/* probably can go away now */
	spin_lock(&tdb_lock);

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

	/* look up the first SA -- we need the protocol functions to figure
	 * out how to do that.
	 */
	{
		struct ipsec_sa *newipsp;
		/* look up the first SA */
		irv = ipsec_rcv_decap_lookup(irs, proto_funcs, &newipsp);
		if(irv != IPSEC_RCV_OK) {
			return irv;
		}
		
		/* newipsp is already referenced by the get() function */
		irs->ipsp=newipsp;
	}

	do {
		ipsec_rcv_setoutif(irs);

		proto_funcs = irs->ipsp->ips_xformfuncs;
		if(proto_funcs == NULL) {
			decap_stat = IPSEC_RCV_BADPROTO;
			goto rcvleave;
		}

		if(proto_funcs->protocol != irs->ipp->protocol) {
			if(proto_funcs->protocol == IPPROTO_COMP) {
                                /* loops like an IPCOMP that we can skip */
				goto skipipcomp;
			}
				
			if(irs->stats) {
				irs->stats->rx_errors++;
			}
			decap_stat = IPSEC_RCV_FAILEDINBOUND;
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

		/* okay, acted on this SA, so free any previous SA, and record a new one*/
		skipipcomp:
		if(irs->ipsp) {
			struct ipsec_sa *newipsp;
			newipsp = irs->ipsp->ips_next;
			if(newipsp) {
				ipsec_sa_get(newipsp);
			}
			if(lastipsp) {
				ipsec_sa_put(lastipsp);
			}
			lastipsp = irs->ipsp;
			irs->ipsp=newipsp;
		}

	/* end decapsulation loop here */
	} while((irs->ipp->protocol == IPPROTO_ESP 
		 || irs->ipp->protocol == IPPROTO_AH  
		 || irs->ipp->protocol == IPPROTO_COMP)
		&& irs->ipsp != NULL);

	/* end of decap loop */
	ipp  =irs->ipp;
	skb = irs->skb;

	/*
	 * if there is an IPCOMP, but we didn't process it,
	 * then we can just skip it
	 */
#ifdef CONFIG_KLIPS_IPCOMP
	if(irs->ipsp && irs->ipsp->ips_said.proto == IPPROTO_COMP) {
			struct ipsec_sa *newipsp = NULL;
			newipsp = irs->ipsp->ips_next;
			if(newipsp) {
				ipsec_sa_get(newipsp);
			}
			if(lastipsp) {
				ipsec_sa_put(lastipsp);
			}
			lastipsp = irs->ipsp;
			irs->ipsp=newipsp;
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
		__u32 natt_oa = lastipsp->ips_natt_oa ?
			((struct sockaddr_in*)(lastipsp->ips_natt_oa))->sin_addr.s_addr : 0;
		
		if(natt_oa != 0) {
			/* reset source address to what it was before NAT */
			ipp->saddr = natt_oa;
			ipp->check = 0;
			ipp->check = ip_fast_csum((unsigned char *)ipp, ipp->ihl);
			KLIPS_PRINT(debug_rcv, "csum: %04x\n", ipp->check);
		}
	}
#endif

	/*
	 * the SA is still locked from the loop
	 */
	if(irs->ipsp && irs->ipsp->ips_xformfuncs->protocol == IPPROTO_IPIP) {
		enum ipsec_rcv_value decap_stat;

		decap_stat = ipsec_rcv_decap_ipip(irs);
		if(decap_stat != IPSEC_RCV_OK) {
			spin_unlock(&tdb_lock);
			goto rcvleave;
		}
	}

	spin_unlock(&tdb_lock);

	if(irs->stats) {
		irs->stats->rx_bytes += skb->len;
	}

	/*
	 * if we are supposed to return the packet directly to the transport
	 * layer, then dump it out correctly.
	 */
	if(lastipsp->ips_transport_direct) {
		KLIPS_PRINT(debug_rcv, "receiving packet as transport direct\n");
		skb->ip_summed=CHECKSUM_UNNECESSARY;
		/* STUFF */
	}
	
	if(skb->sp) {
		secpath_put(skb->sp);
	}
	skb->sp = secpath_dup(NULL);
	skb->sp->ref = lastipsp->ips_ref;

	/* release the dst that was attached, since we have likely
	 * changed the actual destination of the packet.
	 */
	if(skb->dst) {
		dst_release(skb->dst);
		skb->dst = NULL;
	}
	skb->pkt_type = PACKET_HOST;
	if(irs->hard_header_len &&
	   (skb_mac_header(skb) != (skb_network_header(skb) - irs->hard_header_len)) &&
	   (irs->hard_header_len <= skb_headroom(skb))) {
		/* copy back original MAC header */
		memmove(skb_network_header(skb) - irs->hard_header_len,
			skb_mac_header(skb), irs->hard_header_len);
		skb_set_mac_header(skb, ipsec_skb_offset(skb, skb_network_header(skb) - irs->hard_header_len));
	}

	/*
	 * make sure that data now starts at IP header, since we are going
	 * to pass this back to ip_input (aka netif_rx). Rules for what the
	 * pointers wind up a different for 2.6 vs 2.4, so we just fudge it here.
	 */
#ifdef NET_26
	irs->skb->data = skb_push(irs->skb, skb_transport_header(irs->skb) - skb_network_header(irs->skb));
#else
	irs->skb->data = skb_network_header(irs->skb);
	{
	  struct iphdr *iph = ip_hdr(irs->skb);
	  int len = ntohs(iph->tot_len);
	  irs->skb->len  = len;
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
		    "netif_rx(%s) called.\n", skb->dev->name);
	netif_rx(skb);
	skb=NULL;

 rcvleave:
	if(lastipsp) {
		ipsec_sa_put(lastipsp);
		lastipsp=NULL;
	}
	if(irs->ipsp) {
		ipsec_sa_put(irs->ipsp);
	}
	irs->ipsp=NULL;

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
	struct ipsec_rcv_state *irs = NULL;
	struct iphdr *ipp;
	int i;

	/* Don't unlink in the middle of a turnaround */
	KLIPS_INC_USE;

	irs = ipsec_rcv_state_new ();
	if (unlikely (! irs)) {
		KLIPS_PRINT(debug_rcv,
			   "klips_debug:ipsec_rcv: "
			    "failled to allocate a rcv state object\n");
		goto rcvleave;
	}

	if (skb == NULL) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "NULL skb passed in.\n");
		goto rcvleave;
	}

	if (skb->data == NULL) {
		KLIPS_PRINT(debug_rcv,
			    "klips_debug:ipsec_rcv: "
			    "NULL skb->data passed in, packet is bogus, dropping.\n");
		goto rcvleave;
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
			if (irs) {
				ipsec_rcv_state_delete(irs);
			}
			KLIPS_DEC_USE;
			return(udp_decap_ret);
		}
		skb = nskb;
	}
#endif /* NAT_T */

	/* dev->hard_header_len is unreliable and should not be used */
	/* klips26_rcv_encap will have already set hard_header_len for us?? */
	if (irs->hard_header_len == 0) {
		irs->hard_header_len = skb_mac_header(skb) ? (skb_network_header(skb) - skb_mac_header(skb)) : 0;
		if((irs->hard_header_len < 0) || (irs->hard_header_len > skb_headroom(skb)))
			irs->hard_header_len = 0;
	}

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
			    "removing %d bytes from ESPinUDP packet\n"
			    , irs->natt_len);

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

	/* ipp = skb->nh.iph; */
	ipp = ip_hdr(skb);

	irs->ipp = ipp;
	ipsec_rcv_redodebug(irs);

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

	/*
	 * if there is an attached ipsec device, then use that device for
	 * stats until we know better.
	 */
	if(skb->dev) {
		struct ipsecpriv  *prvdev = NULL;
		struct net_device *ipsecdev = NULL;

		for(i = 0; i <= ipsecdevices_max; i++) {
			if(ipsecdevices[i] == NULL) continue;
			prvdev = ipsecdevices[i]->priv;
			
			if(prvdev == NULL) continue;

			if(prvdev->dev == skb->dev) {
				ipsecdev = ipsecdevices[i];
				break;
			}
		}

		if(ipsecdev) {
			skb->dev = ipsecdev;
		} else {
			skb->dev = ipsec_mast_get_device(0);
			
			/* ipsec_mast_get takes the device */
			if(skb->dev) dev_put(skb->dev);
		}

		if(prvdev) {
			stats = (struct net_device_stats *) &(prvdev->mystats);
		}
	} 

	if(stats) {
		stats->rx_packets++;
	}

	KLIPS_IP_PRINT(debug_rcv, ipp);

	/* set up for decap loop */
	irs->stats= stats;
	irs->ipp  = ipp;
	irs->ipsp = NULL;
	irs->lastipsp = NULL;
	irs->ilen = 0;
	irs->authlen=0;
	irs->authfuncs=NULL;
	irs->skb = skb;

	(void)ipsec_rcv_decap(irs);

        ipsec_rcv_state_delete (irs);
        KLIPS_DEC_USE;
	return(0);

rcvleave:
        if (irs) {
                ipsec_rcv_state_delete(irs);
        }
        if (skb) {
                ipsec_kfree_skb(skb);
        }
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
int klips26_udp_encap_rcv(struct sock *sk, struct sk_buff *skb)
{
	return klips26_rcv_encap(skb, udp_sk(sk)->encap_type);
}

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
                goto rcvleave;
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

	/* ipp = skb->nh.iph; */
	ipp =ip_hdr(skb);

	irs->ipp = ipp;
	ipsec_rcv_redodebug(irs);

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
	if (irs) {
        	ipsec_rcv_state_delete (irs);
	}
	KLIPS_DEC_USE;
	return 0;
}
#endif

// ------------------------------------------------------------------------
// this handles creating and managing state for recv path

static spinlock_t irs_cache_lock = SPIN_LOCK_UNLOCKED;
#ifdef HAVE_KMEM_CACHE_MACRO
static struct kmem_cache *irs_cache_allocator = NULL;
#else
static kmem_cache_t *irs_cache_allocator = NULL;
#endif
static unsigned  irs_cache_allocated_count = 0;

int
ipsec_rcv_state_cache_init (void)
{
        if (irs_cache_allocator)
                return -EBUSY;

        spin_lock_init(&irs_cache_lock);
#ifdef HAVE_KMEM_CACHE_MACRO
        /* irs_cache_allocator = KMEM_CACHE(ipsec_irs,0); */
        irs_cache_allocator = kmem_cache_create ("ipsec_irs",
                sizeof (struct ipsec_rcv_state), 0,
                0, NULL);
#else
        irs_cache_allocator = kmem_cache_create ("ipsec_irs",
                sizeof (struct ipsec_rcv_state), 0,
                0, NULL, NULL);
#endif
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
 *
 * Local Variables:
 * c-set-style: linux
 * End:
 *
 */
