/*	$NetBSD: key_debug.c,v 1.14 2018/05/28 20:45:38 maxv Exp $	*/

/*	$KAME: key_debug.c,v 1.29 2001/08/16 14:25:41 itojun Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef _KERNEL
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#include "opt_inet.h"
#include "opt_inet6.h"
#include "opt_ipsec.h"
#endif
#ifdef __NetBSD__
#include "opt_inet.h"
#endif
#endif

#if HAVE_STDINT_H
#include <stdint.h>
#endif

#include <sys/types.h>
#include <sys/param.h>
#ifdef _KERNEL
#include <sys/systm.h>
#include <sys/mbuf.h>
#endif
#include <sys/socket.h>

#include <netinet/in.h>
#include PATH_IPSEC_H

#ifndef _KERNEL
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#endif /* !_KERNEL */

#if 0
#include "config.h"
#endif
#include "libpfkey.h"

#include "lswlog.h"

#define panic(MSG) llog_passert(&global_logger, HERE, "%s", MSG)

static void kdebug_sadb_prop(struct sadb_ext *);
static void kdebug_sadb_identity(struct sadb_ext *);
static void kdebug_sadb_supported(struct sadb_ext *);
static void kdebug_sadb_lifetime(struct sadb_ext *);
static void kdebug_sadb_sa(struct sadb_ext *);
static void kdebug_sadb_address(struct sadb_ext *);
static void kdebug_sadb_key(struct sadb_ext *);
static void kdebug_sadb_x_sa2(struct sadb_ext *);
static void kdebug_sadb_x_policy(struct sadb_ext *ext);
static void kdebug_sockaddr(struct sockaddr *addr);

#ifdef SADB_X_EXT_NAT_T_TYPE
static void kdebug_sadb_x_nat_t_type(struct sadb_ext *ext);
static void kdebug_sadb_x_nat_t_port(struct sadb_ext *ext);
#ifdef SADB_X_EXT_NAT_T_FRAG
static void kdebug_sadb_x_nat_t_frag(struct sadb_ext *ext);
#endif
#endif

#ifdef SADB_X_EXT_PACKET
static void kdebug_sadb_x_packet(struct sadb_ext *);
#endif

#ifdef SADB_X_EXT_KMADDRESS
static void kdebug_sadb_x_kmaddress(struct sadb_ext *);
#endif

#ifdef _KERNEL
static void kdebug_secreplay(struct secreplay *);
#endif

#if 0
#ifndef _KERNEL
#define panic(param)	{ DBG_log(param); exit(1); }
#endif
#endif

#include "libpfkey.h"
/* NOTE: host byte order */

/* %%%: about struct sadb_msg */
void
kdebug_sadb(struct sadb_msg *base)
{
	struct sadb_ext *ext;
	int tlen, extlen;

	/* sanity check */
	if (base == NULL)
		panic("kdebug_sadb: NULL pointer was passed.");

	DBG_log("sadb_msg{ version=%u type=%u errno=%u satype=%u",
	    base->sadb_msg_version, base->sadb_msg_type,
	    base->sadb_msg_errno, base->sadb_msg_satype);
	DBG_log("  len=%u(%u) reserved=%u seq=%u pid=%u",
	       base->sadb_msg_len, PFKEY_UNUNIT64(base->sadb_msg_len),
	       base->sadb_msg_reserved,
	    base->sadb_msg_seq, base->sadb_msg_pid);

	tlen = PFKEY_UNUNIT64(base->sadb_msg_len) - sizeof(struct sadb_msg);
	ext = (void *)((caddr_t)(void *)base + sizeof(struct sadb_msg));

	while (tlen > 0) {
		DBG_log("sadb_ext{ len=%u(%u) type=%u }",
		       ext->sadb_ext_len,
		       PFKEY_UNUNIT64(ext->sadb_ext_len),
		       ext->sadb_ext_type);

		if (ext->sadb_ext_len == 0) {
			DBG_log("kdebug_sadb: invalid ext_len=0 was passed.");
			return;
		}
		if (ext->sadb_ext_len > tlen) {
			DBG_log("kdebug_sadb: ext_len exceeds end of buffer.");
			return;
		}

		switch (ext->sadb_ext_type) {
		case SADB_EXT_SA:
			kdebug_sadb_sa(ext);
			break;
		case SADB_EXT_LIFETIME_CURRENT:
		case SADB_EXT_LIFETIME_HARD:
		case SADB_EXT_LIFETIME_SOFT:
			kdebug_sadb_lifetime(ext);
			break;
		case SADB_EXT_ADDRESS_SRC:
		case SADB_EXT_ADDRESS_DST:
		case SADB_EXT_ADDRESS_PROXY:
			kdebug_sadb_address(ext);
			break;
		case SADB_EXT_KEY_AUTH:
		case SADB_EXT_KEY_ENCRYPT:
			kdebug_sadb_key(ext);
			break;
		case SADB_EXT_IDENTITY_SRC:
		case SADB_EXT_IDENTITY_DST:
			kdebug_sadb_identity(ext);
			break;
		case SADB_EXT_SENSITIVITY:
			break;
		case SADB_EXT_PROPOSAL:
			kdebug_sadb_prop(ext);
			break;
		case SADB_EXT_SUPPORTED_AUTH:
		case SADB_EXT_SUPPORTED_ENCRYPT:
			kdebug_sadb_supported(ext);
			break;
		case SADB_EXT_SPIRANGE:
		case SADB_X_EXT_KMPRIVATE:
			break;
		case SADB_X_EXT_POLICY:
			kdebug_sadb_x_policy(ext);
			break;
		case SADB_X_EXT_SA2:
			kdebug_sadb_x_sa2(ext);
			break;
#ifdef SADB_X_EXT_NAT_T_TYPE
		case SADB_X_EXT_NAT_T_TYPE:
			kdebug_sadb_x_nat_t_type(ext);
			break;
		case SADB_X_EXT_NAT_T_SPORT:
		case SADB_X_EXT_NAT_T_DPORT:
			kdebug_sadb_x_nat_t_port(ext);
			break;
		case SADB_X_EXT_NAT_T_OA:
			kdebug_sadb_address(ext);
			break;
#ifdef SADB_X_EXT_NAT_T_FRAG
		case SADB_X_EXT_NAT_T_FRAG:
			kdebug_sadb_x_nat_t_frag(ext);
			break;
#endif
#endif
#ifdef SADB_X_EXT_PACKET
		case SADB_X_EXT_PACKET:
			kdebug_sadb_x_packet(ext);
			break;
#endif
#ifdef SADB_X_EXT_KMADDRESS
		case SADB_X_EXT_KMADDRESS:
			kdebug_sadb_x_kmaddress(ext);
			break;
#endif
		default:
			DBG_log("kdebug_sadb: invalid ext_type %u was passed.",
			    ext->sadb_ext_type);
			return;
		}

		extlen = PFKEY_UNUNIT64(ext->sadb_ext_len);
		tlen -= extlen;
		ext = (void *)((caddr_t)(void *)ext + extlen);
	}

	return;
}

static void
kdebug_sadb_prop(struct sadb_ext *ext)
{
	struct sadb_prop *prop = (void *)ext;
	struct sadb_comb *comb;
	int len;

	/* sanity check */
	if (ext == NULL)
		panic("kdebug_sadb_prop: NULL pointer was passed.");

	len = (PFKEY_UNUNIT64(prop->sadb_prop_len) - sizeof(*prop))
		/ sizeof(*comb);
	comb = (void *)(prop + 1);
	DBG_log("sadb_prop{ replay=%u", prop->sadb_prop_replay);

	while (len--) {
		DBG_log("sadb_comb{ auth=%u encrypt=%u "
			"flags=0x%04x reserved=0x%08x",
			comb->sadb_comb_auth, comb->sadb_comb_encrypt,
			comb->sadb_comb_flags, comb->sadb_comb_reserved);

		DBG_log("  auth_minbits=%u auth_maxbits=%u "
			"encrypt_minbits=%u encrypt_maxbits=%u",
			comb->sadb_comb_auth_minbits,
			comb->sadb_comb_auth_maxbits,
			comb->sadb_comb_encrypt_minbits,
			comb->sadb_comb_encrypt_maxbits);

		DBG_log("  soft_alloc=%u hard_alloc=%u "
			"soft_bytes=%lu hard_bytes=%lu",
			comb->sadb_comb_soft_allocations,
			comb->sadb_comb_hard_allocations,
			(unsigned long)comb->sadb_comb_soft_bytes,
			(unsigned long)comb->sadb_comb_hard_bytes);

		DBG_log("  soft_alloc=%lu hard_alloc=%lu "
			"soft_bytes=%lu hard_bytes=%lu }",
			(unsigned long)comb->sadb_comb_soft_addtime,
			(unsigned long)comb->sadb_comb_hard_addtime,
			(unsigned long)comb->sadb_comb_soft_usetime,
			(unsigned long)comb->sadb_comb_hard_usetime);
		comb++;
	}
	DBG_log("}");

	return;
}

static void
kdebug_sadb_identity(struct sadb_ext *ext)
{
	struct sadb_ident *id = (void *)ext;
	int len;

	/* sanity check */
	if (ext == NULL)
		panic("kdebug_sadb_identity: NULL pointer was passed.");

	len = PFKEY_UNUNIT64(id->sadb_ident_len) - sizeof(*id);
	DBG_log("sadb_ident_%s{",
	    id->sadb_ident_exttype == SADB_EXT_IDENTITY_SRC ? "src" : "dst");
	switch (id->sadb_ident_type) {
	default:
		DBG_log(" type=%d id=%lu",
			id->sadb_ident_type, (u_long)id->sadb_ident_id);
		if (len) {
#ifdef _KERNEL
			ipsec_hexdump((caddr_t)(id + 1), len); /*XXX cast ?*/
#else
			char *p, *ep;
			DBG_log("\n  str=\"");
			p = (void *)(id + 1);
			ep = p + len;
			for (/*nothing*/; *p && p < ep; p++) {
				if (isprint((int)*p)) {
					DBG_log("%c", *p & 0xff);
				} else {
					DBG_log("\\%03o", *p & 0xff);
				}
			}
#endif
			DBG_log("\"");
		}
		break;
	}

	DBG_log(" }");

	return;
}

static void
kdebug_sadb_supported(struct sadb_ext *ext)
{
	struct sadb_supported *sup = (void *)ext;
	struct sadb_alg *alg;
	int len;

	/* sanity check */
	if (ext == NULL)
		panic("kdebug_sadb_supported: NULL pointer was passed.");

	len = (PFKEY_UNUNIT64(sup->sadb_supported_len) - sizeof(*sup))
		/ sizeof(*alg);
	alg = (void *)(sup + 1);
	DBG_log("sadb_sup{");
	while (len--) {
		DBG_log("  { id=%d ivlen=%d min=%d max=%d }",
			alg->sadb_alg_id, alg->sadb_alg_ivlen,
			alg->sadb_alg_minbits, alg->sadb_alg_maxbits);
		alg++;
	}
	DBG_log("}");

	return;
}

static void
kdebug_sadb_lifetime(struct sadb_ext *ext)
{
	struct sadb_lifetime *lft = (void *)ext;

	/* sanity check */
	if (ext == NULL)
		DBG_log("kdebug_sadb_lifetime: NULL pointer was passed.");

	DBG_log("sadb_lifetime{ alloc=%u, bytes=%u",
		lft->sadb_lifetime_allocations,
		(u_int32_t)lft->sadb_lifetime_bytes);
	DBG_log("  addtime=%u, usetime=%u }",
		(u_int32_t)lft->sadb_lifetime_addtime,
		(u_int32_t)lft->sadb_lifetime_usetime);

	return;
}

static void
kdebug_sadb_sa(struct sadb_ext *ext)
{
	struct sadb_sa *sa = (void *)ext;

	/* sanity check */
	if (ext == NULL)
		panic("kdebug_sadb_sa: NULL pointer was passed.");

	DBG_log("sadb_sa{ spi=%u replay=%u state=%u",
	    (u_int32_t)ntohl(sa->sadb_sa_spi), sa->sadb_sa_replay,
	    sa->sadb_sa_state);
	DBG_log("  auth=%u encrypt=%u flags=0x%08x }",
	    sa->sadb_sa_auth, sa->sadb_sa_encrypt, sa->sadb_sa_flags);

	return;
}

static void
kdebug_sadb_address(struct sadb_ext *ext)
{
	struct sadb_address *addr = (void *)ext;

	/* sanity check */
	if (ext == NULL)
		panic("kdebug_sadb_address: NULL pointer was passed.");

	DBG_log("sadb_address{ proto=%u prefixlen=%u reserved=0x%02x%02x }",
	    addr->sadb_address_proto, addr->sadb_address_prefixlen,
	    ((uint8_t *)(void *)&addr->sadb_address_reserved)[0],
	    ((uint8_t *)(void *)&addr->sadb_address_reserved)[1]);

	kdebug_sockaddr((void *)((caddr_t)(void *)ext + sizeof(*addr)));

	return;
}

static void
kdebug_sadb_key(struct sadb_ext *ext)
{
	struct sadb_key *key = (void *)ext;

	/* sanity check */
	if (ext == NULL)
		panic("kdebug_sadb_key: NULL pointer was passed.");

	DBG_log("sadb_key{ bits=%u reserved=%u",
	    key->sadb_key_bits, key->sadb_key_reserved);
	DBG_log("  key=");

	/* sanity check 2 */
	if (((uint32_t)key->sadb_key_bits >> 3) >
		(PFKEY_UNUNIT64(key->sadb_key_len) - sizeof(struct sadb_key))) {
		DBG_log("kdebug_sadb_key: key length mismatch, bit:%d len:%ld.",
			(uint32_t)key->sadb_key_bits >> 3,
			(long)PFKEY_UNUNIT64(key->sadb_key_len) - sizeof(struct sadb_key));
	}

	if (DBGP(DBG_CRYPT)) {
		ipsec_hexdump(key + 1,
			      (int)((uint32_t)key->sadb_key_bits >> 3));
	}
	DBG_log(" }");
	return;
}

static void
kdebug_sadb_x_sa2(struct sadb_ext *ext)
{
	struct sadb_x_sa2 *sa2 = (void *)ext;

	/* sanity check */
	if (ext == NULL)
		panic("kdebug_sadb_x_sa2: NULL pointer was passed.");

	DBG_log("sadb_x_sa2{ mode=%u reqid=%u",
	    sa2->sadb_x_sa2_mode, sa2->sadb_x_sa2_reqid);
	DBG_log("  reserved1=%u reserved2=%u sequence=%u }",
	    sa2->sadb_x_sa2_reserved1, sa2->sadb_x_sa2_reserved2,
	    sa2->sadb_x_sa2_sequence);

	return;
}

void
kdebug_sadb_x_policy(struct sadb_ext *ext)
{
	struct sadb_x_policy *xpl = (void *)ext;
	struct sockaddr *addr;

	/* sanity check */
	if (ext == NULL)
		panic("kdebug_sadb_x_policy: NULL pointer was passed.");

#ifdef HAVE_PFKEY_POLICY_PRIORITY
	DBG_log("sadb_x_policy{ type=%u dir=%u id=%x priority=%u }",
#else
	DBG_log("sadb_x_policy{ type=%u dir=%u id=%x }",
#endif
		xpl->sadb_x_policy_type, xpl->sadb_x_policy_dir,
#ifdef HAVE_PFKEY_POLICY_PRIORITY
		xpl->sadb_x_policy_id, xpl->sadb_x_policy_priority);
#else
		xpl->sadb_x_policy_id);
#endif

	if (xpl->sadb_x_policy_type == IPSEC_POLICY_IPSEC) {
		int tlen;
		struct sadb_x_ipsecrequest *xisr;

		tlen = PFKEY_UNUNIT64(xpl->sadb_x_policy_len) - sizeof(*xpl);
		xisr = (void *)(xpl + 1);

		while (tlen > 0) {
			DBG_log("sadb_x_ipsecrequest { len=%u(%u) proto=%u mode=%u level=%u reqid=%u",
			       /*XXX: not multiplier!!! */
				xisr->sadb_x_ipsecrequest_len, xisr->sadb_x_ipsecrequest_len,
				xisr->sadb_x_ipsecrequest_proto,
				xisr->sadb_x_ipsecrequest_mode,
				xisr->sadb_x_ipsecrequest_level,
				xisr->sadb_x_ipsecrequest_reqid);

			if (xisr->sadb_x_ipsecrequest_len > sizeof(*xisr)) {
				addr = (void *)(xisr + 1);
				kdebug_sockaddr(addr);
				addr = (void *)((caddr_t)(void *)addr
							+ sysdep_sa_len(addr));
				kdebug_sockaddr(addr);
			}

			DBG_log(" }");

			/* prevent infinite loop */
			if (xisr->sadb_x_ipsecrequest_len == 0) {
				DBG_log("kdebug_sadb_x_policy: wrong policy struct.");
				return;
			}
			/* prevent overflow */
			if (xisr->sadb_x_ipsecrequest_len > tlen) {
				DBG_log("invalid ipsec policy length");
				return;
			}

			tlen -= xisr->sadb_x_ipsecrequest_len;

			xisr = (void *)((caddr_t)(void *)xisr
			                + xisr->sadb_x_ipsecrequest_len);
		}

		if (tlen != 0)
			panic("kdebug_sadb_x_policy: wrong policy struct.");
	}

	return;
}

#ifdef SADB_X_EXT_NAT_T_TYPE
static void
kdebug_sadb_x_nat_t_type(struct sadb_ext *ext)
{
	struct sadb_x_nat_t_type *ntt = (void *)ext;

	/* sanity check */
	if (ext == NULL)
		panic("kdebug_sadb_x_nat_t_type: NULL pointer was passed.");

	DBG_log("sadb_x_nat_t_type{ type=%u }", ntt->sadb_x_nat_t_type_type);

	return;
}

static void
kdebug_sadb_x_nat_t_port(struct sadb_ext *ext)
{
	struct sadb_x_nat_t_port *ntp = (void *)ext;

	/* sanity check */
	if (ext == NULL)
		panic("kdebug_sadb_x_nat_t_port: NULL pointer was passed.");

	DBG_log("sadb_x_nat_t_port{ port=%u }", ntohs(ntp->sadb_x_nat_t_port_port));

	return;
}
#ifdef SADB_X_EXT_NAT_T_FRAG
static void kdebug_sadb_x_nat_t_frag (struct sadb_ext *ext)
{
	struct sadb_x_nat_t_frag *esp_frag = (void *)ext;

	/* sanity check */
	if (ext == NULL)
		panic("kdebug_sadb_x_nat_t_frag: NULL pointer was passed.");

	DBG_log("sadb_x_nat_t_frag{ esp_frag=%u }", esp_frag->sadb_x_nat_t_frag_fraglen);

	return;
}
#endif
#endif

#ifdef SADB_X_EXT_PACKET
static void
kdebug_sadb_x_packet(struct sadb_ext *ext)
{
	struct sadb_x_packet *pkt = (struct sadb_x_packet *)ext;

	/* sanity check */
	if (ext == NULL)
		panic("kdebug_sadb_x_packet: NULL pointer was passed.");

	DBG_log("sadb_x_packet{ copylen=%u", pkt->sadb_x_packet_copylen);
	DBG_log("  packet=");
	ipsec_hexdump((caddr_t)pkt + sizeof(struct sadb_x_packet),
		      pkt->sadb_x_packet_copylen);
	DBG_log(" }");
	return;
}
#endif

#ifdef SADB_X_EXT_KMADDRESS
static void
kdebug_sadb_x_kmaddress(struct sadb_ext *ext)
{
	struct sadb_x_kmaddress *kma = (struct sadb_x_kmaddress *)ext;
	struct sockaddr * sa;
	sa_family_t family;
	int len, sa_len;

	/* sanity check */
	if (ext == NULL)
		panic("kdebug_sadb_x_kmaddress: NULL pointer was passed.");

	len = (PFKEY_UNUNIT64(kma->sadb_x_kmaddress_len) - sizeof(*kma));

	DBG_log("sadb_x_kmaddress{ reserved=0x%02x%02x%02x%02x }",
	       ((uint8_t *)(void *)&kma->sadb_x_kmaddress_reserved)[0],
	       ((uint8_t *)(void *)&kma->sadb_x_kmaddress_reserved)[1],
	       ((uint8_t *)(void *)&kma->sadb_x_kmaddress_reserved)[2],
	       ((uint8_t *)(void *)&kma->sadb_x_kmaddress_reserved)[3]);

	sa = (struct sockaddr *)(kma + 1);
	if (len < sizeof(struct sockaddr) || (sa_len = sysdep_sa_len(sa)) > len)
		panic("kdebug_sadb_x_kmaddress: not enough data to read"
		      " first sockaddr.");
	kdebug_sockaddr((void *)sa); /* local address */
	family = sa->sa_family;

	len -= sa_len;
	sa = (struct sockaddr *)((char *)sa + sa_len);
	if (len < sizeof(struct sockaddr) || sysdep_sa_len(sa) > len)
		panic("kdebug_sadb_x_kmaddress: not enough data to read"
		      " second sockaddr.");
	kdebug_sockaddr((void *)sa); /* remote address */

	if (family != sa->sa_family)
		DBG_log("kdebug_sadb_x_kmaddress:  !!!! Please, note the "
		       "unexpected mismatch in address family.");
}
#endif


#ifdef _KERNEL
/* %%%: about SPD and SAD */
void
kdebug_secpolicy(struct secpolicy *sp)
{
	/* sanity check */
	if (sp == NULL)
		panic("kdebug_secpolicy: NULL pointer was passed.");

	DBG_log("secpolicy{ refcnt=%u state=%u policy=%u",
		sp->refcnt, sp->state, sp->policy);

	kdebug_secpolicyindex(&sp->spidx);

	switch (sp->policy) {
	case IPSEC_POLICY_DISCARD:
		DBG_log("  type=discard }");
		break;
	case IPSEC_POLICY_NONE:
		DBG_log("  type=none }");
		break;
	case IPSEC_POLICY_IPSEC:
	    {
		struct ipsecrequest *isr;
		for (isr = sp->req; isr != NULL; isr = isr->next) {

			DBG_log("  level=%u", isr->level);
			kdebug_secasindex(&isr->saidx);

			if (isr->sav != NULL)
				kdebug_secasv(isr->sav);
		}
		DBG_log("  }");
	    }
		break;
	case IPSEC_POLICY_BYPASS:
		DBG_log("  type=bypass }");
		break;
	case IPSEC_POLICY_ENTRUST:
		DBG_log("  type=entrust }");
		break;
	default:
		DBG_log("kdebug_secpolicy: Invalid policy found. %d",
			sp->policy);
		break;
	}

	return;
}

void
kdebug_secpolicyindex(struct secpolicyindex *spidx)
{
	/* sanity check */
	if (spidx == NULL)
		panic("kdebug_secpolicyindex: NULL pointer was passed.");

	DBG_log("secpolicyindex{ dir=%u prefs=%u prefd=%u ul_proto=%u",
		spidx->dir, spidx->prefs, spidx->prefd, spidx->ul_proto);

	ipsec_hexdump((caddr_t)&spidx->src,
		sysdep_sa_len((struct sockaddr *)&spidx->src));
	DBG_log("");
	ipsec_hexdump((caddr_t)&spidx->dst,
		sysdep_sa_len((struct sockaddr *)&spidx->dst));
	DBG_log("}");

	return;
}

void
kdebug_secasindex(struct secasindex *saidx)
{
	/* sanity check */
	if (saidx == NULL)
		panic("kdebug_secpolicyindex: NULL pointer was passed.");

	DBG_log("secasindex{ mode=%u proto=%u",
		saidx->mode, saidx->proto);

	ipsec_hexdump((caddr_t)&saidx->src,
		sysdep_sa_len((struct sockaddr *)&saidx->src));
	DBG_log("");
	ipsec_hexdump((caddr_t)&saidx->dst,
		sysdep_sa_len((struct sockaddr *)&saidx->dst));
	DBG_log("");

	return;
}

void
kdebug_secasv(struct secasvar *sav)
{
	/* sanity check */
	if (sav == NULL)
		panic("kdebug_secasv: NULL pointer was passed.");

	DBG_log("secas{");
	kdebug_secasindex(&sav->sah->saidx);

	DBG_log("  refcnt=%u state=%u auth=%u enc=%u",
	    sav->refcnt, sav->state, sav->alg_auth, sav->alg_enc);
	DBG_log("  spi=%u flags=%u",
	    (u_int32_t)ntohl(sav->spi), sav->flags);

	if (sav->key_auth != NULL)
		kdebug_sadb_key((struct sadb_ext *)sav->key_auth);
	if (sav->key_enc != NULL)
		kdebug_sadb_key((struct sadb_ext *)sav->key_enc);
	if (sav->iv != NULL) {
		DBG_log("  iv=");
		ipsec_hexdump(sav->iv, sav->ivlen ? sav->ivlen : 8);
		DBG_log("");
	}

	if (sav->replay != NULL)
		kdebug_secreplay(sav->replay);
	if (sav->lft_c != NULL)
		kdebug_sadb_lifetime((struct sadb_ext *)sav->lft_c);
	if (sav->lft_h != NULL)
		kdebug_sadb_lifetime((struct sadb_ext *)sav->lft_h);
	if (sav->lft_s != NULL)
		kdebug_sadb_lifetime((struct sadb_ext *)sav->lft_s);

#if notyet
	/* XXX: misc[123] ? */
#endif

	return;
}

static void
kdebug_secreplay(struct secreplay *rpl)
{
	int len, l;

	/* sanity check */
	if (rpl == NULL)
		panic("kdebug_secreplay: NULL pointer was passed.");

	DBG_log(" secreplay{ count=%u wsize=%u seq=%u lastseq=%u",
	    rpl->count, rpl->wsize, rpl->seq, rpl->lastseq);

	if (rpl->bitmap == NULL) {
		DBG_log(" }");
		return;
	}

	DBG_log("\n   bitmap { ");

	for (len = 0; len < rpl->wsize; len++) {
		for (l = 7; l >= 0; l--)
			DBG_log("%u", (((rpl->bitmap)[len] >> l) & 1) ? 1 : 0);
	}
	DBG_log(" }");

	return;
}

void
kdebug_mbufhdr(struct mbuf *m)
{
	/* sanity check */
	if (m == NULL)
		return;

	DBG_log("mbuf(%p){ m_next:%p m_nextpkt:%p m_data:%p "
	       "m_len:%d m_type:0x%02x m_flags:0x%02x }",
		m, m->m_next, m->m_nextpkt, m->m_data,
		m->m_len, m->m_type, m->m_flags);

	if (m->m_flags & M_PKTHDR) {
		DBG_log("  m_pkthdr{ len:%d rcvif:%p }",
		    m->m_pkthdr.len, m->m_pkthdr.rcvif);
	}

#ifdef __FreeBSD__
	if (m->m_flags & M_EXT) {
		DBG_log("  m_ext{ ext_buf:%p ext_free:%p "
		       "ext_size:%u ext_ref:%p }",
			m->m_ext.ext_buf, m->m_ext.ext_free,
			m->m_ext.ext_size, m->m_ext.ext_ref);
	}
#endif

	return;
}

void
kdebug_mbuf(struct mbuf *m0)
{
	struct mbuf *m = m0;
	int i, j;

	for (j = 0; m; m = m->m_next) {
		kdebug_mbufhdr(m);
		DBG_log("  m_data:");
		for (i = 0; i < m->m_len; i++) {
			if (i && i % 32 == 0)
				DBG_log("");
			if (i % 4 == 0)
				DBG_log(" ");
			DBG_log("%02x", mtod(m, uint8_t *)[i]);
			j++;
		}
		DBG_log("");
	}

	return;
}
#endif /* _KERNEL */

static void
kdebug_sockaddr(struct sockaddr *addr)
{
	struct sockaddr_in *sin4;
#ifdef INET6
	struct sockaddr_in6 *sin6;
#endif

	/* sanity check */
	if (addr == NULL)
		panic("kdebug_sockaddr: NULL pointer was passed.");

	/* NOTE: We deal with port number as host byte order. */
	DBG_log("sockaddr{ len=%u family=%u", sysdep_sa_len(addr), addr->sa_family);

	switch (addr->sa_family) {
	case AF_INET:
		sin4 = (void *)addr;
		DBG_log(" port=%u", ntohs(sin4->sin_port));
		ipsec_hexdump(&sin4->sin_addr, sizeof(sin4->sin_addr));
		break;
#ifdef INET6
	case AF_INET6:
		sin6 = (void *)addr;
		DBG_log(" port=%u", ntohs(sin6->sin6_port));
		DBG_log("  flowinfo=0x%08x, scope_id=0x%08x",
		    sin6->sin6_flowinfo, sin6->sin6_scope_id);
		ipsec_hexdump(&sin6->sin6_addr, sizeof(sin6->sin6_addr));
		break;
#endif
	}

	DBG_log("  }");

	return;
}

void
ipsec_hexdump(const void *buf, int len)
{
	DBG_dump(NULL, buf, len);
#if 0
	int i;

	for (i = 0; i < len; i++) {
		if (i != 0 && i % 32 == 0) DBG_log("");
		if (i % 4 == 0) DBG_log(" ");
		DBG_log("%02x", ((const unsigned char *)buf)[i]);
	}
	if (i % 32 != 0) DBG_log("");
#endif

	return;
}
