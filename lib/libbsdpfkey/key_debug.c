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
#include <sys/queue.h>
#endif
#include <sys/socket.h>

#include <netinet/in.h>
#include PATH_IPSEC_H

#ifndef _KERNEL
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#endif /* !_KERNEL */

#include "config.h"
#include "libpfkey.h"

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

#ifndef _KERNEL
#define panic(param)	{ printf(param); exit(1); }
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
		panic("kdebug_sadb: NULL pointer was passed.\n");

	printf("sadb_msg{ version=%u type=%u errno=%u satype=%u\n",
	    base->sadb_msg_version, base->sadb_msg_type,
	    base->sadb_msg_errno, base->sadb_msg_satype);
	printf("  len=%u reserved=%u seq=%u pid=%u\n",
	    base->sadb_msg_len, base->sadb_msg_reserved,
	    base->sadb_msg_seq, base->sadb_msg_pid);

	tlen = PFKEY_UNUNIT64(base->sadb_msg_len) - sizeof(struct sadb_msg);
	ext = (void *)((caddr_t)(void *)base + sizeof(struct sadb_msg));

	while (tlen > 0) {
		printf("sadb_ext{ len=%u type=%u }\n",
		    PFKEY_UNUNIT64(ext->sadb_ext_len), ext->sadb_ext_type);

		if (ext->sadb_ext_len == 0) {
			printf("kdebug_sadb: invalid ext_len=0 was passed.\n");
			return;
		}
		if (ext->sadb_ext_len > tlen) {
			printf("kdebug_sadb: ext_len exceeds end of buffer.\n");
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
			printf("kdebug_sadb: invalid ext_type %u was passed.\n",
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
		panic("kdebug_sadb_prop: NULL pointer was passed.\n");

	len = (PFKEY_UNUNIT64(prop->sadb_prop_len) - sizeof(*prop))
		/ sizeof(*comb);
	comb = (void *)(prop + 1);
	printf("sadb_prop{ replay=%u\n", prop->sadb_prop_replay);

	while (len--) {
		printf("sadb_comb{ auth=%u encrypt=%u "
			"flags=0x%04x reserved=0x%08x\n",
			comb->sadb_comb_auth, comb->sadb_comb_encrypt,
			comb->sadb_comb_flags, comb->sadb_comb_reserved);

		printf("  auth_minbits=%u auth_maxbits=%u "
			"encrypt_minbits=%u encrypt_maxbits=%u\n",
			comb->sadb_comb_auth_minbits,
			comb->sadb_comb_auth_maxbits,
			comb->sadb_comb_encrypt_minbits,
			comb->sadb_comb_encrypt_maxbits);

		printf("  soft_alloc=%u hard_alloc=%u "
			"soft_bytes=%lu hard_bytes=%lu\n",
			comb->sadb_comb_soft_allocations,
			comb->sadb_comb_hard_allocations,
			(unsigned long)comb->sadb_comb_soft_bytes,
			(unsigned long)comb->sadb_comb_hard_bytes);

		printf("  soft_alloc=%lu hard_alloc=%lu "
			"soft_bytes=%lu hard_bytes=%lu }\n",
			(unsigned long)comb->sadb_comb_soft_addtime,
			(unsigned long)comb->sadb_comb_hard_addtime,
			(unsigned long)comb->sadb_comb_soft_usetime,
			(unsigned long)comb->sadb_comb_hard_usetime);
		comb++;
	}
	printf("}\n");

	return;
}

static void
kdebug_sadb_identity(struct sadb_ext *ext)
{
	struct sadb_ident *id = (void *)ext;
	int len;

	/* sanity check */
	if (ext == NULL)
		panic("kdebug_sadb_identity: NULL pointer was passed.\n");

	len = PFKEY_UNUNIT64(id->sadb_ident_len) - sizeof(*id);
	printf("sadb_ident_%s{",
	    id->sadb_ident_exttype == SADB_EXT_IDENTITY_SRC ? "src" : "dst");
	switch (id->sadb_ident_type) {
	default:
		printf(" type=%d id=%lu",
			id->sadb_ident_type, (u_long)id->sadb_ident_id);
		if (len) {
#ifdef _KERNEL
			ipsec_hexdump((caddr_t)(id + 1), len); /*XXX cast ?*/
#else
			char *p, *ep;
			printf("\n  str=\"");
			p = (void *)(id + 1);
			ep = p + len;
			for (/*nothing*/; *p && p < ep; p++) {
				if (isprint((int)*p))
					printf("%c", *p & 0xff);
				else
					printf("\\%03o", *p & 0xff);
			}
#endif
			printf("\"");
		}
		break;
	}

	printf(" }\n");

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
		panic("kdebug_sadb_supported: NULL pointer was passed.\n");

	len = (PFKEY_UNUNIT64(sup->sadb_supported_len) - sizeof(*sup))
		/ sizeof(*alg);
	alg = (void *)(sup + 1);
	printf("sadb_sup{\n");
	while (len--) {
		printf("  { id=%d ivlen=%d min=%d max=%d }\n",
			alg->sadb_alg_id, alg->sadb_alg_ivlen,
			alg->sadb_alg_minbits, alg->sadb_alg_maxbits);
		alg++;
	}
	printf("}\n");

	return;
}

static void
kdebug_sadb_lifetime(struct sadb_ext *ext)
{
	struct sadb_lifetime *lft = (void *)ext;

	/* sanity check */
	if (ext == NULL)
		printf("kdebug_sadb_lifetime: NULL pointer was passed.\n");

	printf("sadb_lifetime{ alloc=%u, bytes=%u\n",
		lft->sadb_lifetime_allocations,
		(u_int32_t)lft->sadb_lifetime_bytes);
	printf("  addtime=%u, usetime=%u }\n",
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
		panic("kdebug_sadb_sa: NULL pointer was passed.\n");

	printf("sadb_sa{ spi=%u replay=%u state=%u\n",
	    (u_int32_t)ntohl(sa->sadb_sa_spi), sa->sadb_sa_replay,
	    sa->sadb_sa_state);
	printf("  auth=%u encrypt=%u flags=0x%08x }\n",
	    sa->sadb_sa_auth, sa->sadb_sa_encrypt, sa->sadb_sa_flags);

	return;
}

static void
kdebug_sadb_address(struct sadb_ext *ext)
{
	struct sadb_address *addr = (void *)ext;

	/* sanity check */
	if (ext == NULL)
		panic("kdebug_sadb_address: NULL pointer was passed.\n");

	printf("sadb_address{ proto=%u prefixlen=%u reserved=0x%02x%02x }\n",
	    addr->sadb_address_proto, addr->sadb_address_prefixlen,
	    ((u_char *)(void *)&addr->sadb_address_reserved)[0],
	    ((u_char *)(void *)&addr->sadb_address_reserved)[1]);

	kdebug_sockaddr((void *)((caddr_t)(void *)ext + sizeof(*addr)));

	return;
}

static void
kdebug_sadb_key(struct sadb_ext *ext)
{
	struct sadb_key *key = (void *)ext;

	/* sanity check */
	if (ext == NULL)
		panic("kdebug_sadb_key: NULL pointer was passed.\n");

	printf("sadb_key{ bits=%u reserved=%u\n",
	    key->sadb_key_bits, key->sadb_key_reserved);
	printf("  key=");

	/* sanity check 2 */
	if (((uint32_t)key->sadb_key_bits >> 3) >
		(PFKEY_UNUNIT64(key->sadb_key_len) - sizeof(struct sadb_key))) {
		printf("kdebug_sadb_key: key length mismatch, bit:%d len:%ld.\n",
			(uint32_t)key->sadb_key_bits >> 3,
			(long)PFKEY_UNUNIT64(key->sadb_key_len) - sizeof(struct sadb_key));
	}

	ipsec_hexdump(key + sizeof(struct sadb_key),
	              (int)((uint32_t)key->sadb_key_bits >> 3));
	printf(" }\n");
	return;
}

static void
kdebug_sadb_x_sa2(struct sadb_ext *ext)
{
	struct sadb_x_sa2 *sa2 = (void *)ext;

	/* sanity check */
	if (ext == NULL)
		panic("kdebug_sadb_x_sa2: NULL pointer was passed.\n");

	printf("sadb_x_sa2{ mode=%u reqid=%u\n",
	    sa2->sadb_x_sa2_mode, sa2->sadb_x_sa2_reqid);
	printf("  reserved1=%u reserved2=%u sequence=%u }\n",
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
		panic("kdebug_sadb_x_policy: NULL pointer was passed.\n");

#ifdef HAVE_PFKEY_POLICY_PRIORITY
	printf("sadb_x_policy{ type=%u dir=%u id=%x priority=%u }\n",
#else
	printf("sadb_x_policy{ type=%u dir=%u id=%x }\n",
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
			printf(" { len=%u proto=%u mode=%u level=%u reqid=%u\n",
				xisr->sadb_x_ipsecrequest_len,
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

			printf(" }\n");

			/* prevent infinite loop */
			if (xisr->sadb_x_ipsecrequest_len == 0) {
				printf("kdebug_sadb_x_policy: wrong policy struct.\n");
				return;
			}
			/* prevent overflow */
			if (xisr->sadb_x_ipsecrequest_len > tlen) {
				printf("invalid ipsec policy length\n");
				return;
			}

			tlen -= xisr->sadb_x_ipsecrequest_len;

			xisr = (void *)((caddr_t)(void *)xisr
			                + xisr->sadb_x_ipsecrequest_len);
		}

		if (tlen != 0)
			panic("kdebug_sadb_x_policy: wrong policy struct.\n");
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
		panic("kdebug_sadb_x_nat_t_type: NULL pointer was passed.\n");

	printf("sadb_x_nat_t_type{ type=%u }\n", ntt->sadb_x_nat_t_type_type);

	return;
}

static void
kdebug_sadb_x_nat_t_port(struct sadb_ext *ext)
{
	struct sadb_x_nat_t_port *ntp = (void *)ext;

	/* sanity check */
	if (ext == NULL)
		panic("kdebug_sadb_x_nat_t_port: NULL pointer was passed.\n");

	printf("sadb_x_nat_t_port{ port=%u }\n", ntohs(ntp->sadb_x_nat_t_port_port));

	return;
}
#ifdef SADB_X_EXT_NAT_T_FRAG
static void kdebug_sadb_x_nat_t_frag (struct sadb_ext *ext)
{
	struct sadb_x_nat_t_frag *esp_frag = (void *)ext;

	/* sanity check */
	if (ext == NULL)
		panic("kdebug_sadb_x_nat_t_frag: NULL pointer was passed.\n");

	printf("sadb_x_nat_t_frag{ esp_frag=%u }\n", esp_frag->sadb_x_nat_t_frag_fraglen);

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
		panic("kdebug_sadb_x_packet: NULL pointer was passed.\n");

	printf("sadb_x_packet{ copylen=%u\n", pkt->sadb_x_packet_copylen);
	printf("  packet=");
	ipsec_hexdump((caddr_t)pkt + sizeof(struct sadb_x_packet),
		      pkt->sadb_x_packet_copylen);
	printf(" }\n");
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
		panic("kdebug_sadb_x_kmaddress: NULL pointer was passed.\n");

	len = (PFKEY_UNUNIT64(kma->sadb_x_kmaddress_len) - sizeof(*kma));

	printf("sadb_x_kmaddress{ reserved=0x%02x%02x%02x%02x }\n",
	       ((u_char *)(void *)&kma->sadb_x_kmaddress_reserved)[0],
	       ((u_char *)(void *)&kma->sadb_x_kmaddress_reserved)[1],
	       ((u_char *)(void *)&kma->sadb_x_kmaddress_reserved)[2],
	       ((u_char *)(void *)&kma->sadb_x_kmaddress_reserved)[3]);

	sa = (struct sockaddr *)(kma + 1);
	if (len < sizeof(struct sockaddr) || (sa_len = sysdep_sa_len(sa)) > len)
		panic("kdebug_sadb_x_kmaddress: not enough data to read"
		      " first sockaddr.\n");
	kdebug_sockaddr((void *)sa); /* local address */
	family = sa->sa_family;

	len -= sa_len;
	sa = (struct sockaddr *)((char *)sa + sa_len);
	if (len < sizeof(struct sockaddr) || sysdep_sa_len(sa) > len)
		panic("kdebug_sadb_x_kmaddress: not enough data to read"
		      " second sockaddr.\n");
	kdebug_sockaddr((void *)sa); /* remote address */

	if (family != sa->sa_family)
		printf("kdebug_sadb_x_kmaddress:  !!!! Please, note the "
		       "unexpected mismatch in address family.\n");
}
#endif


#ifdef _KERNEL
/* %%%: about SPD and SAD */
void
kdebug_secpolicy(struct secpolicy *sp)
{
	/* sanity check */
	if (sp == NULL)
		panic("kdebug_secpolicy: NULL pointer was passed.\n");

	printf("secpolicy{ refcnt=%u state=%u policy=%u\n",
		sp->refcnt, sp->state, sp->policy);

	kdebug_secpolicyindex(&sp->spidx);

	switch (sp->policy) {
	case IPSEC_POLICY_DISCARD:
		printf("  type=discard }\n");
		break;
	case IPSEC_POLICY_NONE:
		printf("  type=none }\n");
		break;
	case IPSEC_POLICY_IPSEC:
	    {
		struct ipsecrequest *isr;
		for (isr = sp->req; isr != NULL; isr = isr->next) {

			printf("  level=%u\n", isr->level);
			kdebug_secasindex(&isr->saidx);

			if (isr->sav != NULL)
				kdebug_secasv(isr->sav);
		}
		printf("  }\n");
	    }
		break;
	case IPSEC_POLICY_BYPASS:
		printf("  type=bypass }\n");
		break;
	case IPSEC_POLICY_ENTRUST:
		printf("  type=entrust }\n");
		break;
	default:
		printf("kdebug_secpolicy: Invalid policy found. %d\n",
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
		panic("kdebug_secpolicyindex: NULL pointer was passed.\n");

	printf("secpolicyindex{ dir=%u prefs=%u prefd=%u ul_proto=%u\n",
		spidx->dir, spidx->prefs, spidx->prefd, spidx->ul_proto);

	ipsec_hexdump((caddr_t)&spidx->src,
		sysdep_sa_len((struct sockaddr *)&spidx->src));
	printf("\n");
	ipsec_hexdump((caddr_t)&spidx->dst,
		sysdep_sa_len((struct sockaddr *)&spidx->dst));
	printf("}\n");

	return;
}

void
kdebug_secasindex(struct secasindex *saidx)
{
	/* sanity check */
	if (saidx == NULL)
		panic("kdebug_secpolicyindex: NULL pointer was passed.\n");

	printf("secasindex{ mode=%u proto=%u\n",
		saidx->mode, saidx->proto);

	ipsec_hexdump((caddr_t)&saidx->src,
		sysdep_sa_len((struct sockaddr *)&saidx->src));
	printf("\n");
	ipsec_hexdump((caddr_t)&saidx->dst,
		sysdep_sa_len((struct sockaddr *)&saidx->dst));
	printf("\n");

	return;
}

void
kdebug_secasv(struct secasvar *sav)
{
	/* sanity check */
	if (sav == NULL)
		panic("kdebug_secasv: NULL pointer was passed.\n");

	printf("secas{");
	kdebug_secasindex(&sav->sah->saidx);

	printf("  refcnt=%u state=%u auth=%u enc=%u\n",
	    sav->refcnt, sav->state, sav->alg_auth, sav->alg_enc);
	printf("  spi=%u flags=%u\n",
	    (u_int32_t)ntohl(sav->spi), sav->flags);

	if (sav->key_auth != NULL)
		kdebug_sadb_key((struct sadb_ext *)sav->key_auth);
	if (sav->key_enc != NULL)
		kdebug_sadb_key((struct sadb_ext *)sav->key_enc);
	if (sav->iv != NULL) {
		printf("  iv=");
		ipsec_hexdump(sav->iv, sav->ivlen ? sav->ivlen : 8);
		printf("\n");
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
		panic("kdebug_secreplay: NULL pointer was passed.\n");

	printf(" secreplay{ count=%u wsize=%u seq=%u lastseq=%u",
	    rpl->count, rpl->wsize, rpl->seq, rpl->lastseq);

	if (rpl->bitmap == NULL) {
		printf(" }\n");
		return;
	}

	printf("\n   bitmap { ");

	for (len = 0; len < rpl->wsize; len++) {
		for (l = 7; l >= 0; l--)
			printf("%u", (((rpl->bitmap)[len] >> l) & 1) ? 1 : 0);
	}
	printf(" }\n");

	return;
}

void
kdebug_mbufhdr(struct mbuf *m)
{
	/* sanity check */
	if (m == NULL)
		return;

	printf("mbuf(%p){ m_next:%p m_nextpkt:%p m_data:%p "
	       "m_len:%d m_type:0x%02x m_flags:0x%02x }\n",
		m, m->m_next, m->m_nextpkt, m->m_data,
		m->m_len, m->m_type, m->m_flags);

	if (m->m_flags & M_PKTHDR) {
		printf("  m_pkthdr{ len:%d rcvif:%p }\n",
		    m->m_pkthdr.len, m->m_pkthdr.rcvif);
	}

#ifdef __FreeBSD__
	if (m->m_flags & M_EXT) {
		printf("  m_ext{ ext_buf:%p ext_free:%p "
		       "ext_size:%u ext_ref:%p }\n",
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
		printf("  m_data:\n");
		for (i = 0; i < m->m_len; i++) {
			if (i && i % 32 == 0)
				printf("\n");
			if (i % 4 == 0)
				printf(" ");
			printf("%02x", mtod(m, u_char *)[i]);
			j++;
		}
		printf("\n");
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
		panic("kdebug_sockaddr: NULL pointer was passed.\n");

	/* NOTE: We deal with port number as host byte order. */
	printf("sockaddr{ len=%u family=%u", sysdep_sa_len(addr), addr->sa_family);

	switch (addr->sa_family) {
	case AF_INET:
		sin4 = (void *)addr;
		printf(" port=%u\n", ntohs(sin4->sin_port));
		ipsec_hexdump(&sin4->sin_addr, sizeof(sin4->sin_addr));
		break;
#ifdef INET6
	case AF_INET6:
		sin6 = (void *)addr;
		printf(" port=%u\n", ntohs(sin6->sin6_port));
		printf("  flowinfo=0x%08x, scope_id=0x%08x\n",
		    sin6->sin6_flowinfo, sin6->sin6_scope_id);
		ipsec_hexdump(&sin6->sin6_addr, sizeof(sin6->sin6_addr));
		break;
#endif
	}

	printf("  }\n");

	return;
}

void
ipsec_hexdump(const void *buf, int len)
{
	int i;

	for (i = 0; i < len; i++) {
		if (i != 0 && i % 32 == 0) printf("\n");
		if (i % 4 == 0) printf(" ");
		printf("%02x", ((const unsigned char *)buf)[i]);
	}
#if 0
	if (i % 32 != 0) printf("\n");
#endif

	return;
}
