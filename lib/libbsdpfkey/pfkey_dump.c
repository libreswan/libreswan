/*	$NetBSD: pfkey_dump.c,v 1.24 2018/05/28 20:45:38 maxv Exp $	*/

/*	$KAME: pfkey_dump.c,v 1.45 2003/09/08 10:14:56 itojun Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, 1998, and 1999 WIDE Project.
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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include PATH_IPSEC_H
#include <net/pfkeyv2.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <netdb.h>

#include "ipsec_strerror.h"
#include "libpfkey.h"

#include "lswlog.h"
#define printf(ARGS, ...)  DBGF(DBG_CRYPT, ARGS, ##__VA_ARGS__)

/* cope with old kame headers - ugly */
#ifndef SADB_X_AALG_MD5
#define SADB_X_AALG_MD5		SADB_AALG_MD5	
#endif
#ifndef SADB_X_AALG_SHA
#define SADB_X_AALG_SHA		SADB_AALG_SHA
#endif
#ifndef SADB_X_AALG_NULL
#define SADB_X_AALG_NULL	SADB_AALG_NULL
#endif

#ifndef SADB_X_EALG_BLOWFISHCBC
#define SADB_X_EALG_BLOWFISHCBC	SADB_EALG_BLOWFISHCBC
#endif
#ifndef SADB_X_EALG_CAST128CBC
#define SADB_X_EALG_CAST128CBC	SADB_EALG_CAST128CBC
#endif
#ifndef SADB_X_EALG_RC5CBC
#ifdef SADB_EALG_RC5CBC
#define SADB_X_EALG_RC5CBC	SADB_EALG_RC5CBC
#endif
#endif
#if defined(SADB_X_EALG_AES) && ! defined(SADB_X_EALG_AESCBC)
#define SADB_X_EALG_AESCBC  SADB_X_EALG_AES
#endif

#define GETMSGSTR(str, num) \
do { \
	/*CONSTCOND*/ \
	if (sizeof((str)[0]) == 0 \
	 || num >= sizeof(str)/sizeof((str)[0])) \
		printf("%u ", (num)) \
	else if (strlen((str)[(num)]) == 0) \
		printf("%u ", (num)) \
	else \
		printf("%s ", (str)[(num)]); \
} while (/*CONSTCOND*/0)

#define GETMSGV2S(v2s, num) \
do { \
	struct val2str *p;  \
	for (p = (v2s); p && p->str; p++) { \
		if (p->val == (num)) \
			break; \
	} \
	if (p && p->str) \
		printf("%s ", p->str) \
	else \
		printf("%u ", (num)) \
} while (/*CONSTCOND*/0)

static const char *str_ipaddr(struct sockaddr *);
static const char *str_ipport(struct sockaddr *);
static const char *str_prefport(u_int, u_int, u_int, u_int);
static void str_upperspec(u_int, u_int, u_int);
static char *str_time(time_t);
static void str_lifetime_byte(struct sadb_lifetime *, const char *);
static void pfkey_sadump1(struct sadb_msg *, int);
static void pfkey_spdump1(struct sadb_msg *, int);

struct val2str {
	int val;
	const char *str;
};

/*
 * Must to be re-written about following strings.
 */
static const char *str_satype[] = {
	"unspec",
	"unknown",
	"ah",
	"esp",
	"unknown",
	"rsvp",
	"ospfv2",
	"ripv2",
	"mip",
	"ipcomp",
	"policy",
	"tcp",
};

static const char *str_mode[] = {
	"any",
	"transport",
	"tunnel",
};

static const char *str_state[] = {
	"larval",
	"mature",
	"dying",
	"dead",
};

static struct val2str str_alg_auth[] = {
	{ SADB_AALG_NONE, "none", },
	{ SADB_AALG_MD5HMAC, "hmac-md5", },
	{ SADB_AALG_SHA1HMAC, "hmac-sha1", },
	{ SADB_X_AALG_MD5, "md5", },
	{ SADB_X_AALG_SHA, "sha", },
	{ SADB_X_AALG_NULL, "null", },
#ifdef SADB_X_AALG_TCP_MD5
	{ SADB_X_AALG_TCP_MD5, "tcp-md5", },
#endif
#ifdef SADB_X_AALG_SHA2_256
	{ SADB_X_AALG_SHA2_256, "hmac-sha256", },
#endif
#ifdef SADB_X_AALG_SHA2_384
	{ SADB_X_AALG_SHA2_384, "hmac-sha384", },
#endif
#ifdef SADB_X_AALG_SHA2_512
	{ SADB_X_AALG_SHA2_512, "hmac-sha512", },
#endif
#ifdef SADB_X_AALG_RIPEMD160HMAC
	{ SADB_X_AALG_RIPEMD160HMAC, "hmac-ripemd160", },
#endif
#ifdef SADB_X_AALG_AES_XCBC_MAC
	{ SADB_X_AALG_AES_XCBC_MAC, "aes-xcbc-mac", },
#endif
	{ -1, NULL, },
};

static struct val2str str_alg_enc[] = {
	{ SADB_EALG_NONE, "none", },
	{ SADB_EALG_DESCBC, "des-cbc", },
	{ SADB_EALG_3DESCBC, "3des-cbc", },
	{ SADB_EALG_NULL, "null", },
#ifdef SADB_X_EALG_RC5CBC
	{ SADB_X_EALG_RC5CBC, "rc5-cbc", },
#endif
	{ SADB_X_EALG_CAST128CBC, "cast128-cbc", },
	{ SADB_X_EALG_BLOWFISHCBC, "blowfish-cbc", },
#ifdef SADB_X_EALG_AESCBC
	{ SADB_X_EALG_AESCBC, "aes-cbc", },
#endif
#ifdef SADB_X_EALG_TWOFISHCBC
	{ SADB_X_EALG_TWOFISHCBC, "twofish-cbc", },
#endif
#ifdef SADB_X_EALG_AESCTR
	{ SADB_X_EALG_AESCTR, "aes-ctr", },
#endif
#ifdef SADB_X_EALG_AESGCM16
	{ SADB_X_EALG_AESGCM16, "aes-gcm-16", },
#endif
#ifdef SADB_X_EALG_AESGMAC
	{ SADB_X_EALG_AESGMAC, "aes-gmac", },
#endif
#ifdef SADB_X_EALG_CAMELLIACBC
	{ SADB_X_EALG_CAMELLIACBC, "camellia-cbc", },
#endif
	{ -1, NULL, },
};

static struct val2str str_alg_comp[] = {
	{ SADB_X_CALG_NONE, "none", },
	{ SADB_X_CALG_OUI, "oui", },
	{ SADB_X_CALG_DEFLATE, "deflate", },
	{ SADB_X_CALG_LZS, "lzs", },
	{ -1, NULL, },
};

/*
 * dump SADB_MSG formatted.  For debugging, you should use kdebug_sadb().
 */

void
pfkey_sadump(struct sadb_msg *m)
{
	pfkey_sadump1(m, 0);
}

void
pfkey_sadump_withports(struct sadb_msg *m)
{
	pfkey_sadump1(m, 1);
}

void
pfkey_sadump1(struct sadb_msg *m, int withports)
{
	caddr_t mhp[SADB_EXT_MAX + 1];
	struct sadb_sa *m_sa;
	struct sadb_x_sa2 *m_sa2;
	struct sadb_lifetime *m_lftc, *m_lfth, *m_lfts;
	struct sadb_address *m_saddr, *m_daddr;
#ifdef notdef
	struct sadb_address *m_paddr;
#endif
	struct sadb_key *m_auth, *m_enc;
#ifdef notdef
	struct sadb_ident *m_sid, *m_did;
	struct sadb_sens *m_sens;
#endif
#ifdef SADB_X_EXT_SEC_CTX
	struct sadb_x_sec_ctx *m_sec_ctx;
#endif
#ifdef SADB_X_EXT_NAT_T_TYPE
	struct sadb_x_nat_t_type *natt_type;
	struct sadb_x_nat_t_port *natt_sport, *natt_dport;
	struct sadb_address *natt_oa;
#ifdef SADB_X_EXT_NAT_T_FRAG
	struct sadb_x_nat_t_frag *esp_frag;
#endif

	int use_natt = 0;
#endif
	struct sockaddr *sa;

	/* check pfkey message. */
	if (pfkey_align(m, mhp)) {
		printf("%s\n", ipsec_strerror());
		return;
	}
	if (pfkey_check(mhp)) {
		printf("%s\n", ipsec_strerror());
		return;
	}

	m_sa = (void *)mhp[SADB_EXT_SA];
	m_sa2 = (void *)mhp[SADB_X_EXT_SA2];
	m_lftc = (void *)mhp[SADB_EXT_LIFETIME_CURRENT];
	m_lfth = (void *)mhp[SADB_EXT_LIFETIME_HARD];
	m_lfts = (void *)mhp[SADB_EXT_LIFETIME_SOFT];
	m_saddr = (void *)mhp[SADB_EXT_ADDRESS_SRC];
	m_daddr = (void *)mhp[SADB_EXT_ADDRESS_DST];
#ifdef notdef
	m_paddr = (void *)mhp[SADB_EXT_ADDRESS_PROXY];
#endif
	m_auth = (void *)mhp[SADB_EXT_KEY_AUTH];
	m_enc = (void *)mhp[SADB_EXT_KEY_ENCRYPT];
#ifdef notdef
	m_sid = (void *)mhp[SADB_EXT_IDENTITY_SRC];
	m_did = (void *)mhp[SADB_EXT_IDENTITY_DST];
	m_sens = (void *)mhp[SADB_EXT_SENSITIVITY];
#endif
#ifdef SADB_X_EXT_SEC_CTX
	m_sec_ctx = (struct sadb_x_sec_ctx *)mhp[SADB_X_EXT_SEC_CTX];
#endif
#ifdef SADB_X_EXT_NAT_T_TYPE
	natt_type = (void *)mhp[SADB_X_EXT_NAT_T_TYPE];
	natt_sport = (void *)mhp[SADB_X_EXT_NAT_T_SPORT];
	natt_dport = (void *)mhp[SADB_X_EXT_NAT_T_DPORT];
	natt_oa = (void *)mhp[SADB_X_EXT_NAT_T_OA];
#ifdef SADB_X_EXT_NAT_T_FRAG
	esp_frag = (void *)mhp[SADB_X_EXT_NAT_T_FRAG];
#endif

	if (natt_type && natt_type->sadb_x_nat_t_type_type)
		use_natt = 1;
#endif
	/* source address */
	if (m_saddr == NULL) {
		printf("no ADDRESS_SRC extension.\n");
		return;
	}
	sa = (void *)(m_saddr + 1);
	if (withports)
		printf("%s[%s]", str_ipaddr(sa), str_ipport(sa))
	else
		printf("%s", str_ipaddr(sa))
#ifdef SADB_X_EXT_NAT_T_TYPE
	if (use_natt && natt_sport)
		printf("[%u]", ntohs(natt_sport->sadb_x_nat_t_port_port));
#endif
	printf(" ");

	/* destination address */
	if (m_daddr == NULL) {
		printf(" no ADDRESS_DST extension.\n");
		return;
	}
	sa = (void *)(m_daddr + 1);
	if (withports)
		printf("%s[%s]", str_ipaddr(sa), str_ipport(sa))
	else
		printf("%s", str_ipaddr(sa))
#ifdef SADB_X_EXT_NAT_T_TYPE
	if (use_natt && natt_dport)
		printf("[%u]", ntohs(natt_dport->sadb_x_nat_t_port_port));
#endif
	printf(" ");

	/* SA type */
	if (m_sa == NULL) {
		printf("no SA extension.\n");
		return;
	}
	if (m_sa2 == NULL) {
		printf("no SA2 extension.\n");
		return;
	}
	printf("\n\t");

#ifdef SADB_X_EXT_NAT_T_TYPE
	if (use_natt && m->sadb_msg_satype == SADB_SATYPE_ESP)
		printf("esp-udp ")
	else if (use_natt)
		printf("natt+")

	if (!use_natt || m->sadb_msg_satype != SADB_SATYPE_ESP)
#endif
	GETMSGSTR(str_satype, m->sadb_msg_satype);

	printf("mode=");
	GETMSGSTR(str_mode, m_sa2->sadb_x_sa2_mode);

	printf("spi=%u(0x%08x) reqid=%u(0x%08x)\n",
		(u_int32_t)ntohl(m_sa->sadb_sa_spi),
		(u_int32_t)ntohl(m_sa->sadb_sa_spi),
		(u_int32_t)m_sa2->sadb_x_sa2_reqid,
		(u_int32_t)m_sa2->sadb_x_sa2_reqid);

#ifdef SADB_X_EXT_NAT_T_TYPE
	/* other NAT-T information */
	if (use_natt && natt_oa)
		printf("\tNAT OA=%s\n",
		       str_ipaddr((void *)(natt_oa + 1)));

#ifdef SADB_X_EXT_NAT_T_FRAG
	if (use_natt && esp_frag && esp_frag->sadb_x_nat_t_frag_fraglen != 0)
		printf("\tNAT-T esp_frag=%u\n", esp_frag->sadb_x_nat_t_frag_fraglen);
#endif
#endif

	/* encryption key */
	if (m->sadb_msg_satype == SADB_X_SATYPE_IPCOMP) {
		printf("\tC: ");
		GETMSGV2S(str_alg_comp, m_sa->sadb_sa_encrypt);
	} else if (m->sadb_msg_satype == SADB_SATYPE_ESP) {
		if (m_enc != NULL) {
			printf("\tE: ");
			GETMSGV2S(str_alg_enc, m_sa->sadb_sa_encrypt);
			ipsec_hexdump((caddr_t)(void *)m_enc + sizeof(*m_enc),
				      m_enc->sadb_key_bits / 8);
			printf("\n");
		}
	}

	/* authentication key */
	if (m_auth != NULL) {
		printf("\tA: ");
		GETMSGV2S(str_alg_auth, m_sa->sadb_sa_auth);
		ipsec_hexdump((caddr_t)(void *)m_auth + sizeof(*m_auth),
		              m_auth->sadb_key_bits / 8);
		printf("\n");
	}

	/* replay windoe size & flags */
	printf("\tseq=0x%08x replay=%u flags=0x%08x ",
		m_sa2->sadb_x_sa2_sequence,
		m_sa->sadb_sa_replay,
		m_sa->sadb_sa_flags);

	/* state */
	printf("state=");
	GETMSGSTR(str_state, m_sa->sadb_sa_state);
	printf("\n");

	/* lifetime */
	if (m_lftc != NULL) {
		time_t tmp_time = time(0);

		printf("\tcreated: %s",
			str_time((long)m_lftc->sadb_lifetime_addtime));
		printf("\tcurrent: %s\n", str_time(tmp_time));
		printf("\tdiff: %lu(s)",
			(u_long)(m_lftc->sadb_lifetime_addtime == 0 ?
			0 : (tmp_time - m_lftc->sadb_lifetime_addtime)));

		printf("\thard: %lu(s)",
			(u_long)(m_lfth == NULL ?
			0 : m_lfth->sadb_lifetime_addtime));
		printf("\tsoft: %lu(s)\n",
			(u_long)(m_lfts == NULL ?
			0 : m_lfts->sadb_lifetime_addtime));

		printf("\tlast: %s",
			str_time((long)m_lftc->sadb_lifetime_usetime));
		printf("\thard: %lu(s)",
			(u_long)(m_lfth == NULL ?
			0 : m_lfth->sadb_lifetime_usetime));
		printf("\tsoft: %lu(s)\n",
			(u_long)(m_lfts == NULL ?
			0 : m_lfts->sadb_lifetime_usetime));

		str_lifetime_byte(m_lftc, "current");
		str_lifetime_byte(m_lfth, "hard");
		str_lifetime_byte(m_lfts, "soft");
		printf("\n");

		printf("\tallocated: %lu",
			(unsigned long)m_lftc->sadb_lifetime_allocations);
		printf("\thard: %lu",
			(u_long)(m_lfth == NULL ?
			0 : m_lfth->sadb_lifetime_allocations));
		printf("\tsoft: %lu\n",
			(u_long)(m_lfts == NULL ?
			0 : m_lfts->sadb_lifetime_allocations));
	}

#ifdef SADB_X_EXT_SEC_CTX
	if (m_sec_ctx != NULL) {
		printf("\tsecurity context doi: %u\n",
					m_sec_ctx->sadb_x_ctx_doi);
		printf("\tsecurity context algorithm: %u\n",
					m_sec_ctx->sadb_x_ctx_alg);
		printf("\tsecurity context length: %u\n",
					m_sec_ctx->sadb_x_ctx_len);
		printf("\tsecurity context: %s\n",
			(char *)m_sec_ctx + sizeof(struct sadb_x_sec_ctx));
	}
#endif

	printf("\tsadb_seq=%lu pid=%lu ",
		(u_long)m->sadb_msg_seq,
		(u_long)m->sadb_msg_pid);

	/* XXX DEBUG */
	printf("refcnt=%u\n", m->sadb_msg_reserved);

	return;
}

void
pfkey_spdump(struct sadb_msg *m)
{
	pfkey_spdump1(m, 0);
}

void
pfkey_spdump_withports(struct sadb_msg *m)
{
	pfkey_spdump1(m, 1);
}

static void
pfkey_spdump1(struct sadb_msg *m, int withports)
{
	char pbuf[NI_MAXSERV];
	caddr_t mhp[SADB_EXT_MAX + 1];
	struct sadb_address *m_saddr, *m_daddr;
#ifdef SADB_X_EXT_TAG
	struct sadb_x_tag *m_tag;
#endif
	struct sadb_x_policy *m_xpl;
	struct sadb_lifetime *m_lftc = NULL, *m_lfth = NULL;
#ifdef SADB_X_EXT_SEC_CTX
	struct sadb_x_sec_ctx *m_sec_ctx;
#endif
	struct sockaddr *sa;
	u_int16_t sport = 0, dport = 0;

	/* check pfkey message. */
	if (pfkey_align(m, mhp)) {
		printf("%s\n", ipsec_strerror());
		return;
	}
	if (pfkey_check(mhp)) {
		printf("%s\n", ipsec_strerror());
		return;
	}

	m_saddr = (void *)mhp[SADB_EXT_ADDRESS_SRC];
	m_daddr = (void *)mhp[SADB_EXT_ADDRESS_DST];
#ifdef SADB_X_EXT_TAG
	m_tag = (void *)mhp[SADB_X_EXT_TAG];
#endif
	m_xpl = (void *)mhp[SADB_X_EXT_POLICY];
	m_lftc = (void *)mhp[SADB_EXT_LIFETIME_CURRENT];
	m_lfth = (void *)mhp[SADB_EXT_LIFETIME_HARD];

#ifdef SADB_X_EXT_SEC_CTX
	m_sec_ctx = (struct sadb_x_sec_ctx *)mhp[SADB_X_EXT_SEC_CTX];
#endif
#ifdef __linux__
	/* *bsd indicates per-socket policies by omitting src and dst 
	 * extensions. Linux always includes them, but we can catch it
	 * by checkin for policy id.
	 */
	if (m_xpl->sadb_x_policy_id % 8 >= 3) {
		printf("(per-socket policy) ");
	} else
#endif
	if (m_saddr && m_daddr) {
		/* source address */
		sa = (void *)(m_saddr + 1);
		switch (sa->sa_family) {
		case AF_INET:
		case AF_INET6:
			if (getnameinfo(sa, (socklen_t)sysdep_sa_len(sa), NULL,
			    0, pbuf, sizeof(pbuf), NI_NUMERICSERV) != 0)
				sport = 0;	/*XXX*/
			else
				sport = atoi(pbuf);
			printf("%s%s ", str_ipaddr(sa),
				str_prefport((u_int)sa->sa_family,
				    (u_int)m_saddr->sadb_address_prefixlen, 
				    (u_int)sport,
				    (u_int)m_saddr->sadb_address_proto));
			break;
		default:
			printf("unknown-af ");
			break;
		}

		/* destination address */
		sa = (void *)(m_daddr + 1);
		switch (sa->sa_family) {
		case AF_INET:
		case AF_INET6:
			if (getnameinfo(sa, (socklen_t)sysdep_sa_len(sa), NULL,
			    0, pbuf, sizeof(pbuf), NI_NUMERICSERV) != 0)
				dport = 0;	/*XXX*/
			else
				dport = atoi(pbuf);
			printf("%s%s ", str_ipaddr(sa),
				str_prefport((u_int)sa->sa_family,
				    (u_int)m_daddr->sadb_address_prefixlen, 
				    (u_int)dport,
				    (u_int)m_saddr->sadb_address_proto));
			break;
		default:
			printf("unknown-af ");
			break;
		}

		/* upper layer protocol */
		if (m_saddr->sadb_address_proto !=
		    m_daddr->sadb_address_proto) {
			printf("upper layer protocol mismatched.\n");
			return;
		}
		str_upperspec((u_int)m_saddr->sadb_address_proto, (u_int)sport,
		    (u_int)dport);
	}
#ifdef SADB_X_EXT_TAG
	else if (m_tag)
		printf("tagged \"%s\" ", m_tag->sadb_x_tag_name);
#endif
	else
		printf("(no selector, probably per-socket policy) ");

	/* policy */
    {
	char *d_xpl;

	if (m_xpl == NULL) {
		printf("no X_POLICY extension.\n");
		return;
	}
	if (withports)
		d_xpl = ipsec_dump_policy_withports(m_xpl, "\n\t");
	else
		d_xpl = ipsec_dump_policy((ipsec_policy_t)m_xpl, "\n\t");
		
	if (!d_xpl)
		printf("\n\tPolicy:[%s]\n", ipsec_strerror())
	else {
		/* dump SPD */
		printf("\n\t%s\n", d_xpl);
		free(d_xpl);
	}
    }

	/* lifetime */
	if (m_lftc) {
		printf("\tcreated: %s  ",
			str_time((long)m_lftc->sadb_lifetime_addtime));
		printf("lastused: %s\n",
			str_time((long)m_lftc->sadb_lifetime_usetime));
	}
	if (m_lfth) {
		printf("\tlifetime: %lu(s) ",
			(u_long)m_lfth->sadb_lifetime_addtime);
		printf("validtime: %lu(s)\n",
			(u_long)m_lfth->sadb_lifetime_usetime);
	}

#ifdef SADB_X_EXT_SEC_CTX
	if (m_sec_ctx != NULL) {
		printf("\tsecurity context doi: %u\n",
					m_sec_ctx->sadb_x_ctx_doi);
		printf("\tsecurity context algorithm: %u\n",
					m_sec_ctx->sadb_x_ctx_alg);
		printf("\tsecurity context length: %u\n",
					m_sec_ctx->sadb_x_ctx_len);
		printf("\tsecurity context: %s\n",
			(char *)m_sec_ctx + sizeof(struct sadb_x_sec_ctx));
	}
#endif

	printf("\tspid=%ld seq=%ld pid=%ld\n",
		(u_long)m_xpl->sadb_x_policy_id,
		(u_long)m->sadb_msg_seq,
		(u_long)m->sadb_msg_pid);

	/* XXX TEST */
	printf("\trefcnt=%u\n", m->sadb_msg_reserved);

	return;
}

/*
 * set "ipaddress" to buffer.
 */
static const char *
str_ipaddr(struct sockaddr *sa)
{
	static char buf[NI_MAXHOST];
	const int niflag = NI_NUMERICHOST;

	if (sa == NULL)
		return "";

	if (getnameinfo(sa, (socklen_t)sysdep_sa_len(sa), buf, sizeof(buf), 
	    NULL, 0, niflag) == 0)
		return buf;
	return NULL;
}

/*
 * set "port" to buffer.
 */
static const char *
str_ipport(struct sockaddr *sa)
{
	static char buf[NI_MAXHOST];
	const int niflag = NI_NUMERICSERV;

	if (sa == NULL)
		return "";

	if (getnameinfo(sa, (socklen_t)sysdep_sa_len(sa), NULL, 0, 
	    buf, sizeof(buf), niflag) == 0)
		return buf;
	return NULL;
}


/*
 * set "/prefix[port number]" to buffer.
 */
static const char *
str_prefport(u_int family, u_int pref, u_int port, u_int ulp)
{
	static char buf[128];
	char prefbuf[128];
	char portbuf[128];
	size_t plen;

	switch (family) {
	case AF_INET:
		plen = sizeof(struct in_addr) << 3;
		break;
	case AF_INET6:
		plen = sizeof(struct in6_addr) << 3;
		break;
	default:
		return "?";
	}

	if (pref == plen)
		prefbuf[0] = '\0';
	else
		snprintf(prefbuf, sizeof(prefbuf), "/%u", pref);

	switch (ulp) {
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
	case IPPROTO_MH:
	case IPPROTO_GRE:
		memset(portbuf, 0, sizeof(portbuf));
		break;
	default:
		if (port == IPSEC_PORT_ANY)
			strcpy(portbuf, "[any]");
		else
			snprintf(portbuf, sizeof(portbuf), "[%u]", port);
		break;
	}

	snprintf(buf, sizeof(buf), "%s%s", prefbuf, portbuf);

	return buf;
}

static void
str_upperspec(u_int ulp, u_int p1, u_int p2)
{
	struct protoent *ent;

	ent = getprotobynumber((int)ulp);
	if (ent)
		printf("%u(%s)", ulp, ent->p_name)
	else
		printf("%u", ulp);

	if (p1 == IPSEC_PORT_ANY && p2 == IPSEC_PORT_ANY)
		return;

	switch (ulp) {
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
	case IPPROTO_MH:
		printf(" %u,%u", p1, p2);
		break;
	case IPPROTO_GRE:
		printf(" %u", (p1 << 16) + p2);
		break;
	}
}

/*
 * set "Mon Day Time Year" to buffer
 */
static char *
str_time(time_t t)
{
	static char buf[128];

	if (t == 0) {
		int i = 0;
		for (;i < 20;) buf[i++] = ' ';
	} else {
		char *t0;
		if ((t0 = ctime(&t)) == NULL)
			memset(buf, '?', 20);
		else
			memcpy(buf, t0 + 4, 20);
	}

	buf[20] = '\0';

	return(buf);
}

static void
str_lifetime_byte(struct sadb_lifetime *x, const char *str)
{
	double y;
	const char *unit;
	int w;

	if (x == NULL) {
		printf("\t%s: 0(bytes)", str);
		return;
	}

#if 0
	if ((x->sadb_lifetime_bytes) / 1024 / 1024) {
		y = (x->sadb_lifetime_bytes) * 1.0 / 1024 / 1024;
		unit = "M";
		w = 1;
	} else if ((x->sadb_lifetime_bytes) / 1024) {
		y = (x->sadb_lifetime_bytes) * 1.0 / 1024;
		unit = "K";
		w = 1;
	} else {
		y = (x->sadb_lifetime_bytes) * 1.0;
		unit = "";
		w = 0;
	}
#else
	y = (x->sadb_lifetime_bytes) * 1.0;
	unit = "";
	w = 0;
#endif
	printf("\t%s: %.*f(%sbytes)", str, w, y, unit);
}
