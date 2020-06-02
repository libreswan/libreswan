/*	$NetBSD: libpfkey.h,v 1.21 2018/09/06 09:54:36 maxv Exp $	*/

/* Id: libpfkey.h,v 1.13 2005/12/04 20:26:43 manubsd Exp */

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

#ifndef _LIBPFKEY_H
#define _LIBPFKEY_H

#ifndef KAME_LIBPFKEY_H
#define KAME_LIBPFKEY_H

#define PRIORITY_LOW        0xC0000000
#define PRIORITY_DEFAULT    0x80000000
#define PRIORITY_HIGH       0x40000000

#define PRIORITY_OFFSET_POSITIVE_MAX	0x3fffffff
#define PRIORITY_OFFSET_NEGATIVE_MAX	0x40000000

struct sadb_msg;
extern void pfkey_sadump(struct sadb_msg *);
extern void pfkey_sadump_withports(struct sadb_msg *);
extern void pfkey_spdump(struct sadb_msg *);
extern void pfkey_spdump_withports(struct sadb_msg *);

struct sockaddr;
struct sadb_alg;

#include <sys/types.h>
#include PATH_IPSEC_H

#ifndef HAVE_IPSEC_POLICY_T
typedef caddr_t ipsec_policy_t;
#ifdef __NetBSD__
#define __ipsec_const const
#else
#define __ipsec_const
#endif
#else
#define __ipsec_const const
#endif

struct pfkey_send_sa_args {
	int 		so;			/* socket */
	u_int		type;			
	u_int 		satype;
	u_int		mode;
	struct sockaddr *src;			/* IP src address for SA */
	struct sockaddr *dst;			/* IP dst address for SA */
	u_int32_t 	spi;			/* SA's spi */
	u_int32_t 	reqid;
	u_int		wsize;
	caddr_t		keymat;
	u_int		e_type, e_keylen;	/* Encryption alg and keylen */
	u_int		a_type, a_keylen;	/* Authentication alg and key */
	u_int		flags;
	u_int32_t	l_alloc;
	u_int32_t	l_bytes;
	u_int32_t	l_addtime;
	u_int32_t	l_usetime;
	u_int32_t	seq;
	u_int8_t	l_natt_type;
	u_int16_t	l_natt_sport, l_natt_dport;
	struct sockaddr *l_natt_oa;
	u_int16_t	l_natt_frag;
	u_int8_t ctxdoi, ctxalg;	/* Security context DOI and algorithm */
	caddr_t ctxstr;			/* Security context string */
	u_int16_t ctxstrlen;		/* length of security context string */
};

/* The options built into libipsec */
extern int libipsec_opt;
#define LIBIPSEC_OPT_NATT		0x01
#define LIBIPSEC_OPT_FRAG		0x02
#define LIBIPSEC_OPT_SEC_CTX		0x04

/* IPsec Library Routines */

int ipsec_check_keylen(u_int, u_int, u_int);
int ipsec_check_keylen2(u_int, u_int, u_int);
int ipsec_get_keylen(u_int, u_int, struct sadb_alg *);
char *ipsec_dump_policy_withports(void *, const char *);
void ipsec_hexdump(const void *, int);
const char *ipsec_strerror(void);
void kdebug_sadb(struct sadb_msg *);
ipsec_policy_t ipsec_set_policy(__ipsec_const char *, int);
int  ipsec_get_policylen(ipsec_policy_t);
char *ipsec_dump_policy(ipsec_policy_t, __ipsec_const char *);

/* PFKey Routines */

u_int pfkey_set_softrate(u_int, u_int);
u_int pfkey_get_softrate(u_int);
int pfkey_send_getspi(int, u_int, u_int, struct sockaddr *,
	struct sockaddr *, u_int32_t, u_int32_t, u_int32_t, u_int32_t);
int pfkey_send_getspi_nat(int, u_int, u_int,
	struct sockaddr *, struct sockaddr *, u_int8_t, u_int16_t, u_int16_t,
	u_int32_t, u_int32_t, u_int32_t, u_int32_t);

int pfkey_send_update2(struct pfkey_send_sa_args *);
int pfkey_send_add2(struct pfkey_send_sa_args *); 
int pfkey_send_delete(int, u_int, u_int,
	struct sockaddr *, struct sockaddr *, u_int32_t);
int pfkey_send_delete_all(int, u_int, u_int,
	struct sockaddr *, struct sockaddr *);
int pfkey_send_get(int, u_int, u_int,
	struct sockaddr *, struct sockaddr *, u_int32_t);
int pfkey_send_register(int, u_int);
int pfkey_recv_register(int);
int pfkey_set_supported(struct sadb_msg *, int);
int pfkey_send_flush(int, u_int);
int pfkey_send_dump(int, u_int);
int pfkey_send_promisc_toggle(int, int);
int pfkey_send_spdadd(int, struct sockaddr *, u_int,
	struct sockaddr *, u_int, u_int, caddr_t, int, u_int32_t);
int pfkey_send_spdadd2(int, struct sockaddr *, u_int,
	struct sockaddr *, u_int, u_int, u_int64_t, u_int64_t,
	caddr_t, int, u_int32_t);
int pfkey_send_spdupdate(int, struct sockaddr *, u_int,
	struct sockaddr *, u_int, u_int, caddr_t, int, u_int32_t);
int pfkey_send_spdupdate2(int, struct sockaddr *, u_int,
	struct sockaddr *, u_int, u_int, u_int64_t, u_int64_t,
	caddr_t, int, u_int32_t);
int pfkey_send_spddelete(int, struct sockaddr *, u_int,
	struct sockaddr *, u_int, u_int, caddr_t, int, u_int32_t);
int pfkey_send_spddelete2(int, u_int32_t);
int pfkey_send_spdget(int, u_int32_t);
int pfkey_send_spdsetidx(int, struct sockaddr *, u_int,
	struct sockaddr *, u_int, u_int, caddr_t, int, u_int32_t);
int pfkey_send_spdflush(int);
int pfkey_send_spddump(int);
#ifdef SADB_X_MIGRATE
int pfkey_send_migrate(int, struct sockaddr *, struct sockaddr *,
        struct sockaddr *, u_int, struct sockaddr *, u_int, u_int,
        caddr_t, int, u_int32_t);
#endif

/* XXX should be somewhere else !!!
 */
#ifdef SADB_X_EXT_NAT_T_TYPE
#define PFKEY_ADDR_X_PORT(ext) (ntohs(((struct sadb_x_nat_t_port *)ext)->sadb_x_nat_t_port_port))
#define PFKEY_ADDR_X_NATTYPE(ext) ( ext != NULL && ((struct sadb_x_nat_t_type *)ext)->sadb_x_nat_t_type_type )
#endif


int pfkey_open(void);
void pfkey_close(int);
int pfkey_set_buffer_size(int, int);
struct sadb_msg *pfkey_recv(int);
int pfkey_send(int, struct sadb_msg *, int);
int pfkey_align(struct sadb_msg *, caddr_t *);
int pfkey_check(caddr_t *);

/* 
 * Deprecated, available for backward compatibility with third party 
 * libipsec users. Please use pfkey_send_update2 and pfkey_send_add2 instead
 */
int pfkey_send_update(int, u_int, u_int, struct sockaddr *,
	struct sockaddr *, u_int32_t, u_int32_t, u_int,
	caddr_t, u_int, u_int, u_int, u_int, u_int, u_int32_t, u_int64_t,
	u_int64_t, u_int64_t, u_int32_t);
int pfkey_send_update_nat(int, u_int, u_int, struct sockaddr *,
	struct sockaddr *, u_int32_t, u_int32_t, u_int,
	caddr_t, u_int, u_int, u_int, u_int, u_int, u_int32_t, u_int64_t,
	u_int64_t, u_int64_t, u_int32_t,
	u_int8_t, u_int16_t, u_int16_t, struct sockaddr *, u_int16_t);
int pfkey_send_add(int, u_int, u_int, struct sockaddr *,
	struct sockaddr *, u_int32_t, u_int32_t, u_int,
	caddr_t, u_int, u_int, u_int, u_int, u_int, u_int32_t, u_int64_t,
	u_int64_t, u_int64_t, u_int32_t);
int pfkey_send_add_nat(int, u_int, u_int, struct sockaddr *,
	struct sockaddr *, u_int32_t, u_int32_t, u_int,
	caddr_t, u_int, u_int, u_int, u_int, u_int, u_int32_t, u_int64_t,
	u_int64_t, u_int64_t, u_int32_t,
	u_int8_t, u_int16_t, u_int16_t, struct sockaddr *, u_int16_t);

#ifndef __SYSDEP_SA_LEN__
#define __SYSDEP_SA_LEN__
#include <netinet/in.h>

#ifndef IPPROTO_IPV4
#define IPPROTO_IPV4 IPPROTO_IPIP
#endif

#ifndef IPPROTO_IPCOMP
#define IPPROTO_IPCOMP IPPROTO_COMP
#endif

#ifndef IPPROTO_MH
#define IPPROTO_MH		135
#endif

static __inline u_int8_t
sysdep_sa_len (const struct sockaddr *sa)
{
#ifdef __linux__
  switch (sa->sa_family)
    {
    case AF_INET:
      return sizeof (struct sockaddr_in);
    case AF_INET6:
      return sizeof (struct sockaddr_in6);
    }
  // log_print ("sysdep_sa_len: unknown sa family %d", sa->sa_family);
  return sizeof (struct sockaddr_in);
#else
  return sa->sa_len;
#endif
}
#endif

#endif /* KAME_LIBPFKEY_H */

#endif /* _LIBPFKEY_H */
