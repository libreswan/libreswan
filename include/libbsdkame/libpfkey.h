/* I do not understand why this is not installed into /usr/include on FreeBSD */

/*	$FreeBSD: src/lib/libipsec/libpfkey.h,v 1.4 2002/03/22 09:18:36 obrien Exp $	*/
/*	$KAME: libpfkey.h,v 1.6 2001/03/05 18:22:17 thorpej Exp $	*/

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

#define K_SADB_EXT_MAX 24

struct sadb_msg;
extern void pfkey_sadump(struct sadb_msg *);
extern void pfkey_spdump(struct sadb_msg *);

struct sockaddr;
struct sadb_alg;
int ipsec_check_keylen(unsigned, unsigned, unsigned);
int ipsec_check_keylen2(unsigned, unsigned, unsigned);
int ipsec_get_keylen(unsigned, unsigned, struct sadb_alg *);
unsigned pfkey_set_softrate(unsigned, unsigned);
unsigned pfkey_get_softrate(unsigned);
int pfkey_send_getspi(int, unsigned, unsigned, struct sockaddr *, struct sockaddr *,
		      uint32_t, uint32_t, uint32_t, uint32_t);
int pfkey_send_update(int, unsigned, unsigned, struct sockaddr *, struct sockaddr *,
		      uint32_t, uint32_t, unsigned, caddr_t, unsigned, unsigned,
		      unsigned, unsigned,
		      unsigned, uint32_t, uint64_t, uint64_t, uint64_t,
		      uint32_t);
int pfkey_send_add(int, unsigned, unsigned, struct sockaddr *, struct sockaddr *,
		   uint32_t, uint32_t, unsigned, caddr_t, unsigned, unsigned, unsigned,
		   unsigned,
		   unsigned, uint32_t, uint64_t, uint64_t, uint64_t,
		   uint32_t);
int pfkey_send_delete(int, unsigned, unsigned, struct sockaddr *, struct sockaddr *,
		      uint32_t);
int pfkey_send_delete_all(int, unsigned, unsigned, struct sockaddr *,
			  struct sockaddr *);
int pfkey_send_get(int, unsigned, unsigned, struct sockaddr *, struct sockaddr *,
		   uint32_t);
int pfkey_send_register(int, unsigned);
int pfkey_recv_register(int);
int pfkey_set_supported(const struct sadb_msg *, int);
int pfkey_send_flush(int, unsigned);
int pfkey_send_dump(int, unsigned);
int pfkey_send_promisc_toggle(int, int);
int pfkey_send_spdadd(int, const struct sockaddr *, unsigned,
		      const struct sockaddr *, unsigned,
		      unsigned, caddr_t, int, uint32_t);
int pfkey_send_spdadd2(int, struct sockaddr *, unsigned, struct sockaddr *, unsigned,
		       unsigned, uint64_t, uint64_t, caddr_t, int, uint32_t);
int pfkey_send_spdupdate(int, struct sockaddr *, unsigned, struct sockaddr *,
			 unsigned, unsigned, caddr_t, int, uint32_t);
int pfkey_send_spdupdate2(int, struct sockaddr *, unsigned, struct sockaddr *,
			  unsigned, unsigned, uint64_t, uint64_t, caddr_t, int,
			  uint32_t);
int pfkey_send_spddelete(int, const struct sockaddr *, unsigned,
			 const struct sockaddr *,
			 unsigned, unsigned, caddr_t, int, uint32_t);
int pfkey_send_spddelete2(int, uint32_t);
int pfkey_send_spdget(int, uint32_t);
int pfkey_send_spdsetidx(int, struct sockaddr *, unsigned, struct sockaddr *,
			 unsigned, unsigned, caddr_t, int, uint32_t);
int pfkey_send_spdflush(int);
int pfkey_send_spddump(int);

int pfkey_open(void);
void pfkey_close(int);
struct sadb_msg *pfkey_recv(int);
int pfkey_send(int, struct sadb_msg *, int);
int pfkey_align(struct sadb_msg *, caddr_t *);
int pfkey_check(caddr_t *);

/* like pfkey_send_add/update, but lets one specify the operation */
int pfkey_send_x1(int, unsigned, unsigned, unsigned, const struct sockaddr *,
		  const struct sockaddr *, uint32_t, uint32_t, unsigned,
		  caddr_t,
		  unsigned, unsigned, unsigned, unsigned, unsigned, uint32_t, uint32_t,
		  uint32_t, uint32_t, uint32_t);

extern void foreach_supported_alg(void (*algregister)(int satype,
						      int extype,
						      struct sadb_alg *alg));
