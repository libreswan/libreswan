/*
 * Cryptographic helper function - calculate DH
 *
 * Copyright (C) 2006-2008 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2007-2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2015 Paul Wouters <pwouters@redaht.com>
 * Copyright (C) 2017 Antony Antony <antony@phenome.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * This code was developed with the support of IXIA communications.
 *
 */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <signal.h>

#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "packet.h"
#include "demux.h"
#include "crypto.h"
#include "rnd.h"
#include "state.h"
#include "pluto_crypt.h"
#include "lswlog.h"
#include "log.h"
#include "ike_alg.h"
#include "id.h"
#include "keys.h"
#include "crypt_symkey.h" /* to get free_any_symkey */
#include "crypt_dh.h"

void cancelled_v1_dh(struct pcr_v1_dh *dh)
{
	/* query */
	free_dh_secret(&dh->secret); /* helper must be owner */
	release_symkey("cancelled IKEv1 DH", "skey_d_old", &dh->skey_d_old);

	/* response */
	release_symkey("cancelled IKEv1 DH", "shared", &dh->shared);
	release_symkey("cancelled IKEv1 DH", "skeyid", &dh->skeyid);
	release_symkey("cancelled IKEv1 DH", "skeyid_d", &dh->skeyid_d);
	release_symkey("cancelled IKEv1 DH", "skeyid_a", &dh->skeyid_a);
	release_symkey("cancelled IKEv1 DH", "skeyid_e", &dh->skeyid_e);
	release_symkey("cancelled IKEv1 DH", "enc_key", &dh->enc_key);
	freeanychunk(dh->new_iv);
}

/*
 * invoke helper to do DH work (IKEv1)
 */
void start_dh_v1_secretiv(crypto_req_cont_func fn, const char *name,
			  struct state *st, enum original_role role,
			  const struct oakley_group_desc *oakley_group2)
{
	const chunk_t *pss = get_psk(st->st_connection);

	struct pluto_crypto_req_cont *dh = new_pcrc(fn, name);
	struct pcr_v1_dh *const dhq = pcr_v1_dh_init(dh, pcr_compute_dh_iv);

	/* convert appropriate data to dhq */
	dhq->auth = st->st_oakley.auth;
	dhq->prf = st->st_oakley.ta_prf;
	dhq->oakley_group = oakley_group2;
	dhq->encrypter = st->st_oakley.ta_encrypt;
	dhq->role = role;
	dhq->key_size = st->st_oakley.enckeylen / BITS_PER_BYTE;
	dhq->salt_size = st->st_oakley.ta_encrypt->salt_size;

	passert(dhq->oakley_group != NULL && dhq->oakley_group != &unset_group);

	if (pss != NULL)
		WIRE_CLONE_CHUNK(*dhq, pss, *pss);
	WIRE_CLONE_CHUNK(*dhq, ni, st->st_ni);
	WIRE_CLONE_CHUNK(*dhq, nr, st->st_nr);
	WIRE_CLONE_CHUNK(*dhq, gi, st->st_gi);
	WIRE_CLONE_CHUNK(*dhq, gr, st->st_gr);

	transfer_dh_secret_to_helper(st, "IKEv1 DH+IV", &dhq->secret);

	ALLOC_WIRE_CHUNK(*dhq, icookie, COOKIE_SIZE);
	memcpy(WIRE_CHUNK_PTR(*dhq, icookie),
	       st->st_icookie, COOKIE_SIZE);

	ALLOC_WIRE_CHUNK(*dhq, rcookie, COOKIE_SIZE);
	memcpy(WIRE_CHUNK_PTR(*dhq, rcookie),
	       st->st_rcookie, COOKIE_SIZE);

	send_crypto_helper_request(st, dh);
}

bool finish_dh_secretiv(struct state *st,
			struct pluto_crypto_req *r)
{
	struct pcr_v1_dh *dhr = &r->pcr_d.v1_dh;

	transfer_dh_secret_to_state("IKEv1 DH+IV", &dhr->secret, st);

	st->st_shared_nss = dhr->shared;
	st->st_skeyid_nss = dhr->skeyid;
	st->st_skeyid_d_nss = dhr->skeyid_d;
	st->st_skeyid_a_nss = dhr->skeyid_a;
	st->st_skeyid_e_nss = dhr->skeyid_e;
	st->st_enc_key_nss = dhr->enc_key;

	st->hidden_variables.st_skeyid_calculated = TRUE;

	if (st->st_shared_nss == NULL) {
		return FALSE;
	} else {
		passert(dhr->new_iv.len <= MAX_DIGEST_LEN);
		passert(dhr->new_iv.len > 0);
		memcpy(st->st_new_iv, dhr->new_iv.ptr, dhr->new_iv.len);
		st->st_new_iv_len = dhr->new_iv.len;
		freeanychunk(dhr->new_iv);
		return TRUE;
	}
}

void start_dh_v1_secret(crypto_req_cont_func fn, const char *name,
			struct state *st, enum original_role role,
			const struct oakley_group_desc *oakley_group2)
{
	const chunk_t *pss = get_psk(st->st_connection);
	struct pluto_crypto_req_cont *cn = new_pcrc(fn, name);
	struct pcr_v1_dh *const dhq = pcr_v1_dh_init(cn, pcr_compute_dh);

	/* convert appropriate data to dhq */
	dhq->auth = st->st_oakley.auth;
	dhq->prf = st->st_oakley.ta_prf;
	dhq->oakley_group = oakley_group2;
	dhq->role = role;
	dhq->key_size = st->st_oakley.enckeylen / BITS_PER_BYTE;
	dhq->salt_size = st->st_oakley.ta_encrypt->salt_size;

	if (pss != NULL)
		WIRE_CLONE_CHUNK(*dhq, pss, *pss);
	WIRE_CLONE_CHUNK(*dhq, ni, st->st_ni);
	WIRE_CLONE_CHUNK(*dhq, nr, st->st_nr);
	WIRE_CLONE_CHUNK(*dhq, gi, st->st_gi);
	WIRE_CLONE_CHUNK(*dhq, gr, st->st_gr);

	transfer_dh_secret_to_helper(st, "IKEv1 DH", &dhq->secret);

	ALLOC_WIRE_CHUNK(*dhq, icookie, COOKIE_SIZE);
	memcpy(WIRE_CHUNK_PTR(*dhq, icookie),
	       st->st_icookie, COOKIE_SIZE);

	ALLOC_WIRE_CHUNK(*dhq, rcookie, COOKIE_SIZE);
	memcpy(WIRE_CHUNK_PTR(*dhq, rcookie),
	       st->st_rcookie, COOKIE_SIZE);

	send_crypto_helper_request(st, cn);
}

/* NOTE: if NSS refuses to calculate DH, skr->shared == NULL */
/* MUST BE THREAD-SAFE */
void calc_dh(struct pcr_v1_dh *dh)
{
	const struct oakley_group_desc *group = dh->oakley_group;
	passert(group != NULL);

	/* now calculate the (g^x)(g^y) */
	chunk_t g;
	setchunk_from_wire(g, dh, dh->role == ORIGINAL_RESPONDER ? &dh->gi : &dh->gr);
	DBG(DBG_CRYPT, DBG_dump_chunk("peer's g: ", g));

	dh->shared = calc_dh_shared(dh->secret, g);
}

void finish_dh_secret(struct state *st,
		      struct pluto_crypto_req *r)
{
	struct pcr_v1_dh *dhr = &r->pcr_d.v1_dh;
	transfer_dh_secret_to_state("IKEv1 DH", &dhr->secret, st);
	st->st_shared_nss = dhr->shared;
}
