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
 * Copyright (C) 2017 Andrew Cagney
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

void cancelled_dh_v2(struct pcr_dh_v2 *dh)
{
	/* incoming */

	free_dh_secret(&dh->secret); /* must own */
	release_symkey("cancelled IKEv2 DH", "skey_d_old", &dh->skey_d_old);

	/* outgoing */
	release_symkey("cancelled IKEv2 DH", "shared", &dh->shared);
	release_symkey("cancelled IKEv2 DH", "skeyid_d", &dh->skeyid_d);
	release_symkey("cancelled IKEv2 DH", "skeyid_ai", &dh->skeyid_ai);
	release_symkey("cancelled IKEv2 DH", "skeyid_ar", &dh->skeyid_ar);
	release_symkey("cancelled IKEv2 DH", "skeyid_ei", &dh->skeyid_ei);
	release_symkey("cancelled IKEv2 DH", "skeyid_er", &dh->skeyid_er);
	release_symkey("cancelled IKEv2 DH", "skeyid_pi", &dh->skeyid_pi);
	release_symkey("cancelled IKEv2 DH", "skeyid_pr", &dh->skeyid_pr);

	freeanychunk(dh->skey_initiator_salt);
	freeanychunk(dh->skey_responder_salt);
	freeanychunk(dh->skey_chunk_SK_pi);
	freeanychunk(dh->skey_chunk_SK_pr);
}

/*
 * invoke helper to do DH work.
 */
void start_dh_v2(struct state *st,
		 const char *name, enum original_role role,
		 PK11SymKey *skey_d_old, /* SKEYSEED IKE Rekey */
		 const struct prf_desc *old_prf, /* IKE Rekey */
		 crypto_req_cont_func pcrc_func)
{
	struct pluto_crypto_req_cont *dh = new_pcrc(pcrc_func, name);
	struct pcr_dh_v2 *const dhq = pcr_dh_v2_init(dh);

	DBG(DBG_CONTROLMORE,
	    DBG_log("offloading IKEv2 SKEYSEED using prf=%s integ=%s cipherkey=%s",
		    st->st_oakley.ta_prf->common.fqn,
		    st->st_oakley.ta_integ->common.fqn,
		    st->st_oakley.ta_encrypt->common.fqn));

	/* convert appropriate data to dhq */
	dhq->prf = st->st_oakley.ta_prf;
	dhq->integ = st->st_oakley.ta_integ;
	dhq->dh = st->st_oakley.ta_dh;
	dhq->encrypt = st->st_oakley.ta_encrypt;
	dhq->role = role;
	dhq->key_size = st->st_oakley.enckeylen / BITS_PER_BYTE;
	dhq->salt_size = st->st_oakley.ta_encrypt->salt_size;

	passert(dhq->dh != NULL && dhq->dh != &unset_group);

	dhq->old_prf = old_prf;
	dhq->skey_d_old = reference_symkey(__func__, "skey_d_old", skey_d_old);
	if (skey_d_old != NULL) {
		passert(old_prf != NULL);
	}

	WIRE_CLONE_CHUNK(*dhq, ni, st->st_ni);
	WIRE_CLONE_CHUNK(*dhq, nr, st->st_nr);
	WIRE_CLONE_CHUNK(*dhq, gi, st->st_gi);
	WIRE_CLONE_CHUNK(*dhq, gr, st->st_gr);

	transfer_dh_secret_to_helper(st, "IKEv2 DH", &dhq->secret);

	ALLOC_WIRE_CHUNK(*dhq, icookie, COOKIE_SIZE);
	memcpy(WIRE_CHUNK_PTR(*dhq, icookie),
	       st->st_icookie, COOKIE_SIZE);

	ALLOC_WIRE_CHUNK(*dhq, rcookie, COOKIE_SIZE);
	memcpy(WIRE_CHUNK_PTR(*dhq, rcookie),
	       st->st_rcookie, COOKIE_SIZE);

	send_crypto_helper_request(st, dh);
}

bool finish_dh_v2(struct state *st,
		  struct pluto_crypto_req *r,  bool only_shared)
{
	struct pcr_dh_v2 *dhv2 = &r->pcr_d.dh_v2;

	transfer_dh_secret_to_state("IKEv2 DH", &dhv2->secret, st);

	release_symkey(__func__, "st_shared_nss", &st->st_shared_nss);
	st->st_shared_nss = dhv2->shared;

	if (only_shared) {
#define free_any_symkey(p) release_symkey(__func__, #p, &p)
		free_any_symkey(dhv2->skeyid_d);
		free_any_symkey(dhv2->skeyid_ai);
		free_any_symkey(dhv2->skeyid_ar);
		free_any_symkey(dhv2->skeyid_pi);
		free_any_symkey(dhv2->skeyid_pr);
		free_any_symkey(dhv2->skeyid_ei);
		free_any_symkey(dhv2->skeyid_er);
#undef free_any_symkey

		freeanychunk(dhv2->skey_initiator_salt);
		freeanychunk(dhv2->skey_responder_salt);
		freeanychunk(dhv2->skey_chunk_SK_pi);
		freeanychunk(dhv2->skey_chunk_SK_pr);
	} else {
		st->st_skey_d_nss = dhv2->skeyid_d;
		st->st_skey_ai_nss = dhv2->skeyid_ai;
		st->st_skey_ar_nss = dhv2->skeyid_ar;
		st->st_skey_pi_nss = dhv2->skeyid_pi;
		st->st_skey_pr_nss = dhv2->skeyid_pr;
		st->st_skey_ei_nss = dhv2->skeyid_ei;
		st->st_skey_er_nss = dhv2->skeyid_er;
		st->st_skey_initiator_salt = dhv2->skey_initiator_salt;
		st->st_skey_responder_salt = dhv2->skey_responder_salt;
		st->st_skey_chunk_SK_pi = dhv2->skey_chunk_SK_pi;
		st->st_skey_chunk_SK_pr = dhv2->skey_chunk_SK_pr;
	}

	st->hidden_variables.st_skeyid_calculated = TRUE;
	return st->st_shared_nss != NULL;	/* was NSS happy to DH? */
}
