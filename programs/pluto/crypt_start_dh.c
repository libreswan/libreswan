/*
 * Cryptographic helper function - calculate DH
 *
 * Copyright (C) 2006-2008 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2007-2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
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
#include <libreswan/ipsec_policy.h>

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
#include "timer.h"
#include "ike_alg.h"
#include "id.h"
#include "secrets.h"
#include "keys.h"

/*
 * invoke helper to do DH work.
 */
stf_status start_dh_secretiv(struct pluto_crypto_req_cont *cn,
			     struct state *st,
			     enum crypto_importance importance,
			     enum phase1_role init,        /* TRUE=g_init,FALSE=g_r */
			     u_int16_t oakley_group2)
{
	struct pluto_crypto_req r;
	struct pcr_skeyid_q *const dhq = &r.pcr_d.dhq;
	const chunk_t *pss = get_preshared_secret(st->st_connection);
	err_t e;
	bool toomuch = FALSE;

	pcr_dh_init(&r, pcr_compute_dh_iv, importance);

	passert(st->st_sec_in_use);

	/* convert appropriate data to dhq */
	dhq->auth = st->st_oakley.auth;
	dhq->prf_hash = st->st_oakley.prf_hash;
	dhq->oakley_group = oakley_group2;
	dhq->init = init;
	dhq->keysize = st->st_oakley.enckeylen / BITS_PER_BYTE;

	passert(r.pcr_d.dhq.oakley_group != 0);
	DBG(DBG_CONTROL | DBG_CRYPT,
	    DBG_log("parent1 type: %d group: %d len: %d\n", r.pcr_type,
		    r.pcr_d.dhq.oakley_group, (int)r.pcr_len));

	if (pss != NULL)
		WIRE_CLONE_CHUNK(*dhq, pss, *pss);
	WIRE_CLONE_CHUNK(*dhq, ni, st->st_ni);
	WIRE_CLONE_CHUNK(*dhq, nr, st->st_nr);
	WIRE_CLONE_CHUNK(*dhq, gi, st->st_gi);
	WIRE_CLONE_CHUNK(*dhq, gr, st->st_gr);
	WIRE_CLONE_CHUNK(*dhq, secret, st->st_sec_chunk);

	/*copying required encryption algo*/
	/*dhq->encrypt_algo = st->st_oakley.encrypt;*/
	dhq->encrypter = st->st_oakley.encrypter;
	DBG(DBG_CRYPT,
	    DBG_log("Copying DH pub key pointer to be sent to a thread helper"));
	WIRE_CLONE_CHUNK(*dhq, pubk, st->pubk);

	ALLOC_WIRE_CHUNK(*dhq, icookie, COOKIE_SIZE);
	memcpy(wire_chunk_ptr(dhq, &dhq->icookie),
	       st->st_icookie, COOKIE_SIZE);

	ALLOC_WIRE_CHUNK(*dhq, rcookie, COOKIE_SIZE);
	memcpy(wire_chunk_ptr(dhq, &dhq->rcookie),
	       st->st_rcookie, COOKIE_SIZE);

	passert(dhq->oakley_group != 0);
	e = send_crypto_helper_request(&r, cn, &toomuch);

	if (e != NULL) {
		loglog(RC_LOG_SERIOUS, "can not start crypto helper: %s", e);
		if (toomuch)
			return STF_TOOMUCHCRYPTO;
		else
			return STF_FAIL;
	} else if (!toomuch) {
		st->st_calculating = TRUE;
		delete_event(st);
		event_schedule(EVENT_CRYPTO_FAILED, EVENT_CRYPTO_FAILED_DELAY,
			       st);
		return STF_SUSPEND;
	} else {
		/* we must have run the continuation directly, so
		 * complete_state_transition already got called.
		 */
		return STF_INLINE;
	}
}

void finish_dh_secretiv(struct state *st,
			struct pluto_crypto_req *r)
{
	struct pcr_skeyid_r *dhr = &r->pcr_d.dhr;

	clonetochunk(st->st_shared, wire_chunk_ptr(dhr, &dhr->shared),
		     dhr->shared.len, "calculated shared secret");
	clonetochunk(st->st_skeyid, wire_chunk_ptr(dhr, &dhr->skeyid),
		     dhr->skeyid.len, "calculated skeyid secret");
	clonetochunk(st->st_skeyid_d, wire_chunk_ptr(dhr, &dhr->skeyid_d),
		     dhr->skeyid_d.len, "calculated skeyid_d secret");
	clonetochunk(st->st_skeyid_a, wire_chunk_ptr(dhr, &dhr->skeyid_a),
		     dhr->skeyid_a.len, "calculated skeyid_a secret");
	clonetochunk(st->st_skeyid_e, wire_chunk_ptr(dhr, &dhr->skeyid_e),
		     dhr->skeyid_e.len, "calculated skeyid_a secret");
	clonetochunk(st->st_enc_key, wire_chunk_ptr(dhr, &dhr->enc_key),
		     dhr->enc_key.len, "calculated key for phase 1");

	passert(dhr->new_iv.len <= MAX_DIGEST_LEN);
	passert(dhr->new_iv.len > 0);
	memcpy(st->st_new_iv, wire_chunk_ptr(dhr, &dhr->new_iv),
	       dhr->new_iv.len);
	st->st_new_iv_len = dhr->new_iv.len;

	st->hidden_variables.st_skeyid_calculated = TRUE;
}

stf_status start_dh_secret(struct pluto_crypto_req_cont *cn,
			   struct state *st,
			   enum crypto_importance importance,
			   enum phase1_role init,
			   u_int16_t oakley_group2)
{
	struct pluto_crypto_req r;
	struct pcr_skeyid_q *const dhq= &r.pcr_d.dhq;
	const chunk_t *pss = get_preshared_secret(st->st_connection);
	err_t e;
	bool toomuch = FALSE;

	pcr_dh_init(&r, pcr_compute_dh, importance);

	passert(st->st_sec_in_use);

	/* convert appropriate data to dhq */
	dhq->auth = st->st_oakley.auth;
	dhq->prf_hash = st->st_oakley.prf_hash;
	dhq->oakley_group = oakley_group2;
	dhq->init = init;
	dhq->keysize = st->st_oakley.enckeylen / BITS_PER_BYTE;

	if (pss != NULL)
		WIRE_CLONE_CHUNK(*dhq, pss, *pss);
	WIRE_CLONE_CHUNK(*dhq, ni, st->st_ni);
	WIRE_CLONE_CHUNK(*dhq, nr, st->st_nr);
	WIRE_CLONE_CHUNK(*dhq, gi, st->st_gi);
	WIRE_CLONE_CHUNK(*dhq, gr, st->st_gr);
	WIRE_CLONE_CHUNK(*dhq, secret, st->st_sec_chunk);

	/*copying required encryption algo*/
	/* XXX Avesh: you commented this out on purpose or by accident ?? */
	/*dhq->encrypter = st->st_oakley.encrypter;*/
	DBG(DBG_CRYPT,
	    DBG_log("Copying DH pub key pointer to be sent to a thread helper"));
	WIRE_CLONE_CHUNK(*dhq, pubk, st->pubk);

	ALLOC_WIRE_CHUNK(*dhq, icookie, COOKIE_SIZE);
	memcpy(wire_chunk_ptr(&r.pcr_d.dhq, &dhq->icookie),
	       st->st_icookie, COOKIE_SIZE);

	ALLOC_WIRE_CHUNK(*dhq, rcookie, COOKIE_SIZE);
	memcpy(wire_chunk_ptr(&r.pcr_d.dhq, &dhq->rcookie),
	       st->st_rcookie, COOKIE_SIZE);

	e = send_crypto_helper_request(&r, cn, &toomuch);

	if (e != NULL) {
		loglog(RC_LOG_SERIOUS, "can not start crypto helper: %s", e);
		if (toomuch)
			return STF_TOOMUCHCRYPTO;
		else
			return STF_FAIL;
	} else if (!toomuch) {
		st->st_calculating = TRUE;
		delete_event(st);
		event_schedule(EVENT_CRYPTO_FAILED, EVENT_CRYPTO_FAILED_DELAY,
			       st);
		return STF_SUSPEND;
	} else {
		/* we must have run the continuation directly, so
		 * complete_state_transition already got called.
		 */
		return STF_INLINE;
	}
}

void finish_dh_secret(struct state *st,
		      struct pluto_crypto_req *r)
{
	struct pcr_skeyid_r *dhr = &r->pcr_d.dhr;

	clonetochunk(st->st_shared,   wire_chunk_ptr(dhr, &(dhr->shared)),
		     dhr->shared.len,   "calculated shared secret");
}

/*
 * invoke helper to do DH work.
 */
stf_status start_dh_v2(struct pluto_crypto_req_cont *cn,
		       struct state *st,
		       enum crypto_importance importance,
		       enum phase1_role init,        /* TRUE=g_init,FALSE=g_r */
		       u_int16_t oakley_group2)
{
	struct pluto_crypto_req r;
	struct pcr_skeyid_q *const dhq = &r.pcr_d.dhq;
	err_t e;
	bool toomuch = FALSE;

	pcr_dh_init(&r, pcr_compute_dh_v2, importance);

	passert(st->st_sec_in_use);

	DBG(DBG_CONTROLMORE,
	    DBG_log("calculating skeyseed using prf=%s integ=%s cipherkey=%s",
		    enum_name(&ikev2_trans_type_prf_names,   st->st_oakley.prf_hash),
		    enum_name(&ikev2_trans_type_integ_names,
			      st->st_oakley.integ_hash),
		    enum_name(&ikev2_trans_type_encr_names,
			      st->st_oakley.encrypt)));

	/* convert appropriate data to dhq */
	dhq->auth = st->st_oakley.auth;
	dhq->prf_hash   = st->st_oakley.prf_hash;
	dhq->integ_hash = st->st_oakley.integ_hash;
	dhq->oakley_group = oakley_group2;
	dhq->init = init;
	dhq->keysize = st->st_oakley.enckeylen / BITS_PER_BYTE;

	passert(r.pcr_d.dhq.oakley_group != 0);

	WIRE_CLONE_CHUNK(*dhq, ni, st->st_ni);
	WIRE_CLONE_CHUNK(*dhq, nr, st->st_nr);
	WIRE_CLONE_CHUNK(*dhq, gi, st->st_gi);
	WIRE_CLONE_CHUNK(*dhq, gr, st->st_gr);
	WIRE_CLONE_CHUNK(*dhq, secret, st->st_sec_chunk);

	/*copying required encryption algo*/
	/*dhq->encrypt_algo = st->st_oakley.encrypter->common.algo_v2id;*/
	dhq->encrypter = st->st_oakley.encrypter;
	DBG(DBG_CRYPT,
	    DBG_log("Copying DH pub key pointer to be sent to a thread helper"));
	WIRE_CLONE_CHUNK(*dhq, pubk, st->pubk);

	ALLOC_WIRE_CHUNK(*dhq, icookie, COOKIE_SIZE);
	memcpy(wire_chunk_ptr(dhq, &dhq->icookie),
	       st->st_icookie, COOKIE_SIZE);

	ALLOC_WIRE_CHUNK(*dhq, rcookie, COOKIE_SIZE);
	memcpy(wire_chunk_ptr(dhq, &dhq->rcookie),
	       st->st_rcookie, COOKIE_SIZE);

	passert(dhq->oakley_group != 0);
	e = send_crypto_helper_request(&r, cn, &toomuch);

	if (e != NULL) {
		loglog(RC_LOG_SERIOUS, "can not start crypto helper: %s", e);
		if (toomuch)
			return STF_TOOMUCHCRYPTO;
		else
			return STF_FAIL;
	} else if (!toomuch) {
		st->st_calculating = TRUE;
		delete_event(st);
		event_schedule(EVENT_CRYPTO_FAILED, EVENT_CRYPTO_FAILED_DELAY,
			       st);
		return STF_SUSPEND;
	} else {
		/* we must have run the continuation directly, so
		 * complete_state_transition already got called.
		 */
		return STF_INLINE;
	}
}

void finish_dh_v2(struct state *st,
		  const struct pluto_crypto_req *r)
{
	const struct pcr_skeycalc_v2_r *dhv2 = &r->pcr_d.dhv2;

	clonetochunk(st->st_shared,   wire_chunk_ptr(dhv2, &(dhv2->shared)),
		     dhv2->shared.len,   "calculated shared secret");
	clonetochunk(st->st_skey_d,   wire_chunk_ptr(dhv2, &(dhv2->skeyid_d)),
		     dhv2->skeyid_d.len,   "calculated skeyid secret");
	clonetochunk(st->st_skey_ai, wire_chunk_ptr(dhv2, &(dhv2->skeyid_ai)),
		     dhv2->skeyid_ai.len, "calculated skeyid_ai secret");
	clonetochunk(st->st_skey_ar, wire_chunk_ptr(dhv2, &(dhv2->skeyid_ar)),
		     dhv2->skeyid_ar.len, "calculated skeyid_ar secret");
	clonetochunk(st->st_skey_pi, wire_chunk_ptr(dhv2, &(dhv2->skeyid_pi)),
		     dhv2->skeyid_pi.len, "calculated skeyid_pi secret");
	clonetochunk(st->st_skey_pr, wire_chunk_ptr(dhv2, &(dhv2->skeyid_pr)),
		     dhv2->skeyid_pr.len, "calculated skeyid_pr secret");
	clonetochunk(st->st_skey_ei, wire_chunk_ptr(dhv2, &(dhv2->skeyid_ei)),
		     dhv2->skeyid_ei.len, "calculated skeyid_ei secret");
	clonetochunk(st->st_skey_er, wire_chunk_ptr(dhv2, &(dhv2->skeyid_er)),
		     dhv2->skeyid_er.len, "calculated skeyid_er secret");

	st->hidden_variables.st_skeyid_calculated = TRUE;
}
