/* 
 * Cryptographic helper function - calculate DH
 * Copyright (C) 2006 Michael C. Richardson <mcr@xelerance.com>
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
 * RCSID $Id: crypt_dh.c,v 1.11 2005/08/14 21:47:29 mcr Exp $
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

#include <openswan.h>
#include <openswan/ipsec_policy.h>

#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "packet.h"
#include "demux.h"
#include "crypto.h"
#include "rnd.h"
#include "state.h"
#include "pluto_crypt.h"
#include "oswlog.h"
#include "log.h"
#include "timer.h"
#include "ike_alg.h"
#include "id.h"
#include "secrets.h"
#include "keys.h"

/*
 * invoke helper to do DH work.
 */
stf_status start_dh_secretiv(struct pluto_crypto_req_cont *cn
			     , struct state *st
			     , enum crypto_importance importance
			     , enum phase1_role init       /* TRUE=g_init,FALSE=g_r */
			     , u_int16_t oakley_group)
{
    struct pluto_crypto_req r;
    struct pcr_skeyid_q *dhq;
    const chunk_t *pss = get_preshared_secret(st->st_connection);
    err_t e;
    bool toomuch = FALSE;

    r.pcr_len = sizeof(struct pluto_crypto_req);
    r.pcr_type = pcr_compute_dh_iv;
    r.pcr_pcim = importance;

    dhq = &r.pcr_d.dhq;

    passert(st->st_sec_in_use);

    dhq->thespace.start = 0;
    dhq->thespace.len   = sizeof(dhq->space);

    /* convert appropriate data to dhq */
    dhq->auth = st->st_oakley.auth;
    dhq->hash = st->st_oakley.hash;
    dhq->oakley_group = oakley_group;
    dhq->init = init;
    dhq->keysize = st->st_oakley.enckeylen/BITS_PER_BYTE; 

    passert(r.pcr_d.dhq.oakley_group != 0);
    DBG_log("parent1 type: %d group: %d len: %d\n", r.pcr_type,
	    r.pcr_d.dhq.oakley_group, r.pcr_len);

    if(pss) {
	pluto_crypto_copychunk(&dhq->thespace, dhq->space, &dhq->pss, *pss);
    }
    pluto_crypto_copychunk(&dhq->thespace, dhq->space, &dhq->ni,  st->st_ni);
    pluto_crypto_copychunk(&dhq->thespace, dhq->space, &dhq->nr,  st->st_nr);
    pluto_crypto_copychunk(&dhq->thespace, dhq->space, &dhq->gi,  st->st_gi);
    pluto_crypto_copychunk(&dhq->thespace, dhq->space, &dhq->gr,  st->st_gr);
    pluto_crypto_copychunk(&dhq->thespace, dhq->space
			   , &dhq->secret, st->st_sec_chunk);

    pluto_crypto_allocchunk(&dhq->thespace, &dhq->icookie, COOKIE_SIZE);
    memcpy(wire_chunk_ptr(dhq, &dhq->icookie)
	   , st->st_icookie, COOKIE_SIZE);

    pluto_crypto_allocchunk(&dhq->thespace, &dhq->rcookie, COOKIE_SIZE);
    memcpy(wire_chunk_ptr(dhq, &dhq->rcookie)
	   , st->st_rcookie, COOKIE_SIZE);

    passert(dhq->oakley_group != 0);
    e = send_crypto_helper_request(&r, cn, &toomuch);

    if(e != NULL) {
	loglog(RC_LOG_SERIOUS, "can not start crypto helper: %s", e);
	if(toomuch) {
	    return STF_TOOMUCHCRYPTO;
	} else {
	    return STF_FAIL;
	}
    } else if(!toomuch) {
	st->st_calculating = TRUE;
	delete_event(st);
	event_schedule(EVENT_CRYPTO_FAILED, EVENT_CRYPTO_FAILED_DELAY, st);
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
			
    clonetochunk(st->st_shared,   wire_chunk_ptr(dhr, &(dhr->shared))
		 , dhr->shared.len,   "calculated shared secret");
    clonetochunk(st->st_skeyid,   wire_chunk_ptr(dhr, &(dhr->skeyid))
		 , dhr->skeyid.len,   "calculated skeyid secret");
    clonetochunk(st->st_skeyid_d, wire_chunk_ptr(dhr, &(dhr->skeyid_d))
		 , dhr->skeyid_d.len, "calculated skeyid_d secret");
    clonetochunk(st->st_skeyid_a, wire_chunk_ptr(dhr, &(dhr->skeyid_a))
		 , dhr->skeyid_a.len, "calculated skeyid_a secret");
    clonetochunk(st->st_skeyid_e, wire_chunk_ptr(dhr, &(dhr->skeyid_e))
		 , dhr->skeyid_e.len, "calculated skeyid_a secret");
    clonetochunk(st->st_enc_key, wire_chunk_ptr(dhr, &(dhr->enc_key))
		 , dhr->enc_key.len, "calculated key for phase 1");
    
    passert(dhr->new_iv.len <= MAX_DIGEST_LEN);
    passert(dhr->new_iv.len > 0);
    memcpy(st->st_new_iv, wire_chunk_ptr(dhr, &(dhr->new_iv)),dhr->new_iv.len);
    st->st_new_iv_len = dhr->new_iv.len;

    st->hidden_variables.st_skeyid_calculated = TRUE;
}

stf_status start_dh_secret(struct pluto_crypto_req_cont *cn
			   , struct state *st
			   , enum crypto_importance importance
			   , enum phase1_role init      
			   , u_int16_t oakley_group)
{
    struct pluto_crypto_req r;
    struct pcr_skeyid_q *dhq;
    const chunk_t *pss = get_preshared_secret(st->st_connection);
    err_t e;
    bool toomuch = FALSE;

    r.pcr_len = sizeof(struct pluto_crypto_req);
    r.pcr_type = pcr_compute_dh;
    r.pcr_pcim = importance;

    dhq = &r.pcr_d.dhq;

    passert(st->st_sec_in_use);

    dhq->thespace.start = 0;
    dhq->thespace.len   = sizeof(dhq->space);

    /* convert appropriate data to dhq */
    dhq->auth = st->st_oakley.auth;
    dhq->hash = st->st_oakley.hash;
    dhq->oakley_group = oakley_group;
    dhq->init = init;
    dhq->keysize = st->st_oakley.enckeylen/BITS_PER_BYTE; 

    if(pss) {
	pluto_crypto_copychunk(&dhq->thespace, dhq->space, &dhq->pss, *pss);
    }
    pluto_crypto_copychunk(&dhq->thespace, dhq->space, &dhq->ni,  st->st_ni);
    pluto_crypto_copychunk(&dhq->thespace, dhq->space, &dhq->nr,  st->st_nr);
    pluto_crypto_copychunk(&dhq->thespace, dhq->space, &dhq->gi,  st->st_gi);
    pluto_crypto_copychunk(&dhq->thespace, dhq->space, &dhq->gr,  st->st_gr);
    pluto_crypto_copychunk(&dhq->thespace, dhq->space
			   , &dhq->secret, st->st_sec_chunk);

    pluto_crypto_allocchunk(&dhq->thespace, &dhq->icookie, COOKIE_SIZE);
    memcpy(wire_chunk_ptr(&r.pcr_d.dhq, &dhq->icookie)
	   , st->st_icookie, COOKIE_SIZE);

    pluto_crypto_allocchunk(&dhq->thespace, &dhq->rcookie, COOKIE_SIZE);
    memcpy(wire_chunk_ptr(&r.pcr_d.dhq, &dhq->rcookie)
	   , st->st_rcookie, COOKIE_SIZE);

    e = send_crypto_helper_request(&r, cn, &toomuch);

    if(e != NULL) {
	loglog(RC_LOG_SERIOUS, "can not start crypto helper: %s", e);
	if(toomuch) {
	    return STF_TOOMUCHCRYPTO;
	} else {
	    return STF_FAIL;
	}
    } else if(!toomuch) {
	st->st_calculating = TRUE;
	delete_event(st);
	event_schedule(EVENT_CRYPTO_FAILED, EVENT_CRYPTO_FAILED_DELAY, st);
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
			
    clonetochunk(st->st_shared,   wire_chunk_ptr(dhr, &(dhr->shared))
		 , dhr->shared.len,   "calculated shared secret");
}

