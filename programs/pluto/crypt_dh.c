/* 
 * Cryptographic helper function - calculate KE and nonce
 * Copyright (C) 2004 Michael C. Richardson <mcr@xelerance.com>
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
 * RCSID $Id: crypt_dh.c,v 1.8 2005/07/05 21:58:14 mcr Exp $
 */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <signal.h>

#include <openswan.h>
#include <openswan/ipsec_policy.h>

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
#include "secrets.h"

/** Compute DH shared secret from our local secret and the peer's public value.
 * We make the leap that the length should be that of the group
 * (see quoted passage at start of ACCEPT_KE).
 */
static void
calc_dh_shared(chunk_t *shared, const chunk_t g
	       , const MP_INT *sec
	       , const struct oakley_group_desc *group)
{
    MP_INT mp_g, mp_shared;
    struct timeval tv0, tv1;
    unsigned long tv_diff;

    gettimeofday(&tv0, NULL);
    n_to_mpz(&mp_g, g.ptr, g.len);
    mpz_init(&mp_shared);
    mpz_powm(&mp_shared, &mp_g, sec, group->modulus);
    mpz_clear(&mp_g);

    *shared = mpz_to_n(&mp_shared, group->bytes);
    mpz_clear(&mp_shared);

    gettimeofday(&tv1, NULL);
    tv_diff=(tv1.tv_sec  - tv0.tv_sec) * 1000000 + (tv1.tv_usec - tv0.tv_usec);
    DBG(DBG_CRYPT, 
    	DBG_log("calc_dh_shared(): time elapsed (%s): %ld usec"
		, enum_show(&oakley_group_names, group->group)
		, tv_diff);
       );
    /* if took more than 200 msec ... */
    if (tv_diff > 200000) {
	loglog(RC_LOG_SERIOUS, "WARNING: calc_dh_shared(): for %s took "
			"%ld usec"
		, enum_show(&oakley_group_names, group->group)
		, tv_diff);
    }

    DBG_cond_dump_chunk(DBG_CRYPT, "DH shared secret:\n", *shared);
}


/* SKEYID for preshared keys.
 * See draft-ietf-ipsec-ike-01.txt 4.1
 */
static void
skeyid_preshared(const chunk_t pss
		 , const chunk_t ni
		 , const chunk_t nr
		 , const struct hash_desc *hasher
		 , chunk_t *skeyid)
{
    struct hmac_ctx ctx;

    passert(hasher != NULL);

    DBG(DBG_CRYPT,
	DBG_log("Skey inputs (PSK+NI+NR)");
	DBG_dump_chunk("ni: ", ni);
	DBG_dump_chunk("nr: ", nr));
    
    hmac_init_chunk(&ctx, hasher, pss);
    hmac_update_chunk(&ctx, ni);
    hmac_update_chunk(&ctx, nr);
    hmac_final_chunk(*skeyid, "st_skeyid in skeyid_preshared()", &ctx);
    DBG(DBG_CRYPT,
	DBG_dump_chunk("keyid: ", *skeyid));
}

static void
skeyid_digisig(const chunk_t ni
	       , const chunk_t nr
	       , const chunk_t shared
	       , const struct hash_desc *hasher
	       , chunk_t *skeyid)
{
    struct hmac_ctx ctx;
    chunk_t nir;

    DBG(DBG_CRYPT,
	DBG_log("skeyid inputs (digi+NI+NR+shared) hasher: %s", hasher->common.name);
	DBG_dump_chunk("shared: ", shared);
	DBG_dump_chunk("ni: ", ni);
	DBG_dump_chunk("nr: ", nr));
    
    /* We need to hmac_init with the concatenation of Ni_b and Nr_b,
     * so we have to build a temporary concatentation.
     */
    nir.len = ni.len + nr.len;
    nir.ptr = alloc_bytes(nir.len, "Ni + Nr in skeyid_digisig");
    memcpy(nir.ptr, ni.ptr, ni.len);
    memcpy(nir.ptr+ ni.len, nr.ptr, nr.len);
    hmac_init_chunk(&ctx, hasher, nir);
    pfree(nir.ptr);

    hmac_update_chunk(&ctx, shared);
    hmac_final_chunk(*skeyid, "st_skeyid in skeyid_digisig()", &ctx);
    DBG(DBG_CRYPT,
	DBG_dump_chunk("keyid: ", *skeyid));
}

/* Generate the SKEYID_* and new IV
 * See draft-ietf-ipsec-ike-01.txt 4.1
 */
static void
calc_skeyids_iv(struct pcr_skeyid_q *skq
		, chunk_t shared
		, const size_t keysize     /* = st->st_oakley.enckeylen/BITS_PER_BYTE; */
		, chunk_t *skeyid          /* output */
		, chunk_t *skeyid_d        /* output */
		, chunk_t *skeyid_a        /* output */
		, chunk_t *skeyid_e        /* output */
		, chunk_t *new_iv
		, chunk_t *enc_key
    )
{
    oakley_auth_t auth = skq->auth;
    oakley_hash_t hash = skq->hash;
    const struct hash_desc *hasher = crypto_get_hasher(hash);
    chunk_t pss;  
    chunk_t ni;
    chunk_t nr;
    chunk_t gi;
    chunk_t gr;
    chunk_t icookie;
    chunk_t rcookie;

    /* this doesn't take any memory */
    setchunk_fromwire(gi, &skq->gi, skq);
    setchunk_fromwire(gr, &skq->gr, skq);
    setchunk_fromwire(ni, &skq->ni, skq);
    setchunk_fromwire(nr, &skq->nr, skq);
    setchunk_fromwire(icookie, &skq->icookie, skq);
    setchunk_fromwire(rcookie, &skq->rcookie, skq);

    /* Generate the SKEYID */
    switch (auth)
    {
	case OAKLEY_PRESHARED_KEY:
	    setchunk_fromwire(pss,    &skq->pss, skq);
	    skeyid_preshared(pss, ni, nr, hasher, skeyid);
	    break;

	case OAKLEY_RSA_SIG:
	    skeyid_digisig(ni, nr, shared, hasher, skeyid);
	    break;

	case OAKLEY_DSS_SIG:
	    /* XXX */

	case OAKLEY_RSA_ENC:
	case OAKLEY_RSA_ENC_REV:
	case OAKLEY_ELGAMAL_ENC:
	case OAKLEY_ELGAMAL_ENC_REV:
	    /* XXX */

	default:
	    bad_case(auth);
    }

    /* generate SKEYID_* from SKEYID */
    {
	struct hmac_ctx ctx;

	/* SKEYID_D */
	hmac_init_chunk(&ctx, hasher, *skeyid);
	hmac_update_chunk(&ctx, shared);
	hmac_update_chunk(&ctx, icookie);
	hmac_update_chunk(&ctx, rcookie);
	hmac_update(&ctx, "\0", 1);
	hmac_final_chunk(*skeyid_d, "st_skeyid_d in generate_skeyids_iv()", &ctx);

	/* SKEYID_A */
	hmac_reinit(&ctx);
	hmac_update_chunk(&ctx, *skeyid_d);
	hmac_update_chunk(&ctx, shared);
	hmac_update_chunk(&ctx, icookie);
	hmac_update_chunk(&ctx, rcookie);
	hmac_update(&ctx, "\1", 1);
	hmac_final_chunk(*skeyid_a, "st_skeyid_a in generate_skeyids_iv()", &ctx);

	/* SKEYID_E */
	hmac_reinit(&ctx);
	hmac_update_chunk(&ctx, *skeyid_a);
	hmac_update_chunk(&ctx, shared);
	hmac_update_chunk(&ctx, icookie);
	hmac_update_chunk(&ctx, rcookie);
	hmac_update(&ctx, "\2", 1);
	hmac_final_chunk(*skeyid_e, "st_skeyid_e in generate_skeyids_iv()", &ctx);
    }

    /* generate IV */
    {
	union hash_ctx hash_ctx;

	new_iv->len = hasher->hash_digest_len;
	new_iv->ptr = alloc_bytes(new_iv->len, "calculated new iv");

        DBG(DBG_CRYPT,
            DBG_dump_chunk("DH_i:", gi);
            DBG_dump_chunk("DH_r:", gr);
        );
	hasher->hash_init(&hash_ctx);
	hasher->hash_update(&hash_ctx, gi.ptr, gi.len);
	hasher->hash_update(&hash_ctx, gr.ptr, gr.len);
	hasher->hash_final(new_iv->ptr, &hash_ctx);
    }

    /* Oakley Keying Material
     * Derived from Skeyid_e: if it is not big enough, generate more
     * using the PRF.
     * See RFC 2409 "IKE" Appendix B
     */
    {
	u_char keytemp[MAX_OAKLEY_KEY_LEN + MAX_DIGEST_LEN];
	u_char *k = skeyid_e->ptr;

	if (keysize > skeyid_e->len)
	{
	    struct hmac_ctx ctx;
	    size_t i = 0;

	    hmac_init_chunk(&ctx, hasher, *skeyid_e);
	    hmac_update(&ctx, "\0", 1);
	    for (;;)
	    {
		hmac_final(&keytemp[i], &ctx);
		i += ctx.hmac_digest_len;
		if (i >= keysize)
		    break;
		hmac_reinit(&ctx);
		hmac_update(&ctx, &keytemp[i - ctx.hmac_digest_len], ctx.hmac_digest_len);
	    }
	    k = keytemp;
	}
	clonereplacechunk(*enc_key, k, keysize, "st_enc_key");
    }

    DBG(DBG_CRYPT,
	DBG_dump_chunk("Skeyid:  ", *skeyid);
	DBG_dump_chunk("Skeyid_d:", *skeyid_d);
	DBG_dump_chunk("Skeyid_a:", *skeyid_a);
	DBG_dump_chunk("Skeyid_e:", *skeyid_e);
	DBG_dump_chunk("enc key:",  *enc_key);
	DBG_dump_chunk("IV:",       *new_iv));
}


void calc_dh_iv(struct pluto_crypto_req *r)
{
    struct pcr_skeyid_q *skq = &r->pcr_d.dhq;
    struct pcr_skeyid_r *skr = &r->pcr_d.dhr;
    struct pcr_skeyid_q dhq;
    const struct oakley_group_desc *group;
    MP_INT  sec;
    chunk_t  shared, g;
    chunk_t  skeyid, skeyid_d, skeyid_a, skeyid_e; 
    chunk_t  new_iv, enc_key;

    /* copy the request, since we will use the same memory for the reply */
    memcpy(&dhq, skq, sizeof(struct pcr_skeyid_q));

    /* clear out the reply */
    memset(skr, 0, sizeof(*skr));
    skr->thespace.start = 0;
    skr->thespace.len   = sizeof(skr->space);

    group = lookup_group(dhq.oakley_group);

    pluto_crypto_allocchunk(&skr->thespace
			   , &skr->shared
			   , group->bytes);
    shared.ptr = wire_chunk_ptr(skr, &skr->shared);
    shared.len = group->bytes;

    /* recover the long term secret */
    n_to_mpz(&sec, wire_chunk_ptr(&dhq, &dhq.secret), dhq.secret.len);

    /* now calculate the (g^x)(g^y) --- need gi on responder, gr on initiator */

    if(dhq.init == RESPONDER) {
      setchunk_fromwire(g, &dhq.gi, &dhq);
    } else {
      setchunk_fromwire(g, &dhq.gr, &dhq);
    }

    calc_dh_shared(&shared, g, &sec, group);
    
    memset(&skeyid, 0, sizeof(skeyid));
    memset(&skeyid_d, 0, sizeof(skeyid_d));
    memset(&skeyid_a, 0, sizeof(skeyid_a));
    memset(&skeyid_e, 0, sizeof(skeyid_e));
    memset(&new_iv,   0, sizeof(new_iv));
    memset(&enc_key,  0, sizeof(enc_key));
    /* okay, so now calculate IV */
    calc_skeyids_iv(&dhq
		    , shared
		    , dhq.keysize
		    , &skeyid
		    , &skeyid_d
		    , &skeyid_a
		    , &skeyid_e
		    , &new_iv
		    , &enc_key);

    /* now translate it back to wire chunks, freeing the chunks */
    setwirechunk_fromchunk(skr->shared,   shared,   skr);
    setwirechunk_fromchunk(skr->skeyid,   skeyid,   skr);
    setwirechunk_fromchunk(skr->skeyid_d, skeyid_d, skr);
    setwirechunk_fromchunk(skr->skeyid_a, skeyid_a, skr);
    setwirechunk_fromchunk(skr->skeyid_e, skeyid_e, skr);
    setwirechunk_fromchunk(skr->new_iv,   new_iv,   skr);
    setwirechunk_fromchunk(skr->enc_key,  enc_key,  skr);

    freeanychunk(shared);
    freeanychunk(skeyid);
    freeanychunk(skeyid_d);
    freeanychunk(skeyid_a);
    freeanychunk(skeyid_e);
    freeanychunk(new_iv);
    freeanychunk(enc_key);

    return;
}

void calc_dh(struct pluto_crypto_req *r)
{
    struct pcr_skeyid_q *skq = &r->pcr_d.dhq;
    struct pcr_skeyid_r *skr = &r->pcr_d.dhr;
    struct pcr_skeyid_q dhq;
    const struct oakley_group_desc *group;
    MP_INT  sec;
    chunk_t  shared, g;

    /* copy the request, since we will use the same memory for the reply */
    memcpy(&dhq, skq, sizeof(struct pcr_skeyid_q));

    /* clear out the reply */
    memset(skr, 0, sizeof(*skr));
    skr->thespace.start = 0;
    skr->thespace.len   = sizeof(skr->space);

    group = lookup_group(dhq.oakley_group);

    pluto_crypto_allocchunk(&skr->thespace
			   , &skr->shared
			   , group->bytes);
    shared.ptr = wire_chunk_ptr(skr, &skr->shared);
    shared.len = group->bytes;

    /* recover the long term secret */
    n_to_mpz(&sec, wire_chunk_ptr(&dhq, &dhq.secret), dhq.secret.len);

    /* now calculate the (g^x)(g^y) */

    if(dhq.init == RESPONDER) {
      setchunk_fromwire(g, &dhq.gi, &dhq);
    } else {
      setchunk_fromwire(g, &dhq.gr, &dhq);
    }
    calc_dh_shared(&shared, g, &sec, group);

    /* now translate it back to wire chunks, freeing the chunks */
    setwirechunk_fromchunk(skr->shared,   shared,   skr);
    freeanychunk(shared);

    return;
}


stf_status perform_dh_secretiv(struct state *st
			     , enum phase1_role init       /* TRUE=g_init,FALSE=g_r */
			     , u_int16_t oakley_group)
{
    struct pluto_crypto_req r;
    struct pcr_skeyid_q *dhq = &r.pcr_d.dhq;
    struct pcr_skeyid_r *dhr = &r.pcr_d.dhr;
    const chunk_t *pss = get_preshared_secret(st->st_connection);

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

    calc_dh_iv(&r);

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
    return STF_OK;
}

stf_status perform_dh_secret(struct state *st
			     , enum phase1_role init      
			     , u_int16_t oakley_group)
{
    struct pluto_crypto_req r;
    struct pcr_skeyid_q *dhq = &r.pcr_d.dhq;
    struct pcr_skeyid_r *dhr = &r.pcr_d.dhr;
    const chunk_t *pss = get_preshared_secret(st->st_connection);

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

    calc_dh(&r);

    clonetochunk(st->st_shared,   wire_chunk_ptr(dhr, &(dhr->shared))
		 , dhr->shared.len,   "calculated shared secret");
    
    return STF_OK;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */

