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
 * RCSID $Id: crypt_ke.c,v 1.11.2.2 2005/08/19 17:52:42 ken Exp $
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

void calc_ke(struct pluto_crypto_req *r)
{
    MP_INT mp_g;
    MP_INT secret;
    const struct oakley_group_desc *group;
    chunk_t gi;
    struct pcr_kenonce *kn = &r->pcr_d.kn;
    
    group = lookup_group(kn->oakley_group);
    
    pluto_crypto_allocchunk(&kn->thespace
			    , &kn->secret
			    , LOCALSECRETSIZE);
    
    get_rnd_bytes(wire_chunk_ptr(kn, &(kn->secret)), LOCALSECRETSIZE);
    
    n_to_mpz(&secret, wire_chunk_ptr(kn, &(kn->secret)), LOCALSECRETSIZE);
    
    mpz_init(&mp_g);
    mpz_powm(&mp_g, &groupgenerator, &secret, group->modulus);
    
    gi = mpz_to_n(&mp_g, group->bytes);
    
    pluto_crypto_allocchunk(&kn->thespace, &kn->gi, gi.len);
    
    {
	char *gip = wire_chunk_ptr(kn, &(kn->gi));
	
	memcpy(gip, gi.ptr, gi.len);
    }
    
    DBG(DBG_CRYPT,
	DBG_dump("Local DH secret:\n"
		 , wire_chunk_ptr(kn, &(kn->secret))
		 , LOCALSECRETSIZE);
	DBG_dump_chunk("Public DH value sent:\n", gi));

    /* clean up after ourselves */
    mpz_clear(&mp_g);
    freeanychunk(gi);
}

void calc_nonce(struct pluto_crypto_req *r)
{
  struct pcr_kenonce *kn = &r->pcr_d.kn;

  pluto_crypto_allocchunk(&kn->thespace, &kn->n, DEFAULT_NONCE_SIZE);
  get_rnd_bytes(wire_chunk_ptr(kn, &(kn->n)), DEFAULT_NONCE_SIZE);

  DBG(DBG_CRYPT,
      DBG_dump("Generated nonce:\n"
	       , wire_chunk_ptr(kn, &(kn->n))
	       , DEFAULT_NONCE_SIZE));
}

stf_status build_ke(struct pluto_crypto_req_cont *cn
		    , struct state *st 
		    , const struct oakley_group_desc *group
		    , enum crypto_importance importance)
{
  struct pluto_crypto_req *r;
  err_t e;
  bool toomuch = FALSE;

  r = alloc_thing(struct pluto_crypto_req, "build ke request");
  
  r->pcr_len  = sizeof(struct pluto_crypto_req);
  r->pcr_type = pcr_build_kenonce;
  r->pcr_pcim = importance;

  r->pcr_d.kn.thespace.start = 0;
  r->pcr_d.kn.thespace.len   = sizeof(r->pcr_d.kn.space);
  r->pcr_d.kn.oakley_group   = group->group;

  cn->pcrc_serialno = st->st_serialno;
  e= send_crypto_helper_request(r, cn, &toomuch);

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


stf_status build_nonce(struct pluto_crypto_req_cont *cn
		       , struct state *st 
		       , enum crypto_importance importance)
{
  struct pluto_crypto_req *r;
  err_t e;
  bool toomuch = FALSE;

  r = alloc_thing(struct pluto_crypto_req, "build ke request");
  
  r->pcr_len  = sizeof(struct pluto_crypto_req);
  r->pcr_type = pcr_build_nonce;
  r->pcr_pcim = importance;

  r->pcr_d.kn.thespace.start = 0;
  r->pcr_d.kn.thespace.len   = sizeof(r->pcr_d.kn.space);

  cn->pcrc_serialno = st->st_serialno;
  e = send_crypto_helper_request(r, cn, &toomuch);

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


/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
