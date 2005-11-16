/* IPsec DOI and Oakley resolution routines
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright (C) 2003-2005  Michael Richardson <mcr@xelerance.com>
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
 * RCSID $Id: ikev1_aggr.c,v 1.1.2.1 2005/07/26 01:42:39 ken Exp $
 */

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <arpa/nameser.h>	/* missing from <resolv.h> on old systems */
#include <sys/queue.h>
#include <sys/time.h>		/* for gettimeofday */

#include <openswan.h>
#include <openswan/ipsec_policy.h>
#include "pfkeyv2.h"

#include "constants.h"
#include "defs.h"
#include "state.h"
#include "id.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#include "smartcard.h"
#ifdef XAUTH_USEPAM
#include <security/pam_appl.h>
#endif
#include "connections.h"	/* needs id.h */
#include "keys.h"
#include "packet.h"
#include "demux.h"	/* needs packet.h */
#include "adns.h"	/* needs <resolv.h> */
#include "dnskey.h"	/* needs keys.h and adns.h */
#include "kernel.h"	/* needs connections.h */
#include "log.h"
#include "cookie.h"
#include "server.h"
#include "spdb.h"
#include "timer.h"
#include "rnd.h"
#include "ipsec_doi.h"	/* needs demux.h and state.h */
#include "whack.h"
#include "fetch.h"
#include "pkcs.h"
#include "asn1.h"

#include "sha1.h"
#include "md5.h"
#include "crypto.h" /* requires sha1.h and md5.h */

#include "ike_alg.h"
#include "kernel_alg.h"
#include "plutoalg.h"
#include "pluto_crypt.h"
#include "ikev1.h"
#include "ikev1_continuations.h"

#ifdef XAUTH
#include "xauth.h"
#endif
#include "vendor.h"
#ifdef NAT_TRAVERSAL
#include "nat_traversal.h"
#endif
#ifdef VIRTUAL_IP
#include "virtual.h"
#endif
#include "dpd.h"
#include "x509more.h"

#if defined(AGGRESSIVE)
/*
 * Initiate an Oakley Aggressive Mode exchange.
 * --> HDR, SA, KE, Ni, IDii
 */
static stf_status
aggr_outI1_tail(struct pluto_crypto_req_cont *pcrc
		, struct pluto_crypto_req *r);

static void
aggr_outI1_continue(struct pluto_crypto_req_cont *pcrc
		    , struct pluto_crypto_req *r
		    , err_t ugh)
{
  struct ke_continuation *ke = (struct ke_continuation *)pcrc;
  struct msg_digest *md = ke->md;
  struct state *const st = md->st;
  stf_status e;
  
  DBG(DBG_CONTROLMORE
      , DBG_log("aggr outI1: calculated ke+nonce, sending I1"));
  
  /* XXX should check out ugh */
  passert(ugh == NULL);
  passert(cur_state == NULL);
  passert(st != NULL);

  passert(st->st_suspended_md == ke->md);
  st->st_suspended_md = NULL;	/* no longer connected or suspended */

  set_cur_state(st);

  st->st_calculating = FALSE;

  e = aggr_outI1_tail(pcrc, r);
  
  if(ke->md != NULL) {
      complete_state_transition(&ke->md, e);
      release_md(ke->md);
  }
  reset_globals();

  passert(GLOBALS_ARE_RESET());
}

stf_status
aggr_outI1(int whack_sock,
	   struct connection *c,
	   struct state *predecessor,
	   lset_t policy,
	   unsigned long try
	   , enum crypto_importance importance)
{
    struct state *st;

    /* set up new state */
    cur_state = st = new_state();
    st->st_connection = c;
    set_state_ike_endpoints(st, c);

#ifdef DEBUG
    extra_debugging(c);
#endif
    st->st_policy = policy & ~POLICY_IPSEC_MASK;
    st->st_whack_sock = whack_sock;
    st->st_try = try;
    st->st_state = STATE_AGGR_I1;

    get_cookie(TRUE, st->st_icookie, COOKIE_SIZE, &c->spd.that.host_addr);

    insert_state(st);	/* needs cookies, connection, and msgid (0) */

    if(init_am_st_oakley(st, policy) == FALSE) {
	loglog(RC_AGGRALGO, "can not initiate aggressive mode, at most one algorithm may be provided");
	reset_globals();
	return STF_FAIL;
    }

    if (HAS_IPSEC_POLICY(policy))
	add_pending(dup_any(whack_sock), st, c, policy, 1
	    , predecessor == NULL? SOS_NOBODY : predecessor->st_serialno);

    if (predecessor == NULL) {
	openswan_log("initiating Aggressive Mode #%lu, connection \"%s\""
		     , st->st_serialno, st->st_connection->name);
    }
    else {
	openswan_log("initiating Aggressive Mode #%lu to replace #%lu, connection \"%s\""
		     , st->st_serialno, predecessor->st_serialno
		     , st->st_connection->name);
    }

    {
	struct ke_continuation *ke = alloc_thing(struct ke_continuation
						 , "outI2 KE");
	stf_status e;

	ke->md = alloc_md();
	ke->md->st = st;
	st->st_suspended_md = ke->md;

	if (!st->st_sec_in_use) {
	    ke->ke_pcrc.pcrc_func = aggr_outI1_continue;
	    e = build_ke(&ke->ke_pcrc, st, st->st_oakley.group, importance);
	    if(e != STF_SUSPEND) {
	      loglog(RC_CRYPTOFAILED, "system too busy");
	      delete_state(st);
	    }
	} else {
	    e = aggr_outI1_tail((struct pluto_crypto_req_cont *)ke
					, NULL);
	}
	
	reset_globals();

	return e;
    }
}

static stf_status
aggr_outI1_tail(struct pluto_crypto_req_cont *pcrc
		, struct pluto_crypto_req *r)
{
    struct ke_continuation *ke = (struct ke_continuation *)pcrc;
    struct msg_digest *md = ke->md;
    struct state *const st = md->st;
    struct connection *c = st->st_connection;
    u_char space[8192];	/* NOTE: we assume 8192 is big enough to build the packet */
    pb_stream reply;	/* not actually a reply, but you know what I mean */
    pb_stream rbody;

    /* set up reply */
    init_pbs(&reply, space, sizeof(space), "reply packet");

    /* HDR out */
    {
	struct isakmp_hdr hdr;

	memset(&hdr, '\0', sizeof(hdr));	/* default to 0 */
	hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT | ISAKMP_MINOR_VERSION;
	hdr.isa_np = ISAKMP_NEXT_SA;
	hdr.isa_xchg = ISAKMP_XCHG_AGGR;
	memcpy(hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
	/* R-cookie, flags and MessageID are left zero */

	if (!out_struct(&hdr, &isakmp_hdr_desc, &reply, &rbody))
	{
	    cur_state = NULL;
	    return STF_INTERNAL_ERROR;
	}
    }

    /* SA out */
    {
	u_char *sa_start = rbody.cur;
	int    policy_index = POLICY_ISAKMP(st->st_policy
					    , c->spd.this.xauth_server
					    , c->spd.this.xauth_client);
	
	if (!out_sa(&rbody
		    , &oakley_am_sadb[policy_index], st
		    , TRUE, TRUE, ISAKMP_NEXT_KE))
	{
	    return STF_INTERNAL_ERROR;
	    cur_state = NULL;
	}

	/* save initiator SA for later HASH */
	passert(st->st_p1isa.ptr == NULL);	/* no leak! */
	clonetochunk(st->st_p1isa, sa_start, rbody.cur - sa_start,
		     "sa in aggr_outI1");
    }

    /* KE out */
    if (!ship_KE(st, r, &st->st_gi, 
			   &rbody, ISAKMP_NEXT_NONCE))
	return STF_INTERNAL_ERROR;

    /* Ni out */
    if (!ship_nonce(&st->st_ni, r, &rbody, ISAKMP_NEXT_ID, "Ni"))
	return STF_INTERNAL_ERROR;

    /* IDii out */
    {
	struct isakmp_ipsec_id id_hd;
	chunk_t id_b;
	pb_stream id_pbs;

	build_id_payload(&id_hd, &id_b, &st->st_connection->spd.this);
	id_hd.isaiid_np = ISAKMP_NEXT_VID;
	if (!out_struct(&id_hd, &isakmp_ipsec_identification_desc, &rbody, &id_pbs)
	|| !out_chunk(id_b, &id_pbs, "my identity"))
	    return STF_INTERNAL_ERROR;
	close_output_pbs(&id_pbs);
    }

    /* ALWAYS Announce our ability to do Dead Peer Detection to the peer */
    {
      int np = ISAKMP_NEXT_NONE;
	
      if (nat_traversal_enabled
	  || c->spd.this.xauth_client
	  || c->spd.this.xauth_server) {
	
	/* Add supported NAT-Traversal VID */
	np = ISAKMP_NEXT_VID;
      }

      if( !out_generic_raw(np, &isakmp_vendor_id_desc
			   , &rbody
			   , dpd_vendorid, dpd_vendorid_len
			   , "V_ID"))
        return STF_INTERNAL_ERROR;
    }

#ifdef NAT_TRAVERSAL
    if (nat_traversal_enabled) {
	/* Add supported NAT-Traversal VID */
	int np = ISAKMP_NEXT_NONE;

#ifdef XAUTH
	if(c->spd.this.xauth_client || c->spd.this.xauth_server) {
	    np = ISAKMP_NEXT_VID;
	}
#endif
	
	if (!nat_traversal_add_vid(np, &rbody)) {
	    reset_cur_state();
	    return STF_INTERNAL_ERROR;
	}
    }
#endif

#ifdef XAUTH
    if(c->spd.this.xauth_client || c->spd.this.xauth_server)
    {
	if(!out_vendorid(ISAKMP_NEXT_NONE, &rbody, VID_MISC_XAUTH))
	{
	    return STF_INTERNAL_ERROR;
	}
    }
#endif
	
    /* finish message */

    close_message(&rbody);
    close_output_pbs(&reply);

    clonetochunk(st->st_tpacket, reply.start, pbs_offset(&reply),
		 "reply packet from aggr_outI1");

    /* Transmit */

    DBG_cond_dump(DBG_RAW, "sending:\n",
		  st->st_tpacket.ptr, st->st_tpacket.len);

    send_packet(st, "aggr_outI1", TRUE);

    /* Set up a retransmission event, half a minute henceforth */
    delete_event(st);
    event_schedule(EVENT_RETRANSMIT, EVENT_RETRANSMIT_DELAY_0, st);

    whack_log(RC_NEW_STATE + STATE_AGGR_I1,
	      "%s: initiate", enum_name(&state_names, st->st_state));
    cur_state = NULL;
    return STF_IGNORE;
}
#endif /* AGGRESSIVE */

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
