/* IPsec DOI and Oakley resolution routines
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2005  Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2011 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Philippe Vouters <philippe.vouters@laposte.net>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
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
 */

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>           /* for gettimeofday */
#include <resolv.h>

#include <libreswan.h>
#include "libreswan/pfkeyv2.h"

#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "state.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"        /* needs id.h */
#include "keys.h"
#include "packet.h"
#include "demux.h"      /* needs packet.h */
#include "dnskey.h"     /* needs keys.h and adns.h */
#include "kernel.h"     /* needs connections.h */
#include "log.h"
#include "cookie.h"
#include "server.h"
#include "spdb.h"
#include "timer.h"
#include "rnd.h"
#include "ipsec_doi.h"  /* needs demux.h and state.h */
#include "whack.h"
#include "fetch.h"
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

#include "ikev1_xauth.h"

#include "vendor.h"
#include "nat_traversal.h"
#include "virtual.h"	/* needs connections.h */
#include "ikev1_dpd.h"
#include "pluto_x509.h"

/* STATE_AGGR_R0: HDR, SA, KE, Ni, IDii
 *           --> HDR, SA, KE, Nr, IDir, HASH_R/SIG_R
 */

/*
 * Control flow is very confusing.
 *
 * Entry points:
 *	aggr_outI1:	called to initiate
 *	aggr_inI1_outR1
 *	aggr_inR1_outI2
 *	aggr_inI2
 *
 * Called by:
 *	aggr_inI1_outR1_continue1: ke(aggr_inI1_outR1)
 *	aggr_inI1_outR1_continue2: dh(aggr_inI1_outR1_continue1)
 *	aggr_inI1_outR1_tail: aggr_inI1_outR1_continue2
 */

static stf_status aggr_inI1_outR1_tail(struct msg_digest *md,
				       struct pluto_crypto_req *r);

static crypto_req_cont_func aggr_inR1_outI2_crypto_continue;

/*
 * continuation from second calculation (the DH one)
 */

static crypto_req_cont_func aggr_inI1_outR1_continue2;	/* type assertion */

static void aggr_inI1_outR1_continue2(struct pluto_crypto_req_cont *dh,
				      struct pluto_crypto_req *r)
{
	struct msg_digest *md = dh->pcrc_md;
	struct state *const st = md->st;
	stf_status e;

	DBG(DBG_CONTROL,
		DBG_log("aggr_inI1_outR1_continue2 for #%lu: calculated ke+nonce+DH, sending R1",
			dh->pcrc_serialno));

	if (dh->pcrc_serialno == SOS_NOBODY) {
		loglog(RC_LOG_SERIOUS,
		       "%s: Request was disconnected from state",
		       __FUNCTION__);
		release_any_md(&dh->pcrc_md);
		return;
	}

	passert(dh->pcrc_serialno == st->st_serialno);	/* transitional */

	passert(cur_state == NULL);
	passert(st != NULL);

	passert(st->st_suspended_md == dh->pcrc_md);
	unset_suspended(st); /* no longer connected or suspended */

	set_cur_state(st);
	DBG(DBG_CONTROLMORE, DBG_log("#%lu %s:%u st->st_calculating = FALSE;", st->st_serialno, __FUNCTION__, __LINE__));
	st->st_calculating = FALSE;

	e = aggr_inI1_outR1_tail(dh->pcrc_md, r);

	passert(dh->pcrc_md != NULL);
	complete_v1_state_transition(&dh->pcrc_md, e);
	release_any_md(&dh->pcrc_md);
	reset_cur_state();
}

/*
 * for aggressive mode, this is sub-optimal, since we should have
 * had the crypto helper actually do everything, but we need to do
 * some additional work to set that all up, so this is fine for now.
 */

static crypto_req_cont_func aggr_inI1_outR1_continue1;	/* type assertion */

static void aggr_inI1_outR1_continue1(struct pluto_crypto_req_cont *ke,
				      struct pluto_crypto_req *r)
{
	struct msg_digest *md = ke->pcrc_md;
	struct state *const st = md->st;
	stf_status e;

	DBG(DBG_CONTROLMORE,
	    DBG_log("aggr inI1_outR1: calculated ke+nonce, calculating DH"));

	if (ke->pcrc_serialno == SOS_NOBODY) {
		loglog(RC_LOG_SERIOUS,
		       "%s: Request was disconnected from state",
		       __FUNCTION__);
		release_any_md(&ke->pcrc_md);
		return;
	}

	passert(cur_state == NULL);
	passert(st != NULL);

	passert(st->st_suspended_md == ke->pcrc_md);
	unset_suspended(st); /* no longer connected or suspended */

	set_cur_state(st);
	DBG(DBG_CONTROLMORE, DBG_log("#%lu %s:%u st->st_calculating = FALSE;", st->st_serialno, __FUNCTION__, __LINE__));
	st->st_calculating = FALSE;

	/* unpack first calculation */
	unpack_KE_from_helper(st, r, &st->st_gr);

	/* unpack nonce too */
	unpack_nonce(&st->st_nr, r);

	/* NOTE: the "r" reply will get freed by our caller */

	/* set up second calculation */
	{
		struct pluto_crypto_req_cont *dh = new_pcrc(
			aggr_inI1_outR1_continue2,
			"aggr outR1 DH",
			st, md);

		e = start_dh_secretiv(dh, st,
				      st->st_import,
				      ORIGINAL_RESPONDER,
				      st->st_oakley.group->group);

		if (e != STF_SUSPEND) {
			passert(dh->pcrc_md != NULL);
			complete_v1_state_transition(&dh->pcrc_md, e);
			release_any_md(&dh->pcrc_md);
		}

		reset_cur_state();
	}
}

/* STATE_AGGR_R0:
 * SMF_PSK_AUTH: HDR, SA, KE, Ni, IDii
 *           --> HDR, SA, KE, Nr, IDir, HASH_R
 * SMF_DS_AUTH:  HDR, SA, KE, Nr, IDii
 *           --> HDR, SA, KE, Nr, IDir, [CERT,] SIG_R
 */
stf_status aggr_inI1_outR1(struct msg_digest *md)
{
	/* With Aggressive Mode, we get an ID payload in this, the first
	 * message, so we can use it to index the preshared-secrets
	 * when the IP address would not be meaningful (i.e. Road
	 * Warrior).  That's the one justification for Aggressive Mode.
	 */
	struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_SA];

	if (drop_new_exchanges()) {
		return STF_IGNORE;
	}

	const lset_t policy = preparse_isakmp_sa_body(sa_pd->pbs) |
		POLICY_AGGRESSIVE | POLICY_IKEV1_ALLOW;

	const lset_t policy_exact_mask = POLICY_XAUTH |
		POLICY_AGGRESSIVE | POLICY_IKEV1_ALLOW;

	struct connection *c = find_host_connection(
		&md->iface->ip_addr, md->iface->port,
		&md->sender, md->sender_port,
		policy, policy_exact_mask);

#if 0 /* ??? is this useful? */
	if (c == NULL && md->iface->ike_float) {
		/* ??? see above for discussion about policy argument */
		c = find_host_connection(
			&md->iface->addr, pluto_nat_port,
			&md->sender, md->sender_port,
			policy, policy_exact_mask);
	}
#endif

	if (c == NULL) {
		c = find_host_connection(&md->iface->ip_addr, pluto_port,
					 (ip_address*)NULL, md->sender_port,
					 policy, policy_exact_mask);
		if (c == NULL) {
			ipstr_buf b;

			loglog(RC_LOG_SERIOUS,
				"initial Aggressive Mode message from %s but no (wildcard) connection has been configured with policy %s",
				ipstr(&md->sender, &b),
				bitnamesof(sa_policy_bit_names, policy));
			/* XXX notification is in order! */
			return STF_IGNORE;
		}
		passert(LIN(policy, c->policy));
		/* Create a temporary connection that is a copy of this one.
		 * His ID isn't declared yet.
		 */
		c = rw_instantiate(c, &md->sender, NULL, NULL);
	}

	/* warn for especially dangerous Aggressive Mode and PSK */
	if ((c->policy & POLICY_AGGRESSIVE) != LEMPTY){
		loglog(RC_LOG_SERIOUS,
			"IKEv1 Aggressive Mode with PSK is vulnerable to dictionary attacks and is cracked on large scale by TLA's");
	}

	/* Set up state */
	struct state *st = new_rstate(md);

	cur_state = md->st = st;  /* (caller will reset cur_state) */
	st->st_connection = c;	/* safe: from new_state */
	change_state(st, STATE_AGGR_R1);

	/*
	 * until we have clue who this is, be conservative about allocating
	 * them any crypto bandwidth
	 */
	st->st_import = pcim_stranger_crypto;

	st->st_policy = policy;	/* ??? not sure what's needed here */

	/* ??? not sure what's needed here */
	st->st_oakley.auth = policy & POLICY_PSK ? OAKLEY_PRESHARED_KEY :
		policy & POLICY_RSASIG ? OAKLEY_RSA_SIG :
		0;	/* we don't really know */

	/* note: ikev1_decode_peer_id() may change md->st->st_connection */

	if (!ikev1_decode_peer_id(md, FALSE, TRUE)) {
		char buf[IDTOA_BUF];
		ipstr_buf b;

		(void) idtoa(&st->st_connection->spd.that.id, buf,
			     sizeof(buf));
		loglog(RC_LOG_SERIOUS,
		       "initial Aggressive Mode packet claiming to be from %s on %s but no connection has been authorized",
		       buf, ipstr(&md->sender, &b));
		/* XXX notification is in order! */
		return STF_FAIL + INVALID_ID_INFORMATION;
	}

	c = st->st_connection;	/* fixup after ikev1_decode_peer_id() */

	extra_debugging(c);
	st->st_try = 0;                                 /* Not our job to try again from start */
	st->st_policy = c->policy & ~POLICY_IPSEC_MASK; /* only as accurate as connection */

	memcpy(st->st_icookie, md->hdr.isa_icookie, COOKIE_SIZE);
	get_cookie(FALSE, st->st_rcookie, &md->sender);

	insert_state(st); /* needs cookies, connection, and msgid (0) */

	{
		ipstr_buf b;
		char cib[CONN_INST_BUF];

		libreswan_log("responding to Aggressive Mode, state #%lu, connection \"%s\"%s from %s",
			st->st_serialno,
			st->st_connection->name, fmt_conn_instance(st->st_connection, cib),
			ipstr(&c->spd.that.host_addr, &b));
	}

	merge_quirks(st, md);

	set_nat_traversal(st, md);

	/* save initiator SA for HASH */

	/*
	 * ??? how would st->st_p1isa.ptr != NULL?
	 * This routine creates *st itself so how would this field
	 * be already filled-in.
	 */
	pexpect(st->st_p1isa.ptr == NULL);

	clonereplacechunk(st->st_p1isa, sa_pd->pbs.start,
		pbs_room(&sa_pd->pbs), "sa in aggr_inI1_outR1()");

	/*
	 * parse_isakmp_sa picks the right group, which we need to know
	 * before we do any calculations. We will call it again to have it
	 * emit the winning SA into the output.
	 */
	/* SA body in */
	{
		pb_stream sabs = sa_pd->pbs;

		RETURN_STF_FAILURE(parse_isakmp_sa_body(&sabs,
							&sa_pd->payload.sa,
							NULL, FALSE, st));
	}

	/* KE in */
	RETURN_STF_FAILURE(accept_KE(&st->st_gi, "Gi", st->st_oakley.group,
				     &md->chain[ISAKMP_NEXT_KE]->pbs));

	/* Ni in */
	RETURN_STF_FAILURE(accept_v1_nonce(md, &st->st_ni, "Ni"));

	/* calculate KE and Nonce */
	{
		struct pluto_crypto_req_cont *ke = new_pcrc(
			aggr_inI1_outR1_continue1,
			"outI2 KE",
			st, md);

		return build_ke_and_nonce(ke, st->st_oakley.group,
				st->st_import);
	}
}

static stf_status aggr_inI1_outR1_tail(struct msg_digest *md,
				       struct pluto_crypto_req *r)
{
	struct state *st = md->st;
	bool send_cert = FALSE;
	bool send_cr = FALSE;
	bool send_authcerts = FALSE;
	bool send_full_chain = FALSE;
	struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_SA];
	int auth_payload;
	cert_t mycert = st->st_connection->spd.this.cert;
	chunk_t auth_chain[MAX_CA_PATH_LEN] = { { NULL, 0 } };
	int chain_len = 0;

	pb_stream r_sa_pbs;
	pb_stream r_id_pbs; /* ID Payload; also used for hash calculation */

	/* parse_isakmp_sa also spits out a winning SA into our reply,
	 * so we have to build our reply_stream and emit HDR before calling it.
	 */

	if (!finish_dh_secretiv(st, r))
		return STF_FAIL + INVALID_KEY_INFORMATION;

	/* decode certificate requests */
	ikev1_decode_cr(md);

	if (st->st_requested_ca != NULL)
		st->hidden_variables.st_got_certrequest = TRUE;

	/*
	 * send certificate if we have one and auth is RSA, and we were
	 * told we can send one if asked, and we were asked, or we were told
	 * to always send one.
	 */
	send_cert = st->st_oakley.auth == OAKLEY_RSA_SIG &&
		    mycert.ty != CERT_NONE && mycert.u.nss_cert != NULL &&
		    ((st->st_connection->spd.this.sendcert ==
			cert_sendifasked &&
		      st->hidden_variables.st_got_certrequest) ||
		     st->st_connection->spd.this.sendcert == cert_alwayssend);

	send_authcerts = (send_cert &&
		st->st_connection->send_ca != CA_SEND_NONE);

	send_full_chain = (send_authcerts &&
		st->st_connection->send_ca == CA_SEND_ALL);

	if (send_authcerts) {
		chain_len = get_auth_chain(auth_chain, MAX_CA_PATH_LEN,
				mycert.u.nss_cert,
				send_full_chain ? TRUE : FALSE);
	}

	if (chain_len < 1)
		send_authcerts = FALSE;

	doi_log_cert_thinking(st->st_oakley.auth,
			      mycert.ty,
			      st->st_connection->spd.this.sendcert,
			      st->hidden_variables.st_got_certrequest,
			      send_cert, send_authcerts);

	/* send certificate request, if we don't have a preloaded RSA public key */
	send_cr = send_cert && !has_preloaded_public_key(st);

	DBG(DBG_CONTROL,
	    DBG_log(" I am %ssending a certificate request",
		    send_cr ? "" : "not "));

	/*
	 * free collected certificate requests since as initiator
	 * we don't heed them anyway
	 */
	free_generalNames(st->st_requested_ca, TRUE);

	/* done parsing; initialize crypto  */

	init_out_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
		 "reply packet");

	/* HDR out */
	{
		struct isakmp_hdr hdr = md->hdr;

		hdr.isa_flags = 0; /* clear reserved fields */
		memcpy(hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
		hdr.isa_np = ISAKMP_NEXT_SA;

		if (DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
			hdr.isa_flags |= ISAKMP_FLAGS_RESERVED_BIT6;
		}

		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply_stream,
				&md->rbody))
			return STF_INTERNAL_ERROR;
	}

	/* start of SA out */
	{
		struct isakmp_sa r_sa;
		notification_t rn;

		zero(&r_sa);	/* OK: no pointer fields */
		r_sa.isasa_doi = ISAKMP_DOI_IPSEC;

		r_sa.isasa_np = ISAKMP_NEXT_KE;
		if (!out_struct(&r_sa, &isakmp_sa_desc, &md->rbody, &r_sa_pbs))
			return STF_INTERNAL_ERROR;

		/* SA body in and out */
		rn = parse_isakmp_sa_body(&sa_pd->pbs, &sa_pd->payload.sa,
					  &r_sa_pbs, FALSE, st);
		if (rn != NOTHING_WRONG)
			return STF_FAIL + rn;
	}

	/* don't know until after SA body has been parsed */
	auth_payload = st->st_oakley.auth == OAKLEY_PRESHARED_KEY ?
		       ISAKMP_NEXT_HASH : ISAKMP_NEXT_SIG;

	/************** build rest of output: KE, Nr, IDir, HASH_R/SIG_R ********/

	/* KE */
	if (!ikev1_justship_KE(&st->st_gr,
			 &md->rbody, ISAKMP_NEXT_NONCE))
		return STF_INTERNAL_ERROR;

	/* Nr */
	if (!ikev1_justship_nonce(&st->st_nr, &md->rbody, ISAKMP_NEXT_ID, "Nr"))
		return STF_INTERNAL_ERROR;

	/* IDir out */
	{
		struct isakmp_ipsec_id id_hd;
		chunk_t id_b;

		build_id_payload(&id_hd, &id_b, &st->st_connection->spd.this);
		id_hd.isaiid_np =
			(send_cert) ? ISAKMP_NEXT_CERT : auth_payload;

		if (!out_struct(&id_hd, &isakmp_ipsec_identification_desc,
				&md->rbody, &r_id_pbs) ||
		    !out_chunk(id_b, &r_id_pbs, "my identity"))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&r_id_pbs);
	}

	/* CERT out */
	if (send_cert) {
		pb_stream cert_pbs;

		struct isakmp_cert cert_hd;
		cert_hd.isacert_np =
			(send_cr) ? ISAKMP_NEXT_CR : ISAKMP_NEXT_SIG;
		cert_hd.isacert_type = mycert.ty;

		libreswan_log("I am sending my cert");

		if (!out_struct(&cert_hd,
				&isakmp_ipsec_certificate_desc,
				&md->rbody,
				&cert_pbs))
			return STF_INTERNAL_ERROR;

		if (!out_chunk(get_dercert_from_nss_cert(mycert.u.nss_cert),
								&cert_pbs, "CERT"))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&cert_pbs);
	}

	/* CR out */
	if (send_cr) {
		libreswan_log("I am sending a certificate request");
		if (!ikev1_build_and_ship_CR(mycert.ty,
				       st->st_connection->spd.that.ca,
				       &md->rbody, ISAKMP_NEXT_SIG))
			return STF_INTERNAL_ERROR;
	}

	update_iv(st);

	/* HASH_R or SIG_R out */
	{
		u_char hash_val[MAX_DIGEST_LEN];
		size_t hash_len =
			main_mode_hash(st, hash_val, FALSE, &r_id_pbs);

		if (auth_payload == ISAKMP_NEXT_HASH) {
			/* HASH_R out */
			if (!ikev1_out_generic_raw(ISAKMP_NEXT_VID,
					     &isakmp_hash_desc,
					     &md->rbody,
					     hash_val,
					     hash_len,
					     "HASH_R"))
				return STF_INTERNAL_ERROR;
		} else {
			/* SIG_R out */
			u_char sig_val[RSA_MAX_OCTETS];
			size_t sig_len = RSA_sign_hash(st->st_connection,
						       sig_val, hash_val,
						       hash_len);

			if (sig_len == 0) {
				loglog(RC_LOG_SERIOUS,
				       "unable to locate my private key for RSA Signature");
				return STF_FAIL + AUTHENTICATION_FAILED;
			}

			if (!ikev1_out_generic_raw(ISAKMP_NEXT_VID,
					     &isakmp_signature_desc,
					     &md->rbody, sig_val, sig_len,
					     "SIG_R"))
				return STF_INTERNAL_ERROR;
		}
	}
	/*
	 * NOW SEND VENDOR ID payloads
	 */

	if (st->st_connection->cisco_unity) {
		if (!out_vid(ISAKMP_NEXT_VID, &md->rbody, VID_CISCO_UNITY))
			return STF_INTERNAL_ERROR;
	}
	if (st->st_connection->fake_strongswan) {
		if (!out_vid(ISAKMP_NEXT_VID, &md->rbody, VID_STRONGSWAN))
			return STF_INTERNAL_ERROR;
	}

	if (st->hidden_variables.st_nat_traversal == LEMPTY) {
		/* Always announce our ability to do RFC 3706 Dead Peer Detection to the peer */
		if (!out_vid(ISAKMP_NEXT_NONE, &md->rbody, VID_MISC_DPD))
			return STF_INTERNAL_ERROR;
	} else {
		/* Always announce our ability to do RFC 3706 Dead Peer Detection to the peer */
		if (!out_vid(ISAKMP_NEXT_VID, &md->rbody, VID_MISC_DPD))
			return STF_INTERNAL_ERROR;

		/* and a couple more NAT VIDs */
		if (!out_vid(ISAKMP_NEXT_VID,
			     &md->rbody,
			     md->quirks.qnat_traversal_vid))
			return STF_INTERNAL_ERROR;
		if (!ikev1_nat_traversal_add_natd(ISAKMP_NEXT_NONE, &md->rbody, md))
			return STF_INTERNAL_ERROR;
	}

	/* finish message */
	if (!close_message(&md->rbody, st))
		return STF_INTERNAL_ERROR;

	return STF_OK;
}

/* STATE_AGGR_I1:
 * SMF_PSK_AUTH: HDR, SA, KE, Nr, IDir, HASH_R
 *           --> HDR*, HASH_I
 * SMF_DS_AUTH:  HDR, SA, KE, Nr, IDir, [CERT,] SIG_R
 *           --> HDR*, [CERT,] SIG_I
 */
static stf_status aggr_inR1_outI2_tail(struct msg_digest *md,
				       struct key_continuation *kc); /* forward */

stf_status aggr_inR1_outI2(struct msg_digest *md)
{
	/* With Aggressive Mode, we get an ID payload in this, the second
	 * message, so we can use it to index the preshared-secrets
	 * when the IP address would not be meaningful (i.e. Road
	 * Warrior).  So our first task is to unravel the ID payload.
	 */
	struct state *st = md->st;

	st->st_policy |= POLICY_AGGRESSIVE;	/* ??? surely this should be done elsewhere */

	if (!ikev1_decode_peer_id(md, FALSE, TRUE)) {
		char buf[IDTOA_BUF];
		ipstr_buf b;

		(void) idtoa(&st->st_connection->spd.that.id, buf,
			     sizeof(buf));
		loglog(RC_LOG_SERIOUS,
		       "initial Aggressive Mode packet claiming to be from %s on %s but no connection has been authorized",
		       buf, ipstr(&md->sender, &b));
		/* XXX notification is in order! */
		return STF_FAIL + INVALID_ID_INFORMATION;
	}

	/* verify echoed SA */
	{
		struct payload_digest *const sapd = md->chain[ISAKMP_NEXT_SA];
		notification_t r = \
			parse_isakmp_sa_body(&sapd->pbs, &sapd->payload.sa,
					     NULL, TRUE, st);

		if (r != NOTHING_WRONG)
			return STF_FAIL + r;
	}

	merge_quirks(st, md);

	set_nat_traversal(st, md);

	/* KE in */
	RETURN_STF_FAILURE(accept_KE(&st->st_gr, "Gr", st->st_oakley.group,
				     &md->chain[ISAKMP_NEXT_KE]->pbs));

	/* Ni in */
	RETURN_STF_FAILURE(accept_v1_nonce(md, &st->st_nr, "Nr"));

	/* moved the following up as we need Rcookie for hash, skeyids */
	/* Reinsert the state, using the responder cookie we just received */
	rehash_state(st, md->hdr.isa_rcookie);

	ikev1_natd_init(st, md);

	/* set up second calculation */
	{
		struct pluto_crypto_req_cont *dh = new_pcrc(
			aggr_inR1_outI2_crypto_continue,
			"aggr outR1 DH",
			st, md);

		return start_dh_secretiv(dh, st,
					 st->st_import,
					 ORIGINAL_INITIATOR,
					 st->st_oakley.group->group);
	}
}

/* redundant type assertion: static crypto_req_cont_func aggr_inR1_outI2_crypto_continue; */

static void aggr_inR1_outI2_crypto_continue(struct pluto_crypto_req_cont *dh,
					    struct pluto_crypto_req *r)
{
	struct msg_digest *md = dh->pcrc_md;
	struct state *const st = md->st;
	stf_status e;

	DBG(DBG_CONTROLMORE,
	    DBG_log("aggr inR1_outI2: calculated DH, sending I2"));

	if (dh->pcrc_serialno == SOS_NOBODY) {
		loglog(RC_LOG_SERIOUS,
		       "%s: Request was disconnected from state",
		       __FUNCTION__);
		release_any_md(&dh->pcrc_md);
		return;
	}

	passert(cur_state == NULL);
	passert(st != NULL);

	passert(st->st_suspended_md == dh->pcrc_md);
	unset_suspended(st); /* no longer connected or suspended */

	set_cur_state(st);
	DBG(DBG_CONTROLMORE, DBG_log("#%lu %s:%u st->st_calculating = FALSE;", st->st_serialno, __FUNCTION__, __LINE__));
	st->st_calculating = FALSE;

	if (!finish_dh_secretiv(st, r)) {
		e = STF_FAIL + INVALID_KEY_INFORMATION;
	} else {
		e = aggr_inR1_outI2_tail(md, NULL);
	}

	passert(dh->pcrc_md != NULL);
	complete_v1_state_transition(&dh->pcrc_md, e);
	release_any_md(&dh->pcrc_md);
	reset_cur_state();
}

static void aggr_inR1_outI2_continue(struct adns_continuation *cr, err_t ugh)
{
	key_continue(cr, ugh, aggr_inR1_outI2_tail);
}

static stf_status aggr_inR1_outI2_tail(struct msg_digest *md,
				       struct key_continuation *kc)
{
	struct state *const st = md->st;
	struct connection *c = st->st_connection;
	int auth_payload;

	/* HASH_R or SIG_R in */
	{
		stf_status r = aggr_id_and_auth(md, TRUE,
						aggr_inR1_outI2_continue, kc);

		if (r != STF_OK)
			return r;
	}

	auth_payload = st->st_oakley.auth == OAKLEY_PRESHARED_KEY ?
		       ISAKMP_NEXT_HASH : ISAKMP_NEXT_SIG;

	/**************** build output packet: HDR, HASH_I/SIG_I **************/

	/* make sure HDR is at start of a clean buffer */
	init_out_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
		 "reply packet");

	/* HDR out */
	{
		struct isakmp_hdr hdr = md->hdr;

		hdr.isa_flags = 0; /* clear reserved fields */
		memcpy(hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
		hdr.isa_np = auth_payload;
		hdr.isa_flags |= ISAKMP_FLAGS_v1_ENCRYPTION;

		if (DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
			hdr.isa_flags |= ISAKMP_FLAGS_RESERVED_BIT6;
		}

		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply_stream,
				&md->rbody))
			return STF_INTERNAL_ERROR;
	}

	if (st->hidden_variables.st_nat_traversal != LEMPTY) {
		if (!ikev1_nat_traversal_add_natd(auth_payload, &md->rbody, md))
			return STF_INTERNAL_ERROR;
	}

	/* HASH_I or SIG_I out */
	{
		u_char idbuf[1024]; /* fits all possible identity payloads? */
		struct isakmp_ipsec_id id_hd;
		chunk_t id_b;
		pb_stream id_pbs;
		u_char hash_val[MAX_DIGEST_LEN];
		size_t hash_len;

		build_id_payload(&id_hd, &id_b, &st->st_connection->spd.this);
		init_out_pbs(&id_pbs, idbuf, sizeof(idbuf), "identity payload");
		id_hd.isaiid_np = ISAKMP_NEXT_NONE;
		if (!out_struct(&id_hd, &isakmp_ipsec_identification_desc,
				&id_pbs, NULL) ||
		    !out_chunk(id_b, &id_pbs, "my identity"))
			return STF_INTERNAL_ERROR;

		hash_len = main_mode_hash(st, hash_val, TRUE, &id_pbs);

		if (auth_payload == ISAKMP_NEXT_HASH) {
			/* HASH_I out */
			if (!ikev1_out_generic_raw(ISAKMP_NEXT_NONE,
					     &isakmp_hash_desc, &md->rbody,
					     hash_val, hash_len, "HASH_I"))
				return STF_INTERNAL_ERROR;
		} else {
			/* SIG_I out */
			u_char sig_val[RSA_MAX_OCTETS];
			size_t sig_len = RSA_sign_hash(st->st_connection,
						       sig_val, hash_val,
						       hash_len);

			if (sig_len == 0) {
				loglog(RC_LOG_SERIOUS,
				       "unable to locate my private key for RSA Signature");
				return STF_FAIL + AUTHENTICATION_FAILED;
			}

			if (!ikev1_out_generic_raw(ISAKMP_NEXT_NONE,
					     &isakmp_signature_desc,
					     &md->rbody, sig_val, sig_len,
					     "SIG_I"))
				return STF_INTERNAL_ERROR;
		}
	}

	/* RFC2408 says we must encrypt at this point */

	/* st_new_iv was computed by generate_skeyids_iv (??? DOESN'T EXIST) */
	if (!encrypt_message(&md->rbody, st))
		return STF_INTERNAL_ERROR; /* ??? we may be partly committed */

	/* It seems as per Cisco implementation, XAUTH and MODECFG
	 * are not supposed to be performed again during rekey
	 */
	if (c->newest_isakmp_sa != SOS_NOBODY &&
	    st->st_connection->spd.this.xauth_client &&
	    st->st_connection->remotepeertype == CISCO) {
		DBG(DBG_CONTROL,
		    DBG_log("Skipping XAUTH for rekey for Cisco Peer compatibility."));
		st->hidden_variables.st_xauth_client_done = TRUE;
		st->st_oakley.doing_xauth = FALSE;

		if (st->st_connection->spd.this.modecfg_client) {
			DBG(DBG_CONTROL,
			    DBG_log("Skipping XAUTH for rekey for Cisco Peer compatibility."));
			st->hidden_variables.st_modecfg_vars_set = TRUE;
			st->hidden_variables.st_modecfg_started = TRUE;
		}
	}

	if (c->newest_isakmp_sa != SOS_NOBODY &&
	    st->st_connection->spd.this.xauth_client &&
	    st->st_connection->remotepeertype == CISCO) {
		DBG(DBG_CONTROL,
		    DBG_log("This seems to be rekey, and XAUTH is not supposed to be done again"));
		st->hidden_variables.st_xauth_client_done = TRUE;
		st->st_oakley.doing_xauth = FALSE;

		if (st->st_connection->spd.this.modecfg_client) {
			DBG(DBG_CONTROL,
			    DBG_log("This seems to be rekey, and MODECFG is not supposed to be done again"));
			st->hidden_variables.st_modecfg_vars_set = TRUE;
			st->hidden_variables.st_modecfg_started = TRUE;
		}
	}

	c->newest_isakmp_sa = st->st_serialno;

	/* save last IV from phase 1 so it can be restored later so anything
	 * between the end of phase 1 and the start of phase 2 i.e. mode config
	 * payloads etc. will not lose our IV
	 */
	set_ph1_iv_from_new(st);
	DBG(DBG_CONTROL, DBG_log("phase 1 complete"));
#ifdef USE_LINUX_AUDIT
	linux_audit_conn(st, LAK_PARENT_START);
#endif
	return STF_OK;
}

/* STATE_AGGR_R1:
 * SMF_PSK_AUTH: HDR*, HASH_I --> done
 * SMF_DS_AUTH:  HDR*, SIG_I  --> done
 */
static stf_status aggr_inI2_tail(struct msg_digest *md,
			  struct key_continuation *kc);         /* forward */

static void aggr_inI2_continue(struct adns_continuation *cr, err_t ugh)
{
	key_continue(cr, ugh, aggr_inI2_tail);
}

stf_status aggr_inI2(struct msg_digest *md)
{
	return aggr_inI2_tail(md, NULL);
}

static stf_status aggr_inI2_tail(struct msg_digest *md,
			  struct key_continuation *kc)
{
	struct state *const st = md->st;
	struct connection *c = st->st_connection;
	u_char idbuf[1024];	/* ??? enough room for reconstructed peer ID payload? */
	struct payload_digest id_pd;

	ikev1_natd_init(st, md);

	/* Reconstruct the peer ID so the peer hash can be authenticated */
	{
		struct isakmp_ipsec_id id_hd;
		chunk_t id_b;
		pb_stream pbs;
		pb_stream id_pbs;

		build_id_payload(&id_hd, &id_b, &st->st_connection->spd.that);
		init_out_pbs(&pbs, idbuf, sizeof(idbuf), "identity payload");
		id_hd.isaiid_np = ISAKMP_NEXT_NONE;

		/* interop ID for SoftRemote & maybe others ? */
		id_hd.isaiid_protoid = st->st_peeridentity_protocol;
		id_hd.isaiid_port = htons(st->st_peeridentity_port);

		if (!out_struct(&id_hd, &isakmp_ipsec_identification_desc,
				&pbs, &id_pbs) ||
		    !out_chunk(id_b, &id_pbs, "my identity"))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&id_pbs);
		id_pbs.roof = pbs.cur;
		id_pbs.cur = pbs.start;
		if (!in_struct(&id_pd.payload, &isakmp_identification_desc, &id_pbs,
			  &id_pd.pbs))
			return STF_FAIL + PAYLOAD_MALFORMED;
	}
	md->chain[ISAKMP_NEXT_ID] = &id_pd;

	/* HASH_I or SIG_I in */
	{
		stf_status r = aggr_id_and_auth(md, FALSE,
						aggr_inI2_continue, kc);

		if (r != STF_OK)
			return r;
	}

	/* And reset the md to not leave stale pointers to our private id payload */
	md->chain[ISAKMP_NEXT_ID] = NULL;

	/**************** done input ****************/

	/* It seems as per Cisco implementation, XAUTH and MODECFG
	 * are not supposed to be performed again during rekey
	 */
	if (c->newest_isakmp_sa != SOS_NOBODY &&
	    st->st_connection->spd.this.xauth_client &&
	    st->st_connection->remotepeertype == CISCO) {
		DBG(DBG_CONTROL,
		    DBG_log("Skipping XAUTH for rekey for Cisco Peer compatibility."));
		st->hidden_variables.st_xauth_client_done = TRUE;
		st->st_oakley.doing_xauth = FALSE;

		if (st->st_connection->spd.this.modecfg_client) {
			DBG(DBG_CONTROL,
			    DBG_log("Skipping ModeCFG for rekey for Cisco Peer compatibility."));
			st->hidden_variables.st_modecfg_vars_set = TRUE;
			st->hidden_variables.st_modecfg_started = TRUE;
		}
	}

	if (c->newest_isakmp_sa != SOS_NOBODY &&
	    st->st_connection->spd.this.xauth_client &&
	    st->st_connection->remotepeertype == CISCO) {
		DBG(DBG_CONTROL,
		    DBG_log("This seems to be rekey, and XAUTH is not supposed to be done again"));
		st->hidden_variables.st_xauth_client_done = TRUE;
		st->st_oakley.doing_xauth = FALSE;

		if (st->st_connection->spd.this.modecfg_client) {
			DBG(DBG_CONTROL,
			    DBG_log("This seems to be rekey, and MODECFG is not supposed to be done again"));
			st->hidden_variables.st_modecfg_vars_set = TRUE;
			st->hidden_variables.st_modecfg_started = TRUE;
		}
	}

	c->newest_isakmp_sa = st->st_serialno;

	update_iv(st);  /* Finalize our Phase 1 IV */

	/* save last IV from phase 1 so it can be restored later so anything
	 * between the end of phase 1 and the start of phase 2 i.e. mode config
	 * payloads etc. will not lose our IV
	 */
	set_ph1_iv_from_new(st);
	DBG(DBG_CONTROL, DBG_log("phase 1 complete"));
#ifdef USE_LINUX_AUDIT
	linux_audit_conn(st, LAK_PARENT_START);
#endif
	return STF_OK;
}

/*
 * Initiate an Oakley Aggressive Mode exchange.
 * --> HDR, SA, KE, Ni, IDii
 */
static stf_status aggr_outI1_tail(struct pluto_crypto_req_cont *ke,
				  struct pluto_crypto_req *r);	/* forward */

static crypto_req_cont_func aggr_outI1_continue;	/* type assertion */

static void aggr_outI1_continue(struct pluto_crypto_req_cont *ke,
				struct pluto_crypto_req *r)
{
	struct msg_digest *md = ke->pcrc_md;
	struct state *const st = md->st;
	stf_status e;

	DBG(DBG_CONTROL,
		DBG_log("aggr_outI1_continue for #%lu: calculated ke+nonce, sending I1",
			ke->pcrc_serialno));

	if (ke->pcrc_serialno == SOS_NOBODY) {
		loglog(RC_LOG_SERIOUS,
		       "%s: Request was disconnected from state",
		       __FUNCTION__);
		release_any_md(&ke->pcrc_md);
		return;
	}

	passert(ke->pcrc_serialno == st->st_serialno);	/* transitional */

	passert(cur_state == NULL);
	passert(st != NULL);

	passert(st->st_suspended_md == ke->pcrc_md);
	unset_suspended(st); /* no longer connected or suspended */

	set_cur_state(st);

	DBG(DBG_CONTROLMORE, DBG_log("#%lu %s:%u st->st_calculating = FALSE;", st->st_serialno, __FUNCTION__, __LINE__));
	st->st_calculating = FALSE;

	e = aggr_outI1_tail(ke, r);

	passert(ke->pcrc_md != NULL);
	complete_v1_state_transition(&ke->pcrc_md, e);
	release_any_md(&ke->pcrc_md);
	reset_globals();

	passert(GLOBALS_ARE_RESET());
}

/* No initial state for aggr_outI1:
 * SMF_DS_AUTH (RFC 2409 5.1) and SMF_PSK_AUTH (RFC 2409 5.4):
 * -->HDR, SA, KE, Ni, IDii
 *
 * Not implemented:
 * RFC 2409 5.2: --> HDR, SA, [ HASH(1),] KE, <IDii_b>Pubkey_r, <Ni_b>Pubkey_r
 * RFC 2409 5.3: --> HDR, SA, [ HASH(1),] <Ni_b>Pubkey_r, <KE_b>Ke_i, <IDii_b>Ke_i [, <Cert-I_b>Ke_i ]
 */
stf_status aggr_outI1(int whack_sock,
		      struct connection *c,
		      struct state *predecessor,
		      lset_t policy,
		      unsigned long try,
		      enum crypto_importance importance
#ifdef HAVE_LABELED_IPSEC
		      , struct xfrm_user_sec_ctx_ike *uctx
#endif
		      )
{
	struct state *st;
	struct spd_route *sr;

	if (drop_new_exchanges()) {
		/* Only drop outgoing opportunistic connections */
		if (c->policy & POLICY_OPPORTUNISTIC) {
			return STF_IGNORE;
		}
	}

	if ((c->policy & POLICY_AGGRESSIVE) != LEMPTY){
		loglog(RC_LOG_SERIOUS,
			"IKEv1 Aggressive Mode with PSK is vulnerable to dictionary attacks and is cracked on large scale by TLA's");
	}

	/* set up new state */
	cur_state = st = new_state();
	st->st_connection = c;	/* safe: from new_state */
#ifdef HAVE_LABELED_IPSEC
	st->sec_ctx = NULL;
#endif
	set_state_ike_endpoints(st, c);

	extra_debugging(c);
	st->st_policy = policy & ~POLICY_IPSEC_MASK;
	st->st_whack_sock = whack_sock;
	st->st_try = try;
	change_state(st, STATE_AGGR_I1);

	get_cookie(TRUE, st->st_icookie, &c->spd.that.host_addr);

	st->st_import = importance;

	for (sr = &c->spd; sr != NULL; sr = sr->spd_next) {
		if (sr->this.xauth_client) {
			if (sr->this.username != NULL) {
				jam_str(st->st_username,
					sizeof(st->st_username),
					sr->this.username);
				break;
			}
		}
	}

	insert_state(st); /* needs cookies, connection, and msgid (0) */

	if (!init_aggr_st_oakley(st, policy)) {
		/*
		 * This is only the case if NO IKE proposal was specified in the
		 * configuration file.  It's not the case if there were multiple
		 * configurations, even conflicting multiple DH groups.  So this
		 * should tell the user to add a proper proposal policy
		 */
		loglog(RC_AGGRALGO,
		       "no IKE proposal policy specified in config!  Cannot initiate aggressive mode.  A policy must be specified in the configuration and should contain at most one DH group (mod1024, mod1536, mod2048).  Only the first DH group will be honored.");
		reset_globals();
		return STF_FAIL;
	}

	if (HAS_IPSEC_POLICY(policy))
		add_pending(dup_any(whack_sock), st, c, policy, 1,
			    predecessor == NULL ? SOS_NOBODY : predecessor->st_serialno
#ifdef HAVE_LABELED_IPSEC
			    , uctx
#endif
			    );

	if (predecessor == NULL) {
		libreswan_log("initiating Aggressive Mode");
	} else {
		update_pending(predecessor, st);
		libreswan_log(
			"initiating Aggressive Mode #%lu to replace #%lu",
			st->st_serialno, predecessor->st_serialno);
	}

	/*
	 * Calculate KE and Nonce.
	 *
	 * We need an md because the crypto continuation mechanism requires one
	 * but we don't have one because we are not responding to an
	 * incoming packet.
	 * Solution: build a fake one.  How much do we need to fake?
	 * Note: almost identical code appears at the end of ikev2parent_outI1.
	 */
	{
		struct msg_digest *fake_md = alloc_md();
		struct pluto_crypto_req_cont *ke;
		stf_status e;

		fake_md->st = st;
		fake_md->smc = NULL;	/* ??? */
		fake_md->from_state = STATE_UNDEFINED;	/* ??? */

		ke = new_pcrc(aggr_outI1_continue, "aggr_outI1 KE + nonce",
			st, fake_md);
		e = build_ke_and_nonce(ke, st->st_oakley.group, importance);

		/*
		 * ??? what exactly do we expect for e?
		 * ??? Who frees ke? md?
		 */

		reset_globals();
		return e;
	}
}

static stf_status aggr_outI1_tail(struct pluto_crypto_req_cont *ke,
				  struct pluto_crypto_req *r)
{
	struct msg_digest *md = ke->pcrc_md;
	struct state *const st = md->st;
	struct connection *c = st->st_connection;

	passert(ke->pcrc_serialno == st->st_serialno);	/* transitional */

	DBG(DBG_CONTROL,
		DBG_log("aggr_outI1_tail for #%lu",
			ke->pcrc_serialno));

	/* the MD is already set up by alloc_md() */

	/* make sure HDR is at start of a clean buffer */
	init_out_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
		 "reply packet");

	/* HDR out */
	{
		struct isakmp_hdr hdr;

		zero(&hdr);	/* OK: no pointer fields */
		hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
				  ISAKMP_MINOR_VERSION;
		hdr.isa_np = ISAKMP_NEXT_SA;
		hdr.isa_xchg = ISAKMP_XCHG_AGGR;
		memcpy(hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
		/* R-cookie, flags and MessageID are left zero */

		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply_stream,
				&md->rbody)) {
			cur_state = NULL;
			return STF_INTERNAL_ERROR;
		}
	}

	/* SA out */
	{
		u_char *sa_start = md->rbody.cur;

		if (!ikev1_out_sa(&md->rbody,
				  IKEv1_oakley_am_sadb(st->st_policy, c),
				  st, TRUE, TRUE, ISAKMP_NEXT_KE)) {
			cur_state = NULL;
			return STF_INTERNAL_ERROR;
		}

		/* save initiator SA for later HASH */
		passert(st->st_p1isa.ptr == NULL); /* no leak! */
		clonetochunk(st->st_p1isa, sa_start, md->rbody.cur - sa_start,
			     "sa in aggr_outI1");
	}

	/* KE out */
	if (!ikev1_ship_KE(st, r, &st->st_gi,
		     &md->rbody, ISAKMP_NEXT_NONCE))
		return STF_INTERNAL_ERROR;

	/* Ni out */
	if (!ikev1_ship_nonce(&st->st_ni, r, &md->rbody, ISAKMP_NEXT_ID, "Ni"))
		return STF_INTERNAL_ERROR;

	DBG(DBG_CONTROLMORE, DBG_log("setting sec: %s", st->st_sec_in_use ? "TRUE" : "FALSE"));

	/* IDii out */
	{
		struct isakmp_ipsec_id id_hd;
		chunk_t id_b;
		pb_stream id_pbs;

		build_id_payload(&id_hd, &id_b, &st->st_connection->spd.this);
		id_hd.isaiid_np = ISAKMP_NEXT_VID;
		if (!out_struct(&id_hd, &isakmp_ipsec_identification_desc,
				&md->rbody, &id_pbs) ||
		    !out_chunk(id_b, &id_pbs, "my identity"))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&id_pbs);
	}

	int numvidtosend = 1; /* Always announce DPD capablity */

	if (c->spd.this.xauth_client || c->spd.this.xauth_server)
		numvidtosend++;

	if (nat_traversal_enabled)
		numvidtosend++;
	if (c->cisco_unity)
		numvidtosend++;
	if (c->fake_strongswan)
		numvidtosend++;

	if (c->send_vendorid)
		numvidtosend++;

	if (c->policy & POLICY_IKE_FRAG_ALLOW)
		numvidtosend++;

	/* ALWAYS Announce our ability to do Dead Peer Detection to the peer */
	{
		int np = --numvidtosend > 0 ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;
		if (!out_vid(np, &md->rbody, VID_MISC_DPD))
			return STF_INTERNAL_ERROR;
	}

	if (nat_traversal_enabled) {
		int np = --numvidtosend > 0 ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;

		if (!nat_traversal_insert_vid(np, &md->rbody, st)) {
			reset_cur_state();
			return STF_INTERNAL_ERROR;
		}
	}

	if (c->spd.this.xauth_client || c->spd.this.xauth_server) {
		int np = --numvidtosend > 0 ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;
		if (!out_vid(np, &md->rbody, VID_MISC_XAUTH))
			return STF_INTERNAL_ERROR;
	}

	if (c->cisco_unity) {
		int np = --numvidtosend > 0 ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;
		if (!out_vid(np, &md->rbody, VID_CISCO_UNITY))
			return STF_INTERNAL_ERROR;
	}

	if (c->fake_strongswan) {
		int np = --numvidtosend > 0 ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;
		if (!out_vid(np, &md->rbody, VID_STRONGSWAN))
			return STF_INTERNAL_ERROR;
	}

	if (c->send_vendorid) {
		int np = --numvidtosend > 0 ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;
		if (!out_vid(np, &md->rbody, VID_LIBRESWANSELF))
			return STF_INTERNAL_ERROR;
	}

	if (c->policy & POLICY_IKE_FRAG_ALLOW) {
		int np = --numvidtosend > 0 ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;
		if (!out_vid(np, &md->rbody, VID_IKE_FRAGMENTATION))
			return STF_INTERNAL_ERROR;
	}

	/* INITIAL_CONTACT is an authenticated message, no VID here */

	passert(numvidtosend == 0);


	/* finish message */

	if (!close_message(&md->rbody, st))
		return STF_INTERNAL_ERROR;

	close_output_pbs(&reply_stream);

	/* Transmit */
	record_and_send_ike_msg(st, &reply_stream, "aggr_outI1");

	/* Set up a retransmission event, half a minute hence */
	delete_event(st);
	event_schedule_ms(EVENT_v1_RETRANSMIT, c->r_interval, st);

	whack_log(RC_NEW_STATE + STATE_AGGR_I1,
		  "%s: initiate", enum_name(&state_names, st->st_state));
	cur_state = NULL;
	return STF_IGNORE;
}
