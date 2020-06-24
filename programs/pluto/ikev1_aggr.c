/* IPsec DOI and Oakley resolution routines
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2005  Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2011 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Philippe Vouters <philippe.vouters@laposte.net>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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
 */

#include <unistd.h>

#include "constants.h"		/* for dup_any()!?! ... */
#include "lswlog.h"

#include "defs.h"
#include "state.h"
#include "connections.h"        /* needs id.h */
#include "packet.h"
#include "demux.h"      /* needs packet.h */
#include "log.h"
#include "ike_spi.h"
#include "spdb.h"
#include "ipsec_doi.h"  /* needs demux.h and state.h */
#include "ikev1_send.h"
#include "pluto_crypt.h"
#include "ikev1.h"
#include "vendor.h"
#include "nat_traversal.h"
#include "pluto_x509.h"
#include "fd.h"
#include "hostpair.h"
#include "ikev1_message.h"
#include "pending.h"
#include "iface.h"
#include "secrets.h"

#ifdef USE_XFRM_INTERFACE
# include "kernel_xfrm_interface.h"
#endif

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

static stf_status aggr_inI1_outR1_continue2_tail(struct msg_digest *md,
						 struct pluto_crypto_req *r);

/*
 * continuation from second calculation (the DH one)
 */

static crypto_req_cont_func aggr_inI1_outR1_continue2;	/* type assertion */

static void aggr_inI1_outR1_continue2(struct state *st,
				      struct msg_digest *md,
				      struct pluto_crypto_req *r)
{
	dbg("aggr_inI1_outR1_continue2 for #%lu: calculated ke+nonce+DH, sending R1",
	    st->st_serialno);

	passert(md != NULL);
	stf_status e = aggr_inI1_outR1_continue2_tail(md, r);
	complete_v1_state_transition(md, e);
}

/*
 * for aggressive mode, this is sub-optimal, since we should have
 * had the crypto helper actually do everything, but we need to do
 * some additional work to set that all up, so this is fine for now.
 */

static crypto_req_cont_func aggr_inI1_outR1_continue1;	/* type assertion */

static void aggr_inI1_outR1_continue1(struct state *st,
				      struct msg_digest *md,
				      struct pluto_crypto_req *r)
{
	dbg("aggr inI1_outR1: calculated ke+nonce, calculating DH");

	/* unpack first calculation */
	unpack_KE_from_helper(st, r, &st->st_gr);

	/* unpack nonce too */
	unpack_nonce(&st->st_nr, r);

	/* NOTE: the "r" reply will get freed by our caller */

	/* set up second calculation */
	start_dh_v1_secretiv(aggr_inI1_outR1_continue2, "aggr outR1 DH",
			     st, SA_RESPONDER, st->st_oakley.ta_dh);
	/*
	 * XXX: Since more crypto has been requested, MD needs to be re
	 * suspended.  If the original crypto request did everything
	 * this wouldn't be needed.
	 */
	suspend_any_md(st, md);
}

/* STATE_AGGR_R0:
 * SMF_PSK_AUTH: HDR, SA, KE, Ni, IDii
 *           --> HDR, SA, KE, Nr, IDir, HASH_R
 * SMF_DS_AUTH:  HDR, SA, KE, Nr, IDii
 *           --> HDR, SA, KE, Nr, IDir, [CERT,] SIG_R
 */
stf_status aggr_inI1_outR1(struct state *unused_st UNUSED,
			   struct msg_digest *md)
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

	struct connection *c = find_host_connection(&md->iface->local_endpoint,
						    &md->sender, policy, policy_exact_mask);

	if (c == NULL) {
		c = find_host_connection(&md->iface->local_endpoint, NULL,
					 policy, policy_exact_mask);
		if (c == NULL) {
			endpoint_buf b;

			loglog(RC_LOG_SERIOUS,
				"initial Aggressive Mode message from %s but no (wildcard) connection has been configured with policy %s",
				str_endpoint(&md->sender, &b),
				bitnamesof(sa_policy_bit_names, policy));
			/* XXX notification is in order! */
			return STF_IGNORE;
		}
		passert(LIN(policy, c->policy));
		/* Create a temporary connection that is a copy of this one.
		 * Peers ID isn't declared yet.
		 */
		ip_address sender_address = endpoint_address(&md->sender);
		c = rw_instantiate(c, &sender_address, NULL, NULL);
	}

	/* Set up state */
	struct ike_sa *ike = new_v1_rstate(md);
	struct state *st = &ike->sa;

	md->st = st;  /* (caller will reset cur_state) */
	set_cur_state(st);
	update_state_connection(st, c);
	change_state(st, STATE_AGGR_R1);

	/* warn for especially dangerous Aggressive Mode and PSK */
	if (LIN(POLICY_PSK, c->policy) && LIN(POLICY_AGGRESSIVE, c->policy)) {
		log_state(RC_LOG_SERIOUS, st,
			  "IKEv1 Aggressive Mode with PSK is vulnerable to dictionary attacks and is cracked on large scale by TLA's");
	}

	st->st_policy = policy;	/* ??? not sure what's needed here */

	/* ??? not sure what's needed here */
	st->st_oakley.auth = policy & POLICY_PSK ? OAKLEY_PRESHARED_KEY :
		policy & POLICY_RSASIG ? OAKLEY_RSA_SIG :
		0;	/* we don't really know */

	if (!v1_decode_certs(md)) {
		libreswan_log("X509: CERT payload bogus or revoked");
		return false;
	}

	/*
	 * note: ikev1_decode_peer_id may change which connection is referenced by md->st->st_connection.
	 * But not in this case because we are Aggressive Mode
	 */
	if (!ikev1_decode_peer_id(md, FALSE, TRUE)) {
		id_buf buf;
		endpoint_buf b;
		loglog(RC_LOG_SERIOUS,
		       "initial Aggressive Mode packet claiming to be from %s on %s but no matching connection has been authorized",
		       str_id(&st->st_connection->spd.that.id, &buf),
		       str_endpoint(&md->sender, &b));
		/* XXX notification is in order! */
		return STF_FAIL + INVALID_ID_INFORMATION;
	}

	passert(c == st->st_connection);

	st->st_try = 0;                                 /* Not our job to try again from start */
	st->st_policy = c->policy & ~POLICY_IPSEC_MASK; /* only as accurate as connection */

	binlog_refresh_state(st);

	{
		ipstr_buf b;
		char cib[CONN_INST_BUF];

		libreswan_log("responding to Aggressive Mode, state #%lu, connection \"%s\"%s from %s",
			st->st_serialno,
			st->st_connection->name, fmt_conn_instance(st->st_connection, cib),
			sensitive_ipstr(&c->spd.that.host_addr, &b));
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
	st->st_p1isa = clone_hunk(pbs_in_as_shunk(&sa_pd->pbs), "sa in aggr_inI1_outR1()");

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
	if (!accept_KE(&st->st_gi, "Gi", st->st_oakley.ta_dh,
		       md->chain[ISAKMP_NEXT_KE])) {
		return STF_FAIL + INVALID_KEY_INFORMATION;
	}

	/* Ni in */
	RETURN_STF_FAILURE(accept_v1_nonce(st->st_logger, md, &st->st_ni, "Ni"));

	/* calculate KE and Nonce */
	request_ke_and_nonce("outI2 KE", st,
			     st->st_oakley.ta_dh,
			     aggr_inI1_outR1_continue1);
	return STF_SUSPEND;
}

static stf_status aggr_inI1_outR1_continue2_tail(struct msg_digest *md,
						 struct pluto_crypto_req *r)
{
	struct state *const st = md->st;
	const struct connection *c = st->st_connection;
	struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_SA];
	const cert_t mycert = c->spd.this.cert;

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
	bool send_cert = st->st_oakley.auth == OAKLEY_RSA_SIG &&
		mycert.ty != CERT_NONE &&
		mycert.u.nss_cert != NULL &&
		((c->spd.this.sendcert == CERT_SENDIFASKED &&
		  st->hidden_variables.st_got_certrequest) ||
		 c->spd.this.sendcert == CERT_ALWAYSSEND
		);

	bool send_authcerts = (send_cert && c->send_ca != CA_SEND_NONE);

	/*****
	 * From here on, if send_authcerts, we are obligated to:
	 * free_auth_chain(auth_chain, chain_len);
	 *****/

	chunk_t auth_chain[MAX_CA_PATH_LEN] = { { NULL, 0 } };
	int chain_len = 0;

	if (send_authcerts) {
		chain_len = get_auth_chain(auth_chain, MAX_CA_PATH_LEN,
				mycert.u.nss_cert,
				c->send_ca == CA_SEND_ALL);

		if (chain_len == 0)
			send_authcerts = FALSE;
	}

	doi_log_cert_thinking(st->st_oakley.auth,
			      mycert.ty,
			      c->spd.this.sendcert,
			      st->hidden_variables.st_got_certrequest,
			      send_cert, send_authcerts);

	/* send certificate request, if we don't have a preloaded RSA public key */
	bool send_cr = send_cert && !has_preloaded_public_key(st);

	dbg(" I am %ssending a certificate request",
	    send_cr ? "" : "not ");

	/* done parsing; initialize crypto  */

	init_out_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
		 "reply packet");

	/* HDR out */
	pb_stream rbody;

	{
		struct isakmp_hdr hdr = md->hdr;

		hdr.isa_flags = 0; /* clear reserved fields */
		hdr.isa_ike_responder_spi = st->st_ike_spis.responder;
		hdr.isa_np = ISAKMP_NEXT_NONE; /* clear NP */

		if (impair.send_bogus_isakmp_flag) {
			hdr.isa_flags |= ISAKMP_FLAGS_RESERVED_BIT6;
		}

		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply_stream,
				&rbody)) {
			free_auth_chain(auth_chain, chain_len);
			return STF_INTERNAL_ERROR;
		}
	}

	/* start of SA out */
	{
		struct isakmp_sa r_sa = {
			.isasa_doi = ISAKMP_DOI_IPSEC,
		};

		pb_stream r_sa_pbs;

		if (!out_struct(&r_sa, &isakmp_sa_desc, &rbody,
				&r_sa_pbs)) {
			free_auth_chain(auth_chain, chain_len);
			return STF_INTERNAL_ERROR;
		}

		/* SA body in and out */
		notification_t rn = parse_isakmp_sa_body(&sa_pd->pbs,
			&sa_pd->payload.sa, &r_sa_pbs, FALSE, st);
		if (rn != NOTHING_WRONG) {
			free_auth_chain(auth_chain, chain_len);
			return STF_FAIL + rn;
		}
	}

	/* don't know until after SA body has been parsed */
	enum next_payload_types_ikev1 auth_payload =
		st->st_oakley.auth == OAKLEY_PRESHARED_KEY ?
		       ISAKMP_NEXT_HASH : ISAKMP_NEXT_SIG;

	/************** build rest of output: KE, Nr, IDir, HASH_R/SIG_R ********/

	/* KE */
	if (!ikev1_justship_KE(st->st_logger, &st->st_gr, &rbody)) {
		free_auth_chain(auth_chain, chain_len);
		return STF_INTERNAL_ERROR;
	}

	/* Nr */
	if (!ikev1_justship_nonce(&st->st_nr, &rbody, "Nr")) {
		free_auth_chain(auth_chain, chain_len);
		return STF_INTERNAL_ERROR;
	}

	/* IDir out */

	pb_stream r_id_pbs; /* ID Payload; used later for hash calculation; XXX: use ID_B instead? */

	{
		shunk_t id_b;
		struct isakmp_ipsec_id id_hd = build_v1_id_payload(&c->spd.this, &id_b);
		if (!out_struct(&id_hd, &isakmp_ipsec_identification_desc,
				&rbody, &r_id_pbs) ||
		    !pbs_out_hunk(id_b, &r_id_pbs, "my identity")) {
			free_auth_chain(auth_chain, chain_len);
			return STF_INTERNAL_ERROR;
		}

		close_output_pbs(&r_id_pbs);
	}

	/* CERT out */
	if (send_cert) {
		pb_stream cert_pbs;
		struct isakmp_cert cert_hd = {
			.isacert_type = mycert.ty
		};
		libreswan_log("I am sending my certificate");
		if (!out_struct(&cert_hd,
				&isakmp_ipsec_certificate_desc,
				&rbody,
				&cert_pbs) ||
		    !pbs_out_hunk(get_dercert_from_nss_cert(mycert.u.nss_cert),
								&cert_pbs, "CERT")) {
			free_auth_chain(auth_chain, chain_len);
			return STF_INTERNAL_ERROR;
		}
		close_output_pbs(&cert_pbs);
	}

	free_auth_chain(auth_chain, chain_len);

	/***** obligation to free_auth_chain has been discharged *****/

	/* CERTREQ out */
	if (send_cr) {
		libreswan_log("I am sending a certificate request");
		if (!ikev1_build_and_ship_CR(mycert.ty, c->spd.that.ca, &rbody))
			return STF_INTERNAL_ERROR;
	}

	update_iv(st);

	/* HASH_R or SIG_R out */
	{
		struct crypt_mac hash = main_mode_hash(st, SA_RESPONDER, &r_id_pbs);

		if (auth_payload == ISAKMP_NEXT_HASH) {
			/* HASH_R out */
			if (!ikev1_out_generic_raw(&isakmp_hash_desc,
					     &rbody,
					     hash.ptr,
					     hash.len,
					     "HASH_R"))
				return STF_INTERNAL_ERROR;
		} else {
			/* SIG_R out */
			struct hash_signature sig = v1_sign_hash_RSA(c, &hash,
								     st->st_logger);
			if (sig.len == 0) {
				log_state(RC_LOG_SERIOUS, st,
					  "unable to locate my private key for RSA Signature");
				return STF_FAIL + AUTHENTICATION_FAILED;
			}

			if (!ikev1_out_generic_raw(&isakmp_signature_desc,
					     &rbody, sig.ptr, sig.len,
					     "SIG_R"))
				return STF_INTERNAL_ERROR;
		}
	}

	/* send Vendor IDs */
	if (!out_vid_set(&rbody, c))
		return STF_INTERNAL_ERROR;

	if (st->hidden_variables.st_nat_traversal != LEMPTY) {
		/* as Responder, send best NAT VID we received */
		if (!out_vid(&rbody, md->quirks.qnat_traversal_vid))
			return STF_INTERNAL_ERROR;

		/* send two ISAKMP_NEXT_NATD_RFC* hash payloads to support NAT */
		if (!ikev1_nat_traversal_add_natd(&rbody, md))
			return STF_INTERNAL_ERROR;
	}

	/* finish message */
	if (!ikev1_close_message(&rbody, st))
		return STF_INTERNAL_ERROR;

	return STF_OK;
}

/* STATE_AGGR_I1:
 * SMF_PSK_AUTH: HDR, SA, KE, Nr, IDir, HASH_R
 *           --> HDR*, HASH_I
 * SMF_DS_AUTH:  HDR, SA, KE, Nr, IDir, [CERT,] SIG_R
 *           --> HDR*, [CERT,] SIG_I
 */
static crypto_req_cont_func aggr_inR1_outI2_crypto_continue;	/* forward decl and type assertion */

stf_status aggr_inR1_outI2(struct state *st, struct msg_digest *md)
{
	/* With Aggressive Mode, we get an ID payload in this, the second
	 * message, so we can use it to index the preshared-secrets
	 * when the IP address would not be meaningful (i.e. Road
	 * Warrior).  So our first task is to unravel the ID payload.
	 */
	if (impair.drop_i2) {
		dbg("dropping Aggressive Mode I2 packet as per impair");
		return STF_IGNORE;
	}

	st->st_policy |= POLICY_AGGRESSIVE;	/* ??? surely this should be done elsewhere */

	if (!v1_decode_certs(md)) {
		libreswan_log("X509: CERT payload bogus or revoked");
		return false;
	}

	/*
	 * note: ikev1_decode_peer_id may change which connection is referenced by md->st->st_connection.
	 * But not in this case because we are Aggressive Mode
	 */
	if (!ikev1_decode_peer_id(md, TRUE, TRUE)) {
		id_buf buf;
		endpoint_buf b;

		loglog(RC_LOG_SERIOUS,
		       "initial Aggressive Mode packet claiming to be from %s on %s but no connection has been authorized",
		       str_id(&st->st_connection->spd.that.id, &buf),
		       str_endpoint(&md->sender, &b));
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
	if (!accept_KE(&st->st_gr, "Gr", st->st_oakley.ta_dh,
		       md->chain[ISAKMP_NEXT_KE])) {
		return STF_FAIL + INVALID_KEY_INFORMATION;
	}

	/* Ni in */
	RETURN_STF_FAILURE(accept_v1_nonce(st->st_logger, md, &st->st_nr, "Nr"));

	/* moved the following up as we need Rcookie for hash, skeyids */
	/* Reinsert the state, using the responder cookie we just received */
	rehash_state(st, &md->hdr.isa_ike_responder_spi);

	ikev1_natd_init(st, md);

	/* set up second calculation */
	start_dh_v1_secretiv(aggr_inR1_outI2_crypto_continue, "aggr outR1 DH",
			     st, SA_INITIATOR, st->st_oakley.ta_dh);
	return STF_SUSPEND;
}

static stf_status aggr_inR1_outI2_tail(struct msg_digest *md); /* forward */

static void aggr_inR1_outI2_crypto_continue(struct state *st,
					    struct msg_digest *md,
					    struct pluto_crypto_req *r)
{
	stf_status e;

	dbg("aggr inR1_outI2: calculated DH, sending I2");

	passert(st != NULL);
	passert(md != NULL);
	passert(md->st == st);

	if (!finish_dh_secretiv(st, r)) {
		e = STF_FAIL + INVALID_KEY_INFORMATION;
	} else {
		e = aggr_inR1_outI2_tail(md);
	}

	complete_v1_state_transition(md, e);
}

/* Note: this is only called once.  Not really a tail. */

static stf_status aggr_inR1_outI2_tail(struct msg_digest *md)
{
	if (!v1_decode_certs(md)) {
		libreswan_log("X509: CERT payload bogus or revoked");
		return STF_FAIL + INVALID_ID_INFORMATION;
	}
	/* HASH_R or SIG_R in */
	{
		/*
		 * Note: oakley_id_and_auth won't switch connections
		 * because we are Aggressive Mode.
		 */
		stf_status r = oakley_id_and_auth(md, TRUE, TRUE);

		if (r != STF_OK)
			return r;
	}

	struct state *const st = md->st;
	struct connection *c = st->st_connection;
	const cert_t mycert = c->spd.this.cert;

	enum next_payload_types_ikev1 auth_payload =
		st->st_oakley.auth == OAKLEY_PRESHARED_KEY ?
			ISAKMP_NEXT_HASH : ISAKMP_NEXT_SIG;

	/* decode certificate requests */
	ikev1_decode_cr(md);

	if (st->st_requested_ca != NULL)
		st->hidden_variables.st_got_certrequest = TRUE;

	/*
	 * send certificate if we have one and auth is RSA, and we were
	 * told we can send one if asked, and we were asked, or we were told
	 * to always send one.
	 */
	bool send_cert = st->st_oakley.auth == OAKLEY_RSA_SIG &&
		mycert.ty != CERT_NONE && mycert.u.nss_cert != NULL &&
		((c->spd.this.sendcert == CERT_SENDIFASKED &&
		  st->hidden_variables.st_got_certrequest) ||
		 c->spd.this.sendcert == CERT_ALWAYSSEND
		);

	bool send_authcerts = (send_cert && c->send_ca != CA_SEND_NONE);

	/*****
	 * From here on, if send_authcerts, we are obligated to:
	 * free_auth_chain(auth_chain, chain_len);
	 *****/

	chunk_t auth_chain[MAX_CA_PATH_LEN] = { { NULL, 0 } };
	int chain_len = 0;

	if (send_authcerts) {
		chain_len = get_auth_chain(auth_chain, MAX_CA_PATH_LEN,
				mycert.u.nss_cert,
				c->send_ca == CA_SEND_ALL);

		if (chain_len == 0)
			send_authcerts = FALSE;
	}

	doi_log_cert_thinking(st->st_oakley.auth,
			      mycert.ty,
			      c->spd.this.sendcert,
			      st->hidden_variables.st_got_certrequest,
			      send_cert, send_authcerts);

	/**************** build output packet: HDR, HASH_I/SIG_I **************/

	/* make sure HDR is at start of a clean buffer */
	init_out_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
		 "reply packet");
	pb_stream rbody;

	/* HDR out */
	{
		struct isakmp_hdr hdr = md->hdr;

		hdr.isa_flags = 0; /* clear reserved fields */
		hdr.isa_ike_responder_spi = st->st_ike_spis.responder;
		hdr.isa_np = ISAKMP_NEXT_NONE,	/* clear NP */
		hdr.isa_flags |= ISAKMP_FLAGS_v1_ENCRYPTION;

		if (impair.send_bogus_isakmp_flag) {
			hdr.isa_flags |= ISAKMP_FLAGS_RESERVED_BIT6;
		}

		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply_stream,
				&rbody)) {
			free_auth_chain(auth_chain, chain_len);
			return STF_INTERNAL_ERROR;
		}
	}

	/* [ CERT out ] */
	if (send_cert) {
		pb_stream cert_pbs;

		struct isakmp_cert cert_hd = {
			.isacert_type = mycert.ty,
			.isacert_reserved = 0,
			.isacert_length = 0 /* XXX unused on sending ? */
		};

		libreswan_log("I am sending my cert");

		if (!out_struct(&cert_hd,
				&isakmp_ipsec_certificate_desc,
				&rbody,
				&cert_pbs) ||
		    !pbs_out_hunk(get_dercert_from_nss_cert(mycert.u.nss_cert),
								&cert_pbs, "CERT")) {
			free_auth_chain(auth_chain, chain_len);
			return STF_INTERNAL_ERROR;
		}

		close_output_pbs(&cert_pbs);
	}

	free_auth_chain(auth_chain, chain_len);

	/***** obligation to free_auth_chain has been discharged *****/

	/* [ NAT-D, NAT-D ] */
	/* ??? why does this come before AUTH payload? */
	if (st->hidden_variables.st_nat_traversal != LEMPTY) {
		/* send two ISAKMP_NEXT_NATD_RFC* hash payloads to support NAT */
		if (!ikev1_nat_traversal_add_natd(&rbody, md)) {
			return STF_INTERNAL_ERROR;
		}
	}

	/* HASH_I or SIG_I out */
	{
		dbg("next payload chain: creating a fake payload for hashing identity");

		/* first build an ID payload as a raw material */
		shunk_t id_b;
		struct isakmp_ipsec_id id_hd = build_v1_id_payload(&c->spd.this, &id_b);

		pb_stream id_pbs;
		u_char idbuf[1024]; /* fits all possible identity payloads? */
		init_out_pbs(&id_pbs, idbuf, sizeof(idbuf), "identity payload");
		pb_stream r_id_pbs;
		if (!out_struct(&id_hd, &isakmp_ipsec_identification_desc,
				&id_pbs, &r_id_pbs) ||
		    !pbs_out_hunk(id_b, &r_id_pbs, "my identity")) {
			return STF_INTERNAL_ERROR;
		}
		close_output_pbs(&r_id_pbs);
		close_output_pbs(&id_pbs);

		struct crypt_mac hash = main_mode_hash(st, SA_INITIATOR, &id_pbs);

		if (auth_payload == ISAKMP_NEXT_HASH) {
			/* HASH_I out */
			if (!ikev1_out_generic_raw(&isakmp_hash_desc, &rbody,
					     hash.ptr, hash.len, "HASH_I"))
				return STF_INTERNAL_ERROR;
		} else {
			/* SIG_I out */
			struct hash_signature sig = v1_sign_hash_RSA(st->st_connection, &hash,
								     st->st_logger);
			if (sig.len == 0) {
				log_state(RC_LOG_SERIOUS, st,
					  "unable to locate my private key for RSA Signature");
				return STF_FAIL + AUTHENTICATION_FAILED;
			}

			if (!ikev1_out_generic_raw(&isakmp_signature_desc,
					     &rbody, sig.ptr, sig.len,
					     "SIG_I"))
				return STF_INTERNAL_ERROR;
		}
	}

	/* RFC2408 says we must encrypt at this point */

	/* st_new_iv was computed by generate_skeyids_iv (??? DOESN'T EXIST) */
	if (!ikev1_encrypt_message(&rbody, st))
		return STF_INTERNAL_ERROR; /* ??? we may be partly committed */

	/* It seems as per Cisco implementation, XAUTH and MODECFG
	 * are not supposed to be performed again during rekey
	 */
	if (c->newest_isakmp_sa != SOS_NOBODY && c->spd.this.xauth_client &&
	    c->remotepeertype == CISCO) {
		dbg("skipping XAUTH for rekey for Cisco Peer compatibility.");
		st->hidden_variables.st_xauth_client_done = TRUE;
		st->st_oakley.doing_xauth = FALSE;

		if (c->spd.this.modecfg_client) {
			dbg("skipping XAUTH for rekey for Cisco Peer compatibility.");
			st->hidden_variables.st_modecfg_vars_set = TRUE;
			st->hidden_variables.st_modecfg_started = TRUE;
		}
	}

	if (c->newest_isakmp_sa != SOS_NOBODY && c->spd.this.xauth_client &&
	    c->remotepeertype == CISCO) {
		dbg("this seems to be rekey, and XAUTH is not supposed to be done again");
		st->hidden_variables.st_xauth_client_done = TRUE;
		st->st_oakley.doing_xauth = FALSE;

		if (c->spd.this.modecfg_client) {
			dbg("this seems to be rekey, and MODECFG is not supposed to be done again");
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
	dbg("phase 1 complete");

	IKE_SA_established(pexpect_ike_sa(st));
#ifdef USE_XFRM_INTERFACE
	if (c->xfrmi != NULL && c->xfrmi->if_id != yn_no)
		if (add_xfrmi(c, st->st_logger))
			return STF_FATAL;
#endif

	linux_audit_conn(st, LAK_PARENT_START);
	return STF_OK;
}

/* STATE_AGGR_R1:
 * SMF_PSK_AUTH: HDR*, HASH_I --> done
 * SMF_DS_AUTH:  HDR*, SIG_I  --> done
 */

stf_status aggr_inI2(struct state *st, struct msg_digest *md)
{
	struct connection *c = st->st_connection;
	u_char idbuf[1024];	/* ??? enough room for reconstructed peer ID payload? */
	struct payload_digest id_pd;

	ikev1_natd_init(st, md);

	/* Reconstruct the peer ID so the peer hash can be authenticated */
	{
		dbg("next payload chain: creating a fake payload for hashing identity");

		pb_stream pbs;
		pb_stream id_pbs;

		shunk_t id_b;
		struct isakmp_ipsec_id id_hd = build_v1_id_payload(&c->spd.that, &id_b);

		init_out_pbs(&pbs, idbuf, sizeof(idbuf), "identity payload");

		/* interop ID for SoftRemote & maybe others ? */
		id_hd.isaiid_protoid = st->st_peeridentity_protocol;
		id_hd.isaiid_port = htons(st->st_peeridentity_port);

		if (!out_struct(&id_hd, &isakmp_ipsec_identification_desc,
				&pbs, &id_pbs) ||
		    !pbs_out_hunk(id_b, &id_pbs, "my identity"))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&id_pbs);

		/* rewind id_pbs and read what we wrote */
		id_pbs.roof = pbs.cur;
		id_pbs.cur = pbs.start;
		if (!in_struct(&id_pd.payload, &isakmp_identification_desc, &id_pbs,
			  &id_pd.pbs))
			return STF_FAIL + PAYLOAD_MALFORMED;
	}

	/*
	 * ??? this looks like a really rude assignment
	 *
	 * - we are rewriting the input.  Sheesh!
	 * - at least we undo the damage after calling oakley_id_and_auth.
	 */
	struct payload_digest *save_id = md->chain[ISAKMP_NEXT_ID];
	md->chain[ISAKMP_NEXT_ID] = &id_pd;

	if (!v1_decode_certs(md)) {
		libreswan_log("X509: CERT payload bogus or revoked");
		return STF_FAIL + INVALID_ID_INFORMATION;
	}

	/* HASH_I or SIG_I in */
	{
		/*
		 * Note: oakley_id_and_auth won't switch connections
		 * because we are Aggressive Mode.
		 */
		stf_status r = oakley_id_and_auth(md, FALSE, TRUE);
		if (r != STF_OK)
			return r;
	}

	/* And reset the md to not leave stale pointers to our private id payload */
	md->chain[ISAKMP_NEXT_ID] = save_id;

	/**************** done input ****************/

	/* It seems as per Cisco implementation, XAUTH and MODECFG
	 * are not supposed to be performed again during rekey
	 */
	if (c->newest_isakmp_sa != SOS_NOBODY &&
	    st->st_connection->spd.this.xauth_client &&
	    st->st_connection->remotepeertype == CISCO) {
		dbg("skipping XAUTH for rekey for Cisco Peer compatibility.");
		st->hidden_variables.st_xauth_client_done = TRUE;
		st->st_oakley.doing_xauth = FALSE;

		if (st->st_connection->spd.this.modecfg_client) {
			dbg("skipping ModeCFG for rekey for Cisco Peer compatibility.");
			st->hidden_variables.st_modecfg_vars_set = TRUE;
			st->hidden_variables.st_modecfg_started = TRUE;
		}
	}

	if (c->newest_isakmp_sa != SOS_NOBODY &&
	    st->st_connection->spd.this.xauth_client &&
	    st->st_connection->remotepeertype == CISCO) {
		dbg("this seems to be rekey, and XAUTH is not supposed to be done again");
		st->hidden_variables.st_xauth_client_done = TRUE;
		st->st_oakley.doing_xauth = FALSE;

		if (st->st_connection->spd.this.modecfg_client) {
			dbg("this seems to be rekey, and MODECFG is not supposed to be done again");
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
	dbg("phase 1 complete");

	IKE_SA_established(pexpect_ike_sa(st));
#ifdef USE_XFRM_INTERFACE
	if (c->xfrmi != NULL && c->xfrmi->if_id != yn_no)
		if (add_xfrmi(c, st->st_logger))
			return STF_FATAL;
#endif

	linux_audit_conn(st, LAK_PARENT_START);
	return STF_OK;
}

/*
 * Initiate an Oakley Aggressive Mode exchange.
 * --> HDR, SA, KE, Ni, IDii
 */

static crypto_req_cont_func aggr_outI1_continue;	/* type assertion */

/* No initial state for aggr_outI1:
 * SMF_DS_AUTH (RFC 2409 5.1) and SMF_PSK_AUTH (RFC 2409 5.4):
 * -->HDR, SA, KE, Ni, IDii
 *
 * Not implemented:
 * RFC 2409 5.2: --> HDR, SA, [ HASH(1),] KE, <IDii_b>Pubkey_r, <Ni_b>Pubkey_r
 * RFC 2409 5.3: --> HDR, SA, [ HASH(1),] <Ni_b>Pubkey_r, <KE_b>Ke_i, <IDii_b>Ke_i [, <Cert-I_b>Ke_i ]
 */
/* extern initiator_function aggr_outI1; */	/* type assertion */
void aggr_outI1(struct fd *whack_sock,
		struct connection *c,
		struct state *predecessor,
		lset_t policy,
		unsigned long try,
		const threadtime_t *inception,
		struct xfrm_user_sec_ctx_ike *uctx)
{
	/* set up new state */
	struct ike_sa *ike = new_v1_istate(whack_sock);
	struct state *st = &ike->sa;
	statetime_t start = statetime_backdate(st, inception);
	change_state(st, STATE_AGGR_I1);
	initialize_new_state(st, c, policy, try);
	push_cur_state(st);

	if (LIN(POLICY_PSK, c->policy) && LIN(POLICY_AGGRESSIVE, c->policy)) {
		log_state(RC_LOG_SERIOUS, st,
			  "IKEv1 Aggressive Mode with PSK is vulnerable to dictionary attacks and is cracked on large scale by TLA's");
	}

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
		return;
	}

	if (HAS_IPSEC_POLICY(policy))
		add_pending(whack_sock, ike, c, policy, 1,
			    predecessor == NULL ? SOS_NOBODY : predecessor->st_serialno,
			    uctx, true/*part of initiate*/);

	if (predecessor == NULL) {
		libreswan_log("initiating Aggressive Mode");
	} else {
		update_pending(pexpect_ike_sa(predecessor), pexpect_ike_sa(st));
		libreswan_log(
			"initiating Aggressive Mode #%lu to replace #%lu",
			st->st_serialno, predecessor->st_serialno);
	}

	/*
	 * Calculate KE and Nonce.
	 */
	request_ke_and_nonce("aggr_outI1 KE + nonce", st,
			     st->st_oakley.ta_dh,
			     aggr_outI1_continue);
	statetime_stop(&start, "%s()", __func__);
	reset_globals();
}

static stf_status aggr_outI1_tail(struct state *st, struct pluto_crypto_req *r);

static void aggr_outI1_continue(struct state *st,
				struct msg_digest *unused_md,
				struct pluto_crypto_req *r)
{
	dbg("aggr_outI1_continue for #%lu: calculated ke+nonce, sending I1",
	    st->st_serialno);
	passert(unused_md == NULL); /* no packet */

	stf_status e = aggr_outI1_tail(st, r); /* may return FAIL */

	/*
	 * XXX: The right fix is to stop
	 * complete_v1_state_transition() assuming that there is an
	 * MD.  This hacks around it.
	 */
	struct msg_digest *fake_md = alloc_md(NULL/*iface-port*/, &unset_endpoint, HERE);
	fake_md->st = st;
	fake_md->smc = NULL;	/* ??? */
	fake_md->v1_from_state = STATE_UNDEFINED;	/* ??? */
	fake_md->fake_dne = true;

	complete_v1_state_transition(fake_md, e);
	md_delref(&fake_md, HERE);
}

static stf_status aggr_outI1_tail(struct state *st,
				  struct pluto_crypto_req *r)
{
	struct connection *c = st->st_connection;
	cert_t mycert = c->spd.this.cert;
	bool send_cr = mycert.ty != CERT_NONE && mycert.u.nss_cert != NULL &&
		!has_preloaded_public_key(st) &&
		(c->spd.this.sendcert == CERT_SENDIFASKED ||
		 c->spd.this.sendcert == CERT_ALWAYSSEND);

	dbg("aggr_outI1_tail for #%lu", st->st_serialno);

	/* make sure HDR is at start of a clean buffer */
	init_out_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
		     "reply packet");

	/* HDR out */
	pb_stream rbody;
	{
		struct isakmp_hdr hdr = {
			.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
				  ISAKMP_MINOR_VERSION,
			.isa_xchg = ISAKMP_XCHG_AGGR,
		};
		hdr.isa_ike_initiator_spi = st->st_ike_spis.initiator;
		/* R-cookie, flags and MessageID are left zero */

		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply_stream,
				&rbody)) {
			reset_cur_state();
			return STF_INTERNAL_ERROR;
		}
	}

	/* SA out */
	{
		u_char *sa_start = rbody.cur;

		if (!ikev1_out_sa(&rbody,
				  IKEv1_oakley_am_sadb(st->st_policy, c),
				  st, TRUE, TRUE)) {
			reset_cur_state();
			return STF_INTERNAL_ERROR;
		}

		/* save initiator SA for later HASH */
		passert(st->st_p1isa.ptr == NULL); /* no leak! */
		st->st_p1isa = clone_bytes_as_chunk(sa_start, rbody.cur - sa_start,
						    "sa in aggr_outI1");
	}

	/* KE out */
	if (!ikev1_ship_KE(st, r, &st->st_gi, &rbody))
		return STF_INTERNAL_ERROR;

	/* Ni out */
	if (!ikev1_ship_nonce(&st->st_ni, r, &rbody, "Ni"))
		return STF_INTERNAL_ERROR;

	/* IDii out */
	{
		shunk_t id_b;
		struct isakmp_ipsec_id id_hd = build_v1_id_payload(&c->spd.this, &id_b);

		pb_stream id_pbs;
		if (!out_struct(&id_hd, &isakmp_ipsec_identification_desc,
				&rbody, &id_pbs) ||
		    !pbs_out_hunk(id_b, &id_pbs, "my identity"))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&id_pbs);
	}

	/* CERTREQ out */
	if (send_cr) {
		libreswan_log("I am sending a certificate request");
		if (!ikev1_build_and_ship_CR(mycert.ty, c->spd.that.ca, &rbody))
			return STF_INTERNAL_ERROR;
	}

	/* send Vendor IDs */
	if (!out_vid_set(&rbody, c))
		return STF_INTERNAL_ERROR;

	/* as Initiator, spray NAT VIDs */
	if (!nat_traversal_insert_vid(&rbody, c))
		return STF_INTERNAL_ERROR;

	/* finish message */

	if (!ikev1_close_message(&rbody, st))
		return STF_INTERNAL_ERROR;

	close_output_pbs(&reply_stream);

	/* Transmit */
	record_and_send_v1_ike_msg(st, &reply_stream, "aggr_outI1");

	/* Set up a retransmission event, half a minute hence */
	delete_event(st);
	clear_retransmits(st);
	start_retransmits(st);

	loglog(RC_NEW_V1_STATE + st->st_state->kind,
	       "%s: %s", st->st_state->name, st->st_state->story);
	reset_cur_state();
	return STF_IGNORE;
}
