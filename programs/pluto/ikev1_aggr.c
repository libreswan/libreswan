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

#include "constants.h"

#include "defs.h"
#include "state.h"
#include "connections.h"        /* needs id.h */
#include "packet.h"
#include "demux.h"      /* needs packet.h */
#include "log.h"
#include "ike_spi.h"
#include "ikev1_spdb.h"
#include "ipsec_doi.h"  /* needs demux.h and state.h */
#include "ikev1_send.h"
#include "ikev1.h"
#include "nat_traversal.h"
#include "ikev1_nat.h"
#include "pluto_x509.h"
#include "fd.h"
#include "ikev1_message.h"
#include "pending.h"
#include "iface.h"
#include "secrets.h"
#include "crypt_ke.h"
#include "crypt_dh.h"
#ifdef USE_XFRM_INTERFACE
# include "kernel_xfrm_interface.h"
#endif
#include "unpack.h"
#include "ikev1_host_pair.h"
#include "ikev1_peer_id.h"
#include "peer_id.h"	/* for update_peer_id_cert() */
#include "ikev1_vendorid.h"
#include "ikev1_cert.h"

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

/*
 * continuation from second calculation (the DH one)
 */

static dh_shared_secret_cb aggr_inI1_outR1_continue2;	/* type assertion */

/*
 * for aggressive mode, this is sub-optimal, since we should have
 * had the crypto helper actually do everything, but we need to do
 * some additional work to set that all up, so this is fine for now.
 */

static ke_and_nonce_cb aggr_inI1_outR1_continue1;	/* type assertion */

static stf_status aggr_inI1_outR1_continue1(struct state *st,
					    struct msg_digest *md UNUSED,
					    struct dh_local_secret *local_secret,
					    chunk_t *nonce)
{
	dbg("%s: calculated ke+nonce, calculating DH", __func__);

	/* unpack first calculation */
	unpack_KE_from_helper(st, local_secret, &st->st_gr);

	/* unpack nonce too */
	unpack_nonce(&st->st_nr, nonce);

	/* set up second calculation */
	submit_dh_shared_secret(st, st, st->st_gi/*initiator's KE*/,
				aggr_inI1_outR1_continue2, HERE);

	/*
	 * XXX: Since more crypto has been requested, MD needs to be re
	 * suspended.  If the original crypto request did everything
	 * this wouldn't be needed.
	 */
	return STF_SUSPEND;
}

/* STATE_AGGR_R0:
 * SMF_PSK_AUTH: HDR, SA, KE, Ni, IDii
 *           --> HDR, SA, KE, Nr, IDir, HASH_R
 * SMF_DS_AUTH:  HDR, SA, KE, Nr, IDii
 *           --> HDR, SA, KE, Nr, IDir, [CERT,] SIG_R
 */
stf_status aggr_inI1_outR1(struct state *null_st UNUSED,
			   struct msg_digest *md)
{
	diag_t d;
	/*
	 * With Aggressive Mode, we get an ID payload in this, the
	 * first message, so we can use it to index the
	 * preshared-secrets when the IP address would not be
	 * meaningful (i.e. Road Warrior).  That's the one
	 * justification for Aggressive Mode.
	 */
	struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_SA];

	if (drop_new_exchanges()) {
		return STF_IGNORE;
	}

	bool xauth = false;
	struct authby authby = {0};
	d = preparse_isakmp_sa_body(sa_pd->pbs, &authby, &xauth);
	if (d != NULL) {
		llog_diag(RC_LOG_SERIOUS, md->logger, &d,
			  "initial Aggressive Mode message has corrupt SA payload: ");
		return STF_IGNORE;
	}

	const struct payload_digest *const id_pld = md->chain[ISAKMP_NEXT_ID];
	const struct isakmp_id *const id = &id_pld->payload.id;
	struct id peer_id;
	struct id *ppeer_id = NULL;

	d = unpack_peer_id(id->isaid_idtype, &peer_id, &id_pld->pbs);
	if (d != NULL) {
		dbg("IKEv1 aggressive mode peer ID unpacking failed - ignored peer ID to find connection");
	} else {
		ppeer_id = &peer_id;
	}

	struct connection *c = find_v1_aggr_mode_connection(md, authby, xauth, ppeer_id); /* must delref */
	if (c == NULL) {
		/* XXX: already logged */
		/* XXX notification is in order! */
		return STF_IGNORE;
	}

	/* Set up state */
	struct ike_sa *ike = new_v1_rstate(c, md);

	/* delref stack connection pointer */
	connection_delref(&c, md->logger);
	c = ike->sa.st_connection;

	md->v1_st = &ike->sa;  /* (caller will reset cur_state) */
	change_v1_state(&ike->sa, STATE_AGGR_R0);

	/*
	 * Warn when peer is expected to use especially dangerous
	 * Aggressive Mode and PSK (IKEv1 authentication is symmetric
	 * so also applies to this end).
	 */
	if (c->remote->host.config->auth == AUTH_PSK &&
	    c->config->aggressive) {
		llog_sa(RC_LOG_SERIOUS, ike,
			"IKEv1 Aggressive Mode with PSK is vulnerable to dictionary attacks and is cracked on large scale by TLA's");
	}

	/*
	 * ??? not sure what's needed here.
	 *
	 * Use remote's allowed authentication; since IKEv1 is
	 * symmetric this also applies to us.  Strangely this
	 * preference for PSK over RSASIG is the reverse of
	 * auth_from_authby() which is used to set host.auth.
	 */
	ike->sa.st_oakley.auth = (c->remote->host.config->auth == AUTH_PSK ? OAKLEY_PRESHARED_KEY :
				  c->remote->host.config->auth == AUTH_RSASIG ? OAKLEY_RSA_SIG :
				  0);	/* we don't really know */

	if (!v1_decode_certs(md)) {
		llog_sa(RC_LOG, ike, "X509: CERT payload bogus or revoked");
		/* XXX notification is in order! */
		return STF_FAIL_v1N + v1N_INVALID_ID_INFORMATION;
	}

	/*
	 * Note: Aggressive mode so this cannot change the connection.
	 */

	if (!ikev1_decode_peer_id_aggr_mode_responder(&ike->sa, md)) {
		id_buf buf;
		endpoint_buf b;
		llog_sa(RC_LOG_SERIOUS, ike,
			"initial Aggressive Mode packet claiming to be from %s on %s but no matching connection has been authorized",
			str_id(&ike->sa.st_connection->remote->host.id, &buf),
			str_endpoint(&md->sender, &b));
		/* XXX notification is in order! */
		return STF_FAIL_v1N + v1N_INVALID_ID_INFORMATION;
	}

	passert(c == ike->sa.st_connection); /* no switch */

	ike->sa.st_policy = LEMPTY; /* only as accurate as connection */

	binlog_refresh_state(&ike->sa);

	{
		address_buf b;
		connection_buf cib;
		llog_sa(RC_LOG, ike,
			"responding to Aggressive Mode, state #%lu, connection "PRI_CONNECTION" from %s",
			ike->sa.st_serialno,
			pri_connection(c, &cib),
			str_address_sensitive(&c->remote->host.addr, &b));
	}

	merge_quirks(&ike->sa, md);

	set_nat_traversal(&ike->sa, md);

	/* save initiator SA for HASH */

	/*
	 * ??? how would st->st_p1isa.ptr != NULL?
	 * This routine creates *st itself so how would this field
	 * be already filled-in.
	 */
	pexpect(ike->sa.st_p1isa.ptr == NULL);
	ike->sa.st_p1isa = clone_pbs_in_all(&sa_pd->pbs, "sa in aggr_inI1_outR1()");

	/*
	 * parse_isakmp_sa picks the right group, which we need to know
	 * before we do any calculations. We will call it again to have it
	 * emit the winning SA into the output.
	 */
	/* SA body in */
	{
		struct pbs_in sabs = sa_pd->pbs;

		RETURN_STF_FAIL_v1NURE(parse_isakmp_sa_body(&sabs,
							    &sa_pd->payload.sa,
							    NULL, false, &ike->sa));
	}

	/* KE in */
	if (!unpack_KE(&ike->sa.st_gi, "Gi", ike->sa.st_oakley.ta_dh,
		       md->chain[ISAKMP_NEXT_KE], ike->sa.logger)) {
		return STF_FAIL_v1N + v1N_INVALID_KEY_INFORMATION;
	}

	/* Ni in */
	RETURN_STF_FAIL_v1NURE(accept_v1_nonce(ike->sa.logger, md, &ike->sa.st_ni, "Ni"));

	/* calculate KE and Nonce */
	submit_ke_and_nonce(&ike->sa, ike->sa.st_oakley.ta_dh,
			    aggr_inI1_outR1_continue1,
			    /*detach_whack*/false, HERE);
	return STF_SUSPEND;
}

static stf_status aggr_inI1_outR1_continue2(struct state *st,
					    struct msg_digest *md)
{
	dbg("aggr_inI1_outR1_continue2 for #%lu: calculated ke+nonce+DH, sending R1",
	    st->st_serialno);
	passert(md != NULL);

	const struct connection *c = st->st_connection;
	struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_SA];
	const struct cert *mycert = c->local->host.config->cert.nss_cert != NULL ? &c->local->host.config->cert : NULL;

	/* parse_isakmp_sa also spits out a winning SA into our reply,
	 * so we have to build our reply_stream and emit HDR before calling it.
	 */

	if (st->st_dh_shared_secret == NULL) {
		return STF_FAIL_v1N + v1N_INVALID_KEY_INFORMATION;
	}
	calc_v1_skeyid_and_iv(st);

	/* decode certificate requests */
	decode_v1_certificate_requests(st, md);
	bool cert_requested = (st->st_v1_requested_ca != NULL);

	/*
	 * send certificate if we have one and auth is RSA, and we were
	 * told we can send one if asked, and we were asked, or we were told
	 * to always send one.
	 */
	bool send_cert = (st->st_oakley.auth == OAKLEY_RSA_SIG && mycert != NULL &&
			  ((c->local->host.config->sendcert == CERT_SENDIFASKED && cert_requested) ||
			   (c->local->host.config->sendcert == CERT_ALWAYSSEND)));

	bool send_authcerts = (send_cert && c->config->send_ca != CA_SEND_NONE);

	/*****
	 * From here on, if send_authcerts, we are obligated to:
	 * free_auth_chain(auth_chain, chain_len);
	 *****/

	chunk_t auth_chain[MAX_CA_PATH_LEN] = { { NULL, 0 } };
	int chain_len = 0;

	if (send_authcerts) {
		chain_len = get_auth_chain(auth_chain, MAX_CA_PATH_LEN, mycert,
					   c->config->send_ca == CA_SEND_ALL);

		if (chain_len == 0)
			send_authcerts = false;
	}

	doi_log_cert_thinking(st->st_oakley.auth, cert_ike_type(mycert),
			      c->local->host.config->sendcert, cert_requested,
			      send_cert, send_authcerts);

	/* send certificate request, if we don't have a preloaded RSA public key */
	bool send_cr = send_cert && !remote_has_preloaded_pubkey(st);

	dbg(" I am %ssending a certificate request",
	    send_cr ? "" : "not ");

	/* done parsing; initialize crypto */

	reply_stream = open_pbs_out("reply packet", reply_buffer, sizeof(reply_buffer), st->logger);

	/* HDR out */
	struct pbs_out rbody;

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

		struct pbs_out r_sa_pbs;

		if (!out_struct(&r_sa, &isakmp_sa_desc, &rbody,
				&r_sa_pbs)) {
			free_auth_chain(auth_chain, chain_len);
			return STF_INTERNAL_ERROR;
		}

		/* SA body in and out */
		v1_notification_t rn = parse_isakmp_sa_body(&sa_pd->pbs,
							    &sa_pd->payload.sa,
							    &r_sa_pbs, false, st);
		if (rn != v1N_NOTHING_WRONG) {
			free_auth_chain(auth_chain, chain_len);
			return STF_FAIL_v1N + rn;
		}
	}

	/* don't know until after SA body has been parsed */
	enum next_payload_types_ikev1 auth_payload =
		st->st_oakley.auth == OAKLEY_PRESHARED_KEY ?
		       ISAKMP_NEXT_HASH : ISAKMP_NEXT_SIG;

	/************** build rest of output: KE, Nr, IDir, HASH_R/SIG_R ********/

	/* KE */
	if (!ikev1_justship_KE(st->logger, &st->st_gr, &rbody)) {
		free_auth_chain(auth_chain, chain_len);
		return STF_INTERNAL_ERROR;
	}

	/* Nr */
	if (!ikev1_justship_nonce(&st->st_nr, &rbody, "Nr")) {
		free_auth_chain(auth_chain, chain_len);
		return STF_INTERNAL_ERROR;
	}

	/* IDir out */

	struct pbs_out r_id_pbs; /* ID Payload; used later for hash calculation; XXX: use ID_B instead? */

	{
		shunk_t id_b;
		struct isakmp_ipsec_id id_hd = build_v1_id_payload(&c->local->host, &id_b);
		if (!out_struct(&id_hd, &isakmp_ipsec_identification_desc,
				&rbody, &r_id_pbs) ||
		    !out_hunk(id_b, &r_id_pbs, "my identity")) {
			free_auth_chain(auth_chain, chain_len);
			return STF_INTERNAL_ERROR;
		}

		close_output_pbs(&r_id_pbs);
	}

	/* CERT out */
	if (send_cert) {
		struct pbs_out cert_pbs;
		struct isakmp_cert cert_hd = {
			.isacert_type = cert_ike_type(mycert),
		};
		log_state(RC_LOG, st, "I am sending my certificate");
		if (!out_struct(&cert_hd,
				&isakmp_ipsec_certificate_desc,
				&rbody,
				&cert_pbs) ||
		    !out_hunk(cert_der(mycert), &cert_pbs, "CERT")) {
			free_auth_chain(auth_chain, chain_len);
			return STF_INTERNAL_ERROR;
		}
		close_output_pbs(&cert_pbs);
	}

	free_auth_chain(auth_chain, chain_len);

	/***** obligation to free_auth_chain has been discharged *****/

	/* CERTREQ out */
	if (send_cr) {
		log_state(RC_LOG, st, "I am sending a certificate request");
		if (!ikev1_build_and_ship_CR(cert_ike_type(mycert), c->remote->host.config->ca, &rbody))
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
								     st->logger);
			if (sig.len == 0) {
				/* already logged */
				return STF_FAIL_v1N + v1N_AUTHENTICATION_FAILED;
			}

			if (!ikev1_out_generic_raw(&isakmp_signature_desc,
					     &rbody, sig.ptr, sig.len,
					     "SIG_R"))
				return STF_INTERNAL_ERROR;
		}
	}

	/* send Vendor IDs */
	if (!out_v1VID_set(&rbody, c))
		return STF_INTERNAL_ERROR;

	if (st->hidden_variables.st_nat_traversal != LEMPTY) {
		/* as Responder, send best NAT VID we received */
		if (!out_v1VID(&rbody, md->quirks.qnat_traversal_vid))
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
static dh_shared_secret_cb aggr_inR1_outI2_crypto_continue;	/* forward decl and type assertion */

stf_status aggr_inR1_outI2(struct state *st, struct msg_digest *md)
{
	struct ike_sa *ike = pexpect_ike_sa(st);
	/*
	 * With Aggressive Mode, we get an ID payload in this, the
	 * second message (first response), so we can use it to index
	 * the preshared-secrets when the IP address would not be
	 * meaningful (i.e. Road Warrior).  So our first task is to
	 * unravel the ID payload.
	 */
	if (impair.drop_i2) {
		dbg("dropping Aggressive Mode I2 packet as per impair");
		return STF_IGNORE;
	}

	if (!v1_decode_certs(md)) {
		log_state(RC_LOG, st, "X509: CERT payload bogus or revoked");
		return false;
	}

	/*
	 * Note: Initiator (and Aggressive Mode) so this cannot change
	 * the connection.
	 */

	struct connection *c = st->st_connection;
	if (!ikev1_decode_peer_id_initiator(st, md)) {
		id_buf buf;
		endpoint_buf b;
		log_state(RC_LOG_SERIOUS, st,
			  "initial Aggressive Mode packet claiming to be from %s on %s but no connection has been authorized",
			  str_id(&st->st_connection->remote->host.id, &buf),
			  str_endpoint(&md->sender, &b));
		/* XXX notification is in order! */
		return STF_FAIL_v1N + v1N_INVALID_ID_INFORMATION;
	}

	passert(c == st->st_connection); /* no switch */

	/* verify echoed SA */
	{
		struct payload_digest *const sapd = md->chain[ISAKMP_NEXT_SA];
		v1_notification_t r =
			parse_isakmp_sa_body(&sapd->pbs, &sapd->payload.sa,
					     NULL, true, st);

		if (r != v1N_NOTHING_WRONG)
			return STF_FAIL_v1N + r;
	}

	merge_quirks(st, md);

	set_nat_traversal(st, md);

	/* KE in */
	if (!unpack_KE(&st->st_gr, "Gr", st->st_oakley.ta_dh,
		       md->chain[ISAKMP_NEXT_KE], st->logger)) {
		return STF_FAIL_v1N + v1N_INVALID_KEY_INFORMATION;
	}

	/* Ni in */
	RETURN_STF_FAIL_v1NURE(accept_v1_nonce(st->logger, md, &st->st_nr, "Nr"));

	/*
	 * Moved the following up as we need Rcookie for hash,
	 * skeyids.
	 *
	 * Reinsert the state, using the responder cookie we just
	 * received.
	 */
	update_st_ike_spis_responder(ike, &md->hdr.isa_ike_responder_spi);

	ikev1_natd_init(st, md);

	/* set up second calculation */
	submit_dh_shared_secret(st, st, st->st_gr/*initiator needs responder's KE*/,
				aggr_inR1_outI2_crypto_continue, HERE);
	return STF_SUSPEND;
}

static stf_status aggr_inR1_outI2_crypto_continue(struct state *st,
						  struct msg_digest *md)
{
	dbg("aggr inR1_outI2: calculated DH, sending I2");

	struct connection *c = st->st_connection;

	passert(st != NULL);
	passert(md != NULL);
	passert(md->v1_st == st);

	if (st->st_dh_shared_secret == NULL) {
		return STF_FAIL_v1N + v1N_INVALID_KEY_INFORMATION;
	}
	calc_v1_skeyid_and_iv(st);

	/* HASH_R or SIG_R in */

	stf_status r = oakley_auth(md, true);
	if (r != STF_OK) {
		return r;
	}

	const struct cert *mycert = c->local->host.config->cert.nss_cert != NULL ? &c->local->host.config->cert : NULL;

	enum next_payload_types_ikev1 auth_payload =
		st->st_oakley.auth == OAKLEY_PRESHARED_KEY ?
			ISAKMP_NEXT_HASH : ISAKMP_NEXT_SIG;

	/* decode certificate requests */
	decode_v1_certificate_requests(st, md);
	bool cert_requested = (st->st_v1_requested_ca != NULL);

	/*
	 * send certificate if we have one and auth is RSA, and we were
	 * told we can send one if asked, and we were asked, or we were told
	 * to always send one.
	 */
	bool send_cert = (st->st_oakley.auth == OAKLEY_RSA_SIG && mycert != NULL &&
			  ((c->local->host.config->sendcert == CERT_SENDIFASKED && cert_requested) ||
			   (c->local->host.config->sendcert == CERT_ALWAYSSEND)));

	bool send_authcerts = (send_cert && c->config->send_ca != CA_SEND_NONE);

	/*****
	 * From here on, if send_authcerts, we are obligated to:
	 * free_auth_chain(auth_chain, chain_len);
	 *****/

	chunk_t auth_chain[MAX_CA_PATH_LEN] = { { NULL, 0 } };
	int chain_len = 0;

	if (send_authcerts) {
		chain_len = get_auth_chain(auth_chain, MAX_CA_PATH_LEN, mycert,
					   c->config->send_ca == CA_SEND_ALL);

		if (chain_len == 0)
			send_authcerts = false;
	}

	doi_log_cert_thinking(st->st_oakley.auth, cert_ike_type(mycert),
			      c->local->host.config->sendcert, cert_requested,
			      send_cert, send_authcerts);

	/**************** build output packet: HDR, HASH_I/SIG_I **************/

	/* make sure HDR is at start of a clean buffer */
	reply_stream = open_pbs_out("reply packet", reply_buffer, sizeof(reply_buffer), st->logger);
	struct pbs_out rbody;

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
		struct pbs_out cert_pbs;

		struct isakmp_cert cert_hd = {
			.isacert_type = cert_ike_type(mycert),
			.isacert_reserved = 0,
			.isacert_length = 0 /* XXX unused on sending ? */
		};

		log_state(RC_LOG, st, "I am sending my cert");

		if (!out_struct(&cert_hd,
				&isakmp_ipsec_certificate_desc,
				&rbody,
				&cert_pbs) ||
		    !out_hunk(cert_der(mycert), &cert_pbs, "CERT")) {
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
		struct isakmp_ipsec_id id_hd = build_v1_id_payload(&c->local->host, &id_b);

		uint8_t idbuf[1024]; /* fits all possible identity payloads? */
		struct pbs_out id_pbs = open_pbs_out("identity payload", idbuf, sizeof(idbuf), st->logger);
		struct pbs_out r_id_pbs;
		if (!out_struct(&id_hd, &isakmp_ipsec_identification_desc,
				&id_pbs, &r_id_pbs) ||
		    !out_hunk(id_b, &r_id_pbs, "my identity")) {
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
								     st->logger);
			if (sig.len == 0) {
				/* already logged */
				return STF_FAIL_v1N + v1N_AUTHENTICATION_FAILED;
			}

			if (!ikev1_out_generic_raw(&isakmp_signature_desc,
					     &rbody, sig.ptr, sig.len,
					     "SIG_I"))
				return STF_INTERNAL_ERROR;
		}
	}

	/* RFC2408 says we must encrypt at this point */

	/* st_new_iv was computed by generate_skeyids_iv (??? DOESN'T EXIST) */
	if (!ikev1_close_and_encrypt_message(&rbody, st))
		return STF_INTERNAL_ERROR; /* ??? we may be partly committed */

	/* It seems as per Cisco implementation, XAUTH and MODECFG
	 * are not supposed to be performed again during rekey
	 */
	if (c->established_ike_sa != SOS_NOBODY && c->local->host.config->xauth.client &&
	    c->config->remote_peer_cisco) {
		dbg("skipping XAUTH for rekey for Cisco Peer compatibility.");
		st->hidden_variables.st_xauth_client_done = true;
		st->st_oakley.doing_xauth = false;

		if (c->local->host.config->modecfg.client) {
			dbg("skipping XAUTH for rekey for Cisco Peer compatibility.");
			st->hidden_variables.st_modecfg_vars_set = true;
			st->hidden_variables.st_modecfg_started = true;
		}
	}

	if (c->established_ike_sa != SOS_NOBODY && c->local->host.config->xauth.client &&
	    c->config->remote_peer_cisco) {
		dbg("this seems to be rekey, and XAUTH is not supposed to be done again");
		st->hidden_variables.st_xauth_client_done = true;
		st->st_oakley.doing_xauth = false;

		if (c->local->host.config->modecfg.client) {
			dbg("this seems to be rekey, and MODECFG is not supposed to be done again");
			st->hidden_variables.st_modecfg_vars_set = true;
			st->hidden_variables.st_modecfg_started = true;
		}
	}

	/* save last IV from phase 1 so it can be restored later so anything
	 * between the end of phase 1 and the start of phase 2 i.e. mode config
	 * payloads etc. will not lose our IV
	 */
	set_ph1_iv_from_new(st);
	dbg("phase 1 complete");

#ifdef USE_XFRM_INTERFACE
	if (c->xfrmi != NULL && c->xfrmi->if_id != 0)
		if (!add_xfrm_interface(c, st->logger))
			return STF_FATAL;
#endif
	ISAKMP_SA_established(pexpect_ike_sa(st));
	return STF_OK;
}

/* STATE_AGGR_R1:
 * SMF_PSK_AUTH: HDR*, HASH_I --> done
 * SMF_DS_AUTH:  HDR*, SIG_I  --> done
 */

stf_status aggr_inI2(struct state *st, struct msg_digest *md)
{
	struct connection *c = st->st_connection;
	struct payload_digest id_pd;

	ikev1_natd_init(st, md);

	/* Reconstruct the peer ID so the peer hash can be authenticated */
	{
		dbg("next payload chain: creating a fake payload for hashing identity");

		struct pbs_out id_pbs;

		shunk_t id_b;
		struct isakmp_ipsec_id id_hd = build_v1_id_payload(&c->remote->host, &id_b);

		uint8_t idbuf[1024];	/* ??? enough room for reconstructed peer ID payload? */
		struct pbs_out pbs = open_pbs_out("identity payload", idbuf, sizeof(idbuf), st->logger);

		/* interop ID for SoftRemote & maybe others ? */
		id_hd.isaiid_protoid = st->st_peeridentity_protocol;
		id_hd.isaiid_port = htons(st->st_peeridentity_port);

		if (!out_struct(&id_hd, &isakmp_ipsec_identification_desc,
				&pbs, &id_pbs) ||
		    !out_hunk(id_b, &id_pbs, "my identity"))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&id_pbs);

		/* rewind id_pbs and read what we wrote */
		id_pbs.roof = pbs.cur;
		id_pbs.cur = pbs.start;
		diag_t d = pbs_in_struct(&id_pbs, &isakmp_identification_desc,
					 &id_pd.payload, sizeof(id_pd.payload), &id_pd.pbs);
		if (d != NULL) {
			llog_diag(RC_LOG, st->logger, &d, "%s", "");
			return STF_FAIL_v1N + v1N_PAYLOAD_MALFORMED;
		}
	}

	/*
	 * ??? this looks like a really rude assignment
	 *
	 * - we are rewriting the input.  Sheesh!
	 * - at least we undo the damage after calling oakley_auth().
	 */
	struct payload_digest *save_id = md->chain[ISAKMP_NEXT_ID];
	md->chain[ISAKMP_NEXT_ID] = &id_pd;

	/*
	 * If the first message contained verified certs then
	 * .verified!=NULL; and when .verified!=NULL the certs either
	 * passed muster or the exchange was rejected.
	 *
	 * The first message has already tried to unpack certs, hence
	 * .st_remote_certs.processed is expected to be true.
	 */

	pexpect(st->st_remote_certs.processed); /* not our first time */
	bool new_certs_to_verify = false;
	if (st->st_remote_certs.verified == NULL) {
		if (!v1_decode_certs(md)) {
			log_state(RC_LOG, st, "X509: CERT payload bogus or revoked");
			return STF_FAIL_v1N + v1N_INVALID_ID_INFORMATION;
		}
		new_certs_to_verify = (st->st_remote_certs.verified != NULL);
	}

	/*
	 * ID Payload in.
	 *
	 * Note: won't switch connections because we are in Aggressive
	 * Mode (responder).
	 */

	if (new_certs_to_verify) {
		diag_t d = update_peer_id_certs(pexpect_ike_sa(st));
		if (d != NULL) {
			llog_diag(RC_LOG_SERIOUS, st->logger, &d, "%s", "");
			return STF_FAIL_v1N + v1N_INVALID_ID_INFORMATION;
		}
	}

	passert(c == st->st_connection); /* no switch */

	/* HASH_I or SIG_I in */

	stf_status r = oakley_auth(md, false);
	if (r != STF_OK) {
		return r;
	}

	/* And reset the md to not leave stale pointers to our private id payload */
	md->chain[ISAKMP_NEXT_ID] = save_id;

	/**************** done input ****************/

	/* It seems as per Cisco implementation, XAUTH and MODECFG
	 * are not supposed to be performed again during rekey
	 */
	if (c->established_ike_sa != SOS_NOBODY &&
	    st->st_connection->local->host.config->xauth.client &&
	    st->st_connection->config->remote_peer_cisco) {
		dbg("skipping XAUTH for rekey for Cisco Peer compatibility.");
		st->hidden_variables.st_xauth_client_done = true;
		st->st_oakley.doing_xauth = false;

		if (st->st_connection->local->host.config->modecfg.client) {
			dbg("skipping ModeCFG for rekey for Cisco Peer compatibility.");
			st->hidden_variables.st_modecfg_vars_set = true;
			st->hidden_variables.st_modecfg_started = true;
		}
	}

	if (c->established_ike_sa != SOS_NOBODY &&
	    st->st_connection->local->host.config->xauth.client &&
	    st->st_connection->config->remote_peer_cisco) {
		dbg("this seems to be rekey, and XAUTH is not supposed to be done again");
		st->hidden_variables.st_xauth_client_done = true;
		st->st_oakley.doing_xauth = false;

		if (st->st_connection->local->host.config->modecfg.client) {
			dbg("this seems to be rekey, and MODECFG is not supposed to be done again");
			st->hidden_variables.st_modecfg_vars_set = true;
			st->hidden_variables.st_modecfg_started = true;
		}
	}

	update_iv(st);  /* Finalize our Phase 1 IV */

	/* save last IV from phase 1 so it can be restored later so anything
	 * between the end of phase 1 and the start of phase 2 i.e. mode config
	 * payloads etc. will not lose our IV
	 */
	set_ph1_iv_from_new(st);
	dbg("phase 1 complete");

#ifdef USE_XFRM_INTERFACE
	if (c->xfrmi != NULL && c->xfrmi->if_id != 0)
		if (!add_xfrm_interface(c, st->logger))
			return STF_FATAL;
#endif
	ISAKMP_SA_established(pexpect_ike_sa(st));
	return STF_OK;
}

/*
 * Initiate an Oakley Aggressive Mode exchange.
 * --> HDR, SA, KE, Ni, IDii
 */

static ke_and_nonce_cb aggr_outI1_continue;	/* type assertion */

/* No initial state for aggr_outI1:
 * SMF_DS_AUTH (RFC 2409 5.1) and SMF_PSK_AUTH (RFC 2409 5.4):
 * -->HDR, SA, KE, Ni, IDii
 *
 * Not implemented:
 * RFC 2409 5.2: --> HDR, SA, [ HASH(1),] KE, <IDii_b>Pubkey_r, <Ni_b>Pubkey_r
 * RFC 2409 5.3: --> HDR, SA, [ HASH(1),] <Ni_b>Pubkey_r, <KE_b>Ke_i, <IDii_b>Ke_i [, <Cert-I_b>Ke_i ]
 */

struct ike_sa *aggr_outI1(struct connection *c,
			  struct ike_sa *predecessor,
			  lset_t policy,
			  const threadtime_t *inception,
			  bool detach_whack)
{
	/* set up new state */
	struct ike_sa *ike = new_v1_istate(c, STATE_AGGR_I1);
	if (ike == NULL) {
		return NULL;
	}

	statetime_t start = statetime_backdate(&ike->sa, inception);

	if (c->local->host.config->auth == AUTH_PSK &&
	    c->config->aggressive) {
		llog_sa(RC_LOG_SERIOUS, ike,
			"IKEv1 Aggressive Mode with PSK is vulnerable to dictionary attacks and is cracked on large scale by TLA's");
	}

	if (!init_aggr_st_oakley(ike)) {
		/*
		 * This is only the case if NO IKE proposal was specified in the
		 * configuration file.  It's not the case if there were multiple
		 * configurations, even conflicting multiple DH groups.  So this
		 * should tell the user to add a proper proposal policy
		 */
		llog_sa(RC_AGGRALGO, ike,
			"no IKE proposal policy specified in config!  Cannot initiate aggressive mode.  A policy must be specified in the configuration and should contain at most one DH group (mod1024, mod1536, mod2048).  Only the first DH group will be honored.");
		return NULL;
	}

	if (policy != LEMPTY) {
		/*
		 * When replacing the IKE (ISAKMP) SA, policy=LEMPTY
		 * so that a Child SA isn't also initiated and this
		 * code is skipped.
		 */
		append_pending(ike, c, policy,
			       (predecessor == NULL ? SOS_NOBODY : predecessor->sa.st_serialno),
			       null_shunk, true /*part of initiate*/,
			       detach_whack);
	}

	if (predecessor == NULL) {
		llog_sa(RC_LOG, ike, "initiating IKEv1 Aggressive Mode connection");
	} else {
		move_pending(predecessor, ike);
		llog_sa(RC_LOG, ike,
			"initiating IKEv1 Aggressive Mode connection "PRI_SO" to replace "PRI_SO,
			pri_so(ike->sa.st_serialno),
			pri_so(predecessor->sa.st_serialno));
	}

	/*
	 * Calculate KE and Nonce.
	 */
	submit_ke_and_nonce(&ike->sa, ike->sa.st_oakley.ta_dh,
			    aggr_outI1_continue,
			    /*detach_whack*/false, HERE);
	statetime_stop(&start, "%s()", __func__);
	return ike;
}

static ke_and_nonce_cb aggr_outI1_continue_tail;

static stf_status aggr_outI1_continue(struct state *st,
				      struct msg_digest *unused_md,
				      struct dh_local_secret *local_secret,
				      chunk_t *nonce)
{
	dbg("aggr_outI1_continue for #%lu: calculated ke+nonce, sending I1",
	    st->st_serialno);
	passert(unused_md == NULL); /* no packet */

	stf_status e = aggr_outI1_continue_tail(st, unused_md,
						local_secret, nonce); /* may return FAIL */

	pexpect(e == STF_IGNORE);	/* ??? what would be better? */
	complete_v1_state_transition(st, NULL, STF_IGNORE);

	return STF_SKIP_COMPLETE_STATE_TRANSITION;
}

static stf_status aggr_outI1_continue_tail(struct state *st,
					   struct msg_digest *unused_md,
					   struct dh_local_secret *local_secret,
					   chunk_t *nonce)
{
	passert(unused_md == NULL); /* no packet */
	struct connection *c = st->st_connection;
	const struct cert *mycert = c->local->host.config->cert.nss_cert != NULL ? &c->local->host.config->cert : NULL;
	bool send_cr = (mycert != NULL &&
			!remote_has_preloaded_pubkey(st) &&
			(c->local->host.config->sendcert == CERT_SENDIFASKED ||
			 c->local->host.config->sendcert == CERT_ALWAYSSEND));

	dbg("aggr_outI1_tail for #%lu", st->st_serialno);

	/* make sure HDR is at start of a clean buffer */
	reply_stream = open_pbs_out("reply packet", reply_buffer, sizeof(reply_buffer), st->logger);

	/* HDR out */
	struct pbs_out rbody;
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
			return STF_INTERNAL_ERROR;
		}
	}

	/* SA out */
	{
		uint8_t *sa_start = rbody.cur;

		if (!ikev1_out_sa(&rbody,
				  IKEv1_oakley_aggr_mode_db_sa(c),
				  st, true, true)) {
			return STF_INTERNAL_ERROR;
		}

		/* save initiator SA for later HASH */
		passert(st->st_p1isa.ptr == NULL); /* no leak! */
		st->st_p1isa = clone_bytes_as_chunk(sa_start, rbody.cur - sa_start,
						    "sa in aggr_outI1");
	}

	/* KE out */
	if (!ikev1_ship_KE(st, local_secret, &st->st_gi, &rbody))
		return STF_INTERNAL_ERROR;

	/* Ni out */
	if (!ikev1_ship_nonce(&st->st_ni, nonce, &rbody, "Ni"))
		return STF_INTERNAL_ERROR;

	/* IDii out */
	{
		shunk_t id_b;
		struct isakmp_ipsec_id id_hd = build_v1_id_payload(&c->local->host, &id_b);

		struct pbs_out id_pbs;
		if (!out_struct(&id_hd, &isakmp_ipsec_identification_desc,
				&rbody, &id_pbs) ||
		    !out_hunk(id_b, &id_pbs, "my identity"))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&id_pbs);
	}

	/* CERTREQ out */
	if (send_cr) {
		log_state(RC_LOG, st, "I am sending a certificate request");
		if (!ikev1_build_and_ship_CR(cert_ike_type(mycert), c->remote->host.config->ca, &rbody))
			return STF_INTERNAL_ERROR;
	}

	/* send Vendor IDs */
	if (!out_v1VID_set(&rbody, c))
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

	log_state(RC_LOG, st, "%s", st->st_state->story);
	return STF_IGNORE;
}
