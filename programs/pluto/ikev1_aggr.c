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
#include <libreswan/ipsec_policy.h>
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
#include "adns.h"       /* needs <resolv.h> */
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

#include "xauth.h"

#include "vendor.h"
#include "nat_traversal.h"
#include "virtual.h"	/* needs connections.h */
#include "dpd.h"
#include "x509more.h"

/* STATE_AGGR_R0: HDR, SA, KE, Ni, IDii
 *           --> HDR, SA, KE, Nr, IDir, HASH_R/SIG_R
 */
static stf_status aggr_inI1_outR1_tail(struct pluto_crypto_req_cont *pcrc,
				       struct pluto_crypto_req *r);

static void aggr_inR1_outI2_crypto_continue(struct pluto_crypto_req_cont *pcrc,
					    struct pluto_crypto_req *r,
					    err_t ugh);

/*
 * continuation from second calculation (the DH one)
 *
 */
static void aggr_inI1_outR1_continue2(struct pluto_crypto_req_cont *pcrc,
				      struct pluto_crypto_req *r,
				      err_t ugh)
{
	struct dh_continuation *dh = (struct dh_continuation *)pcrc;
	struct msg_digest *md = dh->md;
	struct state *const st = md->st;
	stf_status e;

	DBG(DBG_CONTROLMORE,
	    DBG_log("aggr inI1_outR1: calculated ke+nonce+DH, sending R1"));

	if (st == NULL) {
		loglog(RC_LOG_SERIOUS,
		       "%s: Request was disconnected from state",
		       __FUNCTION__);
		if (dh->md != NULL)
			release_md(dh->md);
		return;
	}

	/* XXX should check out ugh */
	passert(ugh == NULL);
	passert(cur_state == NULL);
	passert(st != NULL);

	passert(st->st_suspended_md == dh->md);
	set_suspended(st, NULL); /* no longer connected or suspended */

	set_cur_state(st);
	st->st_calculating = FALSE;

	e = aggr_inI1_outR1_tail(pcrc, r);

	if (dh->md != NULL) {
		complete_v1_state_transition(&dh->md, e);
		if (dh->md != NULL)
			release_md(dh->md);
	}
	reset_cur_state();
}

/*
 * for aggressive mode, this is sub-optimal, since we should have
 * had the crypto helper actually do everything, but we need to do
 * some additional work to set that all up, so this is fine for now.
 *
 */
static void aggr_inI1_outR1_continue1(struct pluto_crypto_req_cont *pcrc,
				      struct pluto_crypto_req *r,
				      err_t ugh)
{
	struct ke_continuation *ke = (struct ke_continuation *)pcrc;
	struct msg_digest *md = ke->md;
	struct state *const st = md->st;
	stf_status e;

	DBG(DBG_CONTROLMORE,
	    DBG_log("aggr inI1_outR1: calculated ke+nonce, calculating DH"));

	if (st == NULL) {
		loglog(RC_LOG_SERIOUS,
		       "%s: Request was disconnected from state",
		       __FUNCTION__);
		if (ke->md != NULL)
			release_md(ke->md);
		return;
	}

	/* XXX should check out ugh */
	passert(ugh == NULL);
	passert(cur_state == NULL);
	passert(st != NULL);

	passert(st->st_suspended_md == ke->md);
	set_suspended(st, NULL); /* no longer connected or suspended */

	set_cur_state(st);
	st->st_calculating = FALSE;

	/* unpack first calculation */
	unpack_KE(st, r, &st->st_gr);

	/* unpack nonce too */
	unpack_nonce(&st->st_nr, r);

	/* NOTE: the "r" reply will get freed by our caller */

	/* set up second calculation */
	{
		struct dh_continuation *dh = alloc_thing(
			struct dh_continuation,
			"aggr outR1 DH");
		dh->md = md;
		set_suspended(st, md);
		pcrc_init(&dh->dh_pcrc);
		dh->dh_pcrc.pcrc_func = aggr_inI1_outR1_continue2;
		e = start_dh_secretiv(&dh->dh_pcrc, st,
				      st->st_import,
				      RESPONDER,
				      st->st_oakley.group->group);

		if (e != STF_SUSPEND) {
			if (dh->md != NULL) {
				complete_v1_state_transition(&dh->md, e);
				if (dh->md != NULL)
					release_md(dh->md);
			}
		}

		reset_cur_state();
	}
}

static stf_status aggr_inI1_outR1_common(struct msg_digest *md,
					 int authtype)
{
	/* With Aggressive Mode, we get an ID payload in this, the first
	 * message, so we can use it to index the preshared-secrets
	 * when the IP address would not be meaningful (i.e. Road
	 * Warrior).  So our first task is to unravel the ID payload.
	 */
	struct state *st;
	struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_SA];
	pb_stream *keyex_pbs = &md->chain[ISAKMP_NEXT_KE]->pbs;
	struct connection *c = find_host_connection(&md->iface->ip_addr,
						    md->iface->port,
						    &md->sender,
						    md->sender_port, LEMPTY);

#if 0
	if (c == NULL && md->iface->ike_float) {
		c = find_host_connection(&md->iface->addr,
					 pluto_natt_float_port,
					 &md->sender, md->sender_port, LEMPTY);
	}
#endif

	if (c == NULL) {
		/* see if a wildcarded connection can be found */
		pb_stream pre_sa_pbs = sa_pd->pbs;
		lset_t policy = preparse_isakmp_sa_body(&pre_sa_pbs) |
				POLICY_AGGRESSIVE;
		c = find_host_connection(&md->iface->ip_addr, pluto_port,
					 (ip_address*)NULL, md->sender_port,
					 policy);
		if (c == NULL || (c->policy & POLICY_AGGRESSIVE) == 0) {
			loglog(RC_LOG_SERIOUS, "initial Aggressive Mode message from %s"
			       " but no (wildcard) connection has been configured%s%s",
			       ip_str(&md->sender),
			       (policy != LEMPTY) ? " with policy=" : "",
			       (policy != LEMPTY) ?
			       bitnamesof(sa_policy_bit_names, policy) : "");
			/* XXX notification is in order! */
			return STF_IGNORE;
		}
		/* Create a temporary connection that is a copy of this one.
		 * His ID isn't declared yet.
		 */
		c = rw_instantiate(c, &md->sender, NULL, NULL);
	}

	/* Set up state */
	cur_state = md->st = st = new_state();  /* (caller will reset cur_state) */
	st->st_connection = c;
	st->st_remoteaddr = md->sender;
	st->st_remoteport = md->sender_port;
	st->st_localaddr  = md->iface->ip_addr;
	st->st_localport  = md->iface->port;
	st->st_interface  = md->iface;
	change_state(st, STATE_AGGR_R1);

	/* until we have clue who this is, then be conservative about allocating
	 * them any crypto bandwidth */
	st->st_import = pcim_stranger_crypto;

	st->st_policy |= POLICY_AGGRESSIVE;

	st->st_oakley.auth = authtype;

	if (!decode_peer_id(md, FALSE, TRUE)) {
		char buf[IDTOA_BUF];

		(void) idtoa(&st->st_connection->spd.that.id, buf,
			     sizeof(buf));
		loglog(RC_LOG_SERIOUS,
		       "initial Aggressive Mode packet claiming to be from %s"
		       " on %s but no connection has been authorized",
		       buf, ip_str(&md->sender));
		/* XXX notification is in order! */
		return STF_FAIL + INVALID_ID_INFORMATION;
	}

	c = st->st_connection;

#ifdef DEBUG
	extra_debugging(c);
#endif
	st->st_try = 0;                                 /* Not our job to try again from start */
	st->st_policy = c->policy & ~POLICY_IPSEC_MASK; /* only as accurate as connection */

	memcpy(st->st_icookie, md->hdr.isa_icookie, COOKIE_SIZE);
	get_cookie(FALSE, st->st_rcookie, COOKIE_SIZE, &md->sender);

	insert_state(st); /* needs cookies, connection, and msgid (0) */

	/* copy the quirks we might have accumulated */
	copy_quirks(&st->quirks, &md->quirks);

	st->st_doi = ISAKMP_DOI_IPSEC;
	st->st_situation = SIT_IDENTITY_ONLY; /* We only support this */

	libreswan_log("responding to Aggressive Mode, state #%lu, connection \"%s\""
		      " from %s",
		      st->st_serialno, st->st_connection->name,
		      ip_str(&c->spd.that.host_addr));

	DBG(DBG_CONTROLMORE, DBG_log("sender checking NAT-t: %d and %d",
				     nat_traversal_enabled,
				     md->quirks.nat_traversal_vid));
	if (md->quirks.nat_traversal_vid && nat_traversal_enabled) {
		/* reply if NAT-Traversal draft is supported */
		st->hidden_variables.st_nat_traversal =
			LELEM(nat_traversal_vid_to_method(md->quirks.nat_traversal_vid));
		libreswan_log("enabling possible NAT-traversal with method %s",
			      enum_name(&natt_method_names,
					nat_traversal_vid_to_method(md->quirks.
								    nat_traversal_vid)));
	}

	/* save initiator SA for HASH */
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
				     keyex_pbs));

	/* Ni in */
	RETURN_STF_FAILURE(accept_v1_nonce(md, &st->st_ni, "Ni"));

	{
		struct ke_continuation *ke = alloc_thing(
			struct ke_continuation,
			"outI2 KE");
		ke->md = md;
		set_suspended(st, md);

		if (!st->st_sec_in_use) {
			pcrc_init(&ke->ke_pcrc);
			ke->ke_pcrc.pcrc_func = aggr_inI1_outR1_continue1;
			return build_ke(&ke->ke_pcrc, st, st->st_oakley.group,
					st->st_import);
		} else {
			return aggr_inI1_outR1_tail(
				(struct pluto_crypto_req_cont *)ke, NULL);
		}
	}
}

static void doi_log_cert_thinking(struct msg_digest *md UNUSED,
				  u_int16_t auth,
				  enum ipsec_cert_type certtype,
				  enum certpolicy policy,
				  bool gotcertrequest,
				  bool send_cert)
{
	DBG(DBG_CONTROL,
	    DBG_log("thinking about whether to send my certificate:"));

	DBG(DBG_CONTROL, {
		char esb[ENUM_SHOW_BUF_LEN];

		DBG_log("  I have RSA key: %s cert.type: %s ",
		    enum_showb(&oakley_auth_names, auth, esb, sizeof(esb)),
		    enum_show(&cert_type_names, certtype));
	});

	DBG(DBG_CONTROL,
	    DBG_log("  sendcert: %s and I did%s get a certificate request ",
		    enum_show(&certpolicy_type_names, policy),
		    gotcertrequest ? "" : " not"));

	DBG(DBG_CONTROL,
	    DBG_log("  so %ssend cert.", send_cert ? "" : "do not "));

	if (!send_cert) {
		if (auth == OAKLEY_PRESHARED_KEY)
			DBG(DBG_CONTROL,
			    DBG_log("I did not send a certificate because digital signatures are not being used. (PSK)"));
		else if (certtype == CERT_NONE)
			DBG(DBG_CONTROL,
			    DBG_log("I did not send a certificate because I do not have one."));
		else if (policy == cert_sendifasked)
			DBG(DBG_CONTROL,
			    DBG_log("I did not send my certificate because I was not asked to."));
	}
}

stf_status aggr_inI1_outR1_psk(struct msg_digest *md)
{
	return aggr_inI1_outR1_common(md, OAKLEY_PRESHARED_KEY);
}

stf_status aggr_inI1_outR1_rsasig(struct msg_digest *md)
{
	return aggr_inI1_outR1_common(md, OAKLEY_RSA_SIG);
}

static stf_status aggr_inI1_outR1_tail(struct pluto_crypto_req_cont *pcrc,
				       struct pluto_crypto_req *r)
{
	struct ke_continuation *ke = (struct ke_continuation *)pcrc;
	struct msg_digest *md = ke->md;
	struct state *st = md->st;
	bool send_cert = FALSE;
	bool send_cr = FALSE;
	generalName_t *requested_ca = NULL;
	struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_SA];
	int auth_payload;
	cert_t mycert = st->st_connection->spd.this.cert;

	pb_stream r_sa_pbs;
	pb_stream r_id_pbs; /* ID Payload; also used for hash calculation */

	/* parse_isakmp_sa also spits out a winning SA into our reply,
	 * so we have to build our reply_stream and emit HDR before calling it.
	 */

	finish_dh_secretiv(st, r);

	/* decode certificate requests */
	decode_cr(md, &requested_ca);

	if (requested_ca != NULL)
		st->hidden_variables.st_got_certrequest = TRUE;

	/*
	 * send certificate if we have one and auth is RSA, and we were
	 * told we can send one if asked, and we were asked, or we were told
	 * to always send one.
	 */
	send_cert = st->st_oakley.auth == OAKLEY_RSA_SIG &&
		    mycert.type != CERT_NONE &&
		    ((st->st_connection->spd.this.sendcert ==
		      cert_sendifasked &&
		      st->hidden_variables.st_got_certrequest) ||
		     st->st_connection->spd.this.sendcert == cert_alwayssend ||
		     st->st_connection->spd.this.sendcert == cert_forcedtype);

	doi_log_cert_thinking(md,
			      st->st_oakley.auth,
			      mycert.type,
			      st->st_connection->spd.this.sendcert,
			      st->hidden_variables.st_got_certrequest,
			      send_cert);

	/* send certificate request, if we don't have a preloaded RSA public key */
	send_cr = send_cert && !has_preloaded_public_key(st);

	DBG(DBG_CONTROL,
	    DBG_log(" I am %ssending a certificate request",
		    send_cr ? "" : "not "));

	/*
	 * free collected certificate requests since as initiator
	 * we don't heed them anyway
	 */
	free_generalNames(requested_ca, TRUE);

	/* done parsing; initialize crypto  */

	init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
		 "reply packet");

	/* HDR out */
	{
		struct isakmp_hdr r_hdr = md->hdr;

		memcpy(r_hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
		r_hdr.isa_np = ISAKMP_NEXT_SA;
		if (!out_struct(&r_hdr, &isakmp_hdr_desc, &reply_stream,
				&md->rbody))
			return STF_INTERNAL_ERROR;
	}

	/* start of SA out */
	{
		struct isakmp_sa r_sa = sa_pd->payload.sa;
		notification_t rn;

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
	if (!justship_KE(&st->st_gr,
			 &md->rbody, ISAKMP_NEXT_NONCE))
		return STF_INTERNAL_ERROR;

	/* Nr */
	if (!justship_nonce(&st->st_nr, &md->rbody, ISAKMP_NEXT_ID, "Nr"))
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
		cert_hd.isacert_type = mycert.type;

		libreswan_log("I am sending my cert");

		if (!out_struct(&cert_hd,
				&isakmp_ipsec_certificate_desc,
				&md->rbody,
				&cert_pbs))
			return STF_INTERNAL_ERROR;

		if (mycert.forced) {
			if (!out_chunk(mycert.u.blob, &cert_pbs,
				       "forced CERT"))
				return STF_INTERNAL_ERROR;
		} else {
			if (!out_chunk(get_mycert(mycert), &cert_pbs, "CERT"))
				return STF_INTERNAL_ERROR;
		}
		close_output_pbs(&cert_pbs);
	}

	/* CR out */
	if (send_cr) {
		libreswan_log("I am sending a certificate request");
		if (!build_and_ship_CR(mycert.type,
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
			if (!out_generic_raw(ISAKMP_NEXT_VID,
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

			if (!out_generic_raw(ISAKMP_NEXT_VID,
					     &isakmp_signature_desc,
					     &md->rbody, sig_val, sig_len,
					     "SIG_R"))
				return STF_INTERNAL_ERROR;
		}
	}
	/*
	 * NOW SEND VENDOR ID payloads
	 */

	/* Announce our ability to do RFC 3706 Dead Peer Detection to the peer
	    if we have it enabled on this conn */
	if (st->st_connection->dpd_delay && st->st_connection->dpd_timeout) {
		/* Set local policy for DPD to be on */
		st->hidden_variables.st_dpd_local = 1;
	}

	/* send DPD VID */
	{
		int np = ISAKMP_NEXT_NONE;

		if (st->hidden_variables.st_nat_traversal)
			np = ISAKMP_NEXT_VID;

		if (!out_vid(np, &md->rbody, VID_MISC_DPD))
			return STF_INTERNAL_ERROR;
	}

	if (st->hidden_variables.st_nat_traversal) {
		if (!nat_traversal_add_natd(ISAKMP_NEXT_VID, &md->rbody, md))
			return STF_INTERNAL_ERROR;

		if (!out_vid(ISAKMP_NEXT_NONE,
			     &md->rbody,
			     md->quirks.nat_traversal_vid))
			return STF_INTERNAL_ERROR;
	}

	/* finish message */
	close_message(&md->rbody, st);

	return STF_OK;
}

/* STATE_AGGR_I1: HDR, SA, KE, Nr, IDir, HASH_R/SIG_R
 *           --> HDR*, HASH_I/SIG_I
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
	pb_stream *keyex_pbs = &md->chain[ISAKMP_NEXT_KE]->pbs;

	st->st_policy |= POLICY_AGGRESSIVE;

	if (!decode_peer_id(md, FALSE, TRUE)) {
		char buf[IDTOA_BUF];

		(void) idtoa(&st->st_connection->spd.that.id, buf,
			     sizeof(buf));
		loglog(RC_LOG_SERIOUS,
		       "initial Aggressive Mode packet claiming to be from %s"
		       " on %s but no connection has been authorized",
		       buf, ip_str(&md->sender));
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

	/* copy the quirks we might have accumulated */
	copy_quirks(&st->quirks, &md->quirks);

	if (nat_traversal_enabled && md->quirks.nat_traversal_vid)
		st->hidden_variables.st_nat_traversal = LELEM(nat_traversal_vid_to_method(
								      md->
								      quirks.
								      nat_traversal_vid));

	/* KE in */
	RETURN_STF_FAILURE(accept_KE(&st->st_gr, "Gr", st->st_oakley.group,
				     keyex_pbs));

	/* Ni in */
	RETURN_STF_FAILURE(accept_v1_nonce(md, &st->st_nr, "Nr"));

	/* moved the following up as we need Rcookie for hash, skeyids */
	/* Reinsert the state, using the responder cookie we just received */
	unhash_state(st);
	memcpy(st->st_rcookie, md->hdr.isa_rcookie, COOKIE_SIZE);
	insert_state(st); /* needs cookies, connection, and msgid (0) */

	DBG(DBG_CONTROLMORE,
	    DBG_log("inR1: checking NAT-t: %d and %d",
		    nat_traversal_enabled,
		    st->hidden_variables.st_nat_traversal));
	if (st->hidden_variables.st_nat_traversal) {
		nat_traversal_natd_lookup(md);
		nat_traversal_show_result(
			st->hidden_variables.st_nat_traversal,
			md->sender_port);
	}
	if (st->hidden_variables.st_nat_traversal & NAT_T_WITH_KA)
		nat_traversal_new_ka_event();

	/* set up second calculation */
	{
		struct dh_continuation *dh = alloc_thing(
			struct dh_continuation,
			"aggr outR1 DH");
		dh->md = md;

		set_suspended(st, md);
		pcrc_init(&dh->dh_pcrc);
		dh->dh_pcrc.pcrc_func = aggr_inR1_outI2_crypto_continue;
		return start_dh_secretiv(&dh->dh_pcrc, st,
					 st->st_import,
					 INITIATOR,
					 st->st_oakley.group->group);
	}
}

static void aggr_inR1_outI2_crypto_continue(struct pluto_crypto_req_cont *pcrc,
					    struct pluto_crypto_req *r,
					    err_t ugh)
{
	struct dh_continuation *dh = (struct dh_continuation *)pcrc;
	struct msg_digest *md = dh->md;
	struct state *const st = md->st;
	stf_status e;

	DBG(DBG_CONTROLMORE,
	    DBG_log("aggr inR1_outI2: calculated DH, sending I2"));

	if (st == NULL) {
		loglog(RC_LOG_SERIOUS,
		       "%s: Request was disconnected from state",
		       __FUNCTION__);
		if (dh->md != NULL)
			release_md(dh->md);
		return;
	}

	/* XXX should check out ugh */
	passert(ugh == NULL);
	passert(cur_state == NULL);
	passert(st != NULL);

	passert(st->st_suspended_md == dh->md);
	set_suspended(st, NULL); /* no longer connected or suspended */

	set_cur_state(st);
	st->st_calculating = FALSE;

	finish_dh_secretiv(st, r);

	e = aggr_inR1_outI2_tail(md, NULL);

	if (dh->md != NULL) {
		complete_v1_state_transition(&dh->md, e);
		if (dh->md != NULL)
			release_md(dh->md);
	}
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
	zero(reply_buffer);
	init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
		 "reply packet");

	/* HDR out */
	{
		struct isakmp_hdr r_hdr = md->hdr;

		memcpy(r_hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
		/* outputting should back-patch previous struct/hdr with payload type */
		r_hdr.isa_np = auth_payload;
		r_hdr.isa_flags |= ISAKMP_FLAG_ENCRYPTION; /* KLUDGE */
		if (!out_struct(&r_hdr, &isakmp_hdr_desc, &reply_stream,
				&md->rbody))
			return STF_INTERNAL_ERROR;
	}

	if (st->hidden_variables.st_nat_traversal) {
		if (!nat_traversal_add_natd(auth_payload, &md->rbody, md))
			return STF_INTERNAL_ERROR;
	}

	/* HASH_I or SIG_I out */
	{
		u_char buffer[1024];
		struct isakmp_ipsec_id id_hd;
		chunk_t id_b;
		pb_stream id_pbs;
		u_char hash_val[MAX_DIGEST_LEN];
		size_t hash_len;

		build_id_payload(&id_hd, &id_b, &st->st_connection->spd.this);
		init_pbs(&id_pbs, buffer, sizeof(buffer), "identity payload");
		id_hd.isaiid_np = ISAKMP_NEXT_NONE;
		if (!out_struct(&id_hd, &isakmp_ipsec_identification_desc,
				&id_pbs, NULL) ||
		    !out_chunk(id_b, &id_pbs, "my identity"))
			return STF_INTERNAL_ERROR;

		hash_len = main_mode_hash(st, hash_val, TRUE, &id_pbs);

		if (auth_payload == ISAKMP_NEXT_HASH) {
			/* HASH_I out */
			if (!out_generic_raw(ISAKMP_NEXT_NONE,
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

			if (!out_generic_raw(ISAKMP_NEXT_NONE,
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
	 * between the end of phase 1 and the start of phase 2 ie mode config
	 * payloads etc will not loose our IV
	 */
	memcpy(st->st_ph1_iv, st->st_new_iv, st->st_new_iv_len);
	st->st_ph1_iv_len = st->st_new_iv_len;

	return STF_OK;
}

/* STATE_AGGR_R1: HDR*, HASH_I --> done
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
	u_char buffer[1024];	/* ??? enough room for reconstructed peer ID payload? */
	struct payload_digest id_pd;

	if (st->hidden_variables.st_nat_traversal) {
		nat_traversal_natd_lookup(md);
		nat_traversal_show_result(
			st->hidden_variables.st_nat_traversal,
			md->sender_port);
	}
	if (st->hidden_variables.st_nat_traversal & NAT_T_WITH_KA)
		nat_traversal_new_ka_event();

	/* Reconstruct the peer ID so the peer hash can be authenticated */
	{
		struct isakmp_ipsec_id id_hd;
		chunk_t id_b;
		pb_stream pbs;
		pb_stream id_pbs;

		build_id_payload(&id_hd, &id_b, &st->st_connection->spd.that);
		init_pbs(&pbs, buffer, sizeof(buffer), "identity payload");
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
		in_struct(&id_pd.payload, &isakmp_identification_desc, &id_pbs,
			  &id_pd.pbs);
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
	 * are not supposed to be performed again during rekey */
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
	 * between the end of phase 1 and the start of phase 2 ie mode config
	 * payloads etc will not loose our IV
	 */
	memcpy(st->st_ph1_iv, st->st_new_iv, st->st_new_iv_len);
	st->st_ph1_iv_len = st->st_new_iv_len;

	DBG(DBG_CONTROL, DBG_log("phase 1 complete"));

	return STF_OK;
}

/*
 * Initiate an Oakley Aggressive Mode exchange.
 * --> HDR, SA, KE, Ni, IDii
 */
static stf_status aggr_outI1_tail(struct pluto_crypto_req_cont *pcrc,
				  struct pluto_crypto_req *r);	/* forward */

static void aggr_outI1_continue(struct pluto_crypto_req_cont *pcrc,
				struct pluto_crypto_req *r,
				err_t ugh)
{
	struct ke_continuation *ke = (struct ke_continuation *)pcrc;
	struct msg_digest *md = ke->md;
	struct state *const st = md->st;
	stf_status e;

	DBG(DBG_CONTROLMORE,
	    DBG_log("aggr outI1: calculated ke+nonce, sending I1"));

	if (st == NULL) {
		loglog(RC_LOG_SERIOUS,
		       "%s: Request was disconnected from state",
		       __FUNCTION__);
		if (ke->md != NULL)
			release_md(ke->md);
		return;
	}

	/* XXX should check out ugh */
	passert(ugh == NULL);
	passert(cur_state == NULL);
	passert(st != NULL);

	passert(st->st_suspended_md == ke->md);
	set_suspended(st, NULL); /* no longer connected or suspended */

	set_cur_state(st);

	st->st_calculating = FALSE;

	e = aggr_outI1_tail(pcrc, r);

	if (ke->md != NULL) {
		complete_v1_state_transition(&ke->md, e);
		if (ke->md != NULL)
			release_md(ke->md);
	}
	reset_globals();

	passert(GLOBALS_ARE_RESET());
}

stf_status aggr_outI1(int whack_sock,
		      struct connection *c,
		      struct state *predecessor,
		      lset_t policy,
		      unsigned long try,
		      enum crypto_importance importance
#ifdef HAVE_LABELED_IPSEC
		      , struct xfrm_user_sec_ctx_ike * uctx
#endif
		      )
{
	struct state *st;
	struct spd_route *sr;

	/* set up new state */
	cur_state = st = new_state();
	st->st_connection = c;
#ifdef HAVE_LABELED_IPSEC
	st->sec_ctx = NULL;
#endif
	set_state_ike_endpoints(st, c);

#ifdef DEBUG
	extra_debugging(c);
#endif
	st->st_policy = policy & ~POLICY_IPSEC_MASK;
	st->st_whack_sock = whack_sock;
	st->st_try = try;
	change_state(st, STATE_AGGR_I1);

	get_cookie(TRUE, st->st_icookie, COOKIE_SIZE, &c->spd.that.host_addr);

	st->st_import = importance;

	for (sr = &c->spd; sr != NULL; sr = sr->next) {
		if (sr->this.xauth_client) {
			if (sr->this.xauth_name) {
				/* ??? is this strncpy correct? */
				strncpy(st->st_xauth_username,
					sr->this.xauth_name,
					sizeof(st->st_xauth_username));
				break;
			}
		}
	}

	insert_state(st); /* needs cookies, connection, and msgid (0) */

	if (init_am_st_oakley(st, policy) == FALSE) {
		/*
		 * This is only the case if NO IKE proposal was specified in the
		 * configuration file.  It's not the case if there were multiple
		 * configurations, even conflicting multiple DH groups.  So this
		 * should tell the user to add a proper proposal policy
		 */
		loglog(RC_AGGRALGO,
		       "no IKE proposal policy specified in config!  Can not initiate aggressive mode.  A policy must be specified in the configuration and should contain at most one DH group (mod1024, mod1536, mod2048).  Only the first DH group will be honored.");
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
		libreswan_log(
			"initiating Aggressive Mode #%lu, connection \"%s\"",
			st->st_serialno, st->st_connection->name);
	} else {
		update_pending(predecessor, st);
		libreswan_log(
			"initiating Aggressive Mode #%lu to replace #%lu, connection \"%s\"",
			st->st_serialno, predecessor->st_serialno,
			st->st_connection->name);
	}

	{
		struct ke_continuation *ke = alloc_thing(
			struct ke_continuation,
			"aggr_outI1 KE");
		stf_status e;

		ke->md = alloc_md();
		ke->md->st = st;
		set_suspended(st, ke->md);

		if (!st->st_sec_in_use) {
			pcrc_init(&ke->ke_pcrc);
			ke->ke_pcrc.pcrc_func = aggr_outI1_continue;
			e = build_ke(&ke->ke_pcrc, st, st->st_oakley.group,
				     importance);
			if (e != STF_SUSPEND && e != STF_INLINE) {
				loglog(RC_CRYPTOFAILED, "system too busy");
				delete_state(st);
			}
		} else {
			e = aggr_outI1_tail((struct pluto_crypto_req_cont *)ke,
					    NULL);
		}

		reset_globals();

		return e;
	}
}

static stf_status aggr_outI1_tail(struct pluto_crypto_req_cont *pcrc,
				  struct pluto_crypto_req *r)
{
	struct ke_continuation *ke = (struct ke_continuation *)pcrc;
	struct msg_digest *md = ke->md;
	struct state *const st = md->st;
	struct connection *c = st->st_connection;

	/* the MD is already set up by alloc_md() */

	/* make sure HDR is at start of a clean buffer */
	zero(reply_buffer);
	init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
		 "reply packet");

	/* HDR out */
	{
		struct isakmp_hdr hdr;

		memset(&hdr, '\0', sizeof(hdr)); /* default to 0 */
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
		int policy_index = POLICY_ISAKMP(st->st_policy,
						 c->spd.this.xauth_server,
						 c->spd.this.xauth_client);

		if (!out_sa(&md->rbody,
			    &oakley_am_sadb[policy_index], st,
			    TRUE, TRUE, ISAKMP_NEXT_KE)) {
			cur_state = NULL;
			return STF_INTERNAL_ERROR;
		}

		/* save initiator SA for later HASH */
		passert(st->st_p1isa.ptr == NULL); /* no leak! */
		clonetochunk(st->st_p1isa, sa_start, md->rbody.cur - sa_start,
			     "sa in aggr_outI1");
	}

	/* KE out */
	if (!ship_KE(st, r, &st->st_gi,
		     &md->rbody, ISAKMP_NEXT_NONCE))
		return STF_INTERNAL_ERROR;

	/* Ni out */
	if (!ship_nonce(&st->st_ni, r, &md->rbody, ISAKMP_NEXT_ID, "Ni"))
		return STF_INTERNAL_ERROR;

	DBG(DBG_CONTROLMORE, DBG_log("setting sec: %d", st->st_sec_in_use));

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
	if(c->cisco_unity)
		numvidtosend++;

	if(c->send_vendorid)
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

		if (!nat_traversal_insert_vid(np, &md->rbody)) {
			reset_cur_state();
			return STF_INTERNAL_ERROR;
		}
	}

	if (c->spd.this.xauth_client || c->spd.this.xauth_server) {
		int np = --numvidtosend > 0 ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;
		if (!out_vid(np, &md->rbody, VID_MISC_XAUTH))
			return STF_INTERNAL_ERROR;
	}

	if(c->cisco_unity) {
		int np = --numvidtosend > 0 ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;
		if (!out_vid(np, &md->rbody, VID_CISCO_UNITY))
			return STF_INTERNAL_ERROR;
	}

	if(c->send_vendorid) {
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

	close_message(&md->rbody, st);
	close_output_pbs(&reply_stream);

	/* let TCL hack it before we mark the length and copy it */

	clonetochunk(st->st_tpacket, reply_stream.start,
		     pbs_offset(&reply_stream),
		     "reply packet from aggr_outI1");

	/* Transmit */

	DBG_cond_dump(DBG_RAW, "sending:\n",
		      st->st_tpacket.ptr, st->st_tpacket.len);

	send_ike_msg(st, "aggr_outI1");

	/* Set up a retransmission event, half a minute henceforth */
	delete_event(st);
	event_schedule(EVENT_RETRANSMIT, EVENT_RETRANSMIT_DELAY_0, st);

	whack_log(RC_NEW_STATE + STATE_AGGR_I1,
		  "%s: initiate", enum_name(&state_names, st->st_state));
	cur_state = NULL;
	return STF_IGNORE;
}
