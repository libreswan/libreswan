/* IPsec DOI and Oakley resolution routines
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009,2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2008 Ilia Sotnikov
 * Copyright (C) 2009 Seong-hun Lim
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2010-2019 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
 * Copyright (C) 2013 Wolfgang Nothdurft <wolfgang@linogate.de>
 * Copyright (C) 2013-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2017-2019 Andrew Cagney <cagney@gnu.org>
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

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>

#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "state.h"
#include "ikev1_msgid.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h" /* needs id.h */
#include "keys.h"
#include "packet.h"
#include "demux.h" /* needs packet.h */
#include "kernel.h" /* needs connections.h */
#include "log.h"
#include "ike_spi.h"
#include "server.h"
#include "ikev1_spdb.h"
#include "timer.h"
#include "rnd.h"
#include "ipsec_doi.h" /* needs demux.h and state.h */
#include "whack.h"
#include "asn1.h"
#include "pending.h"
#include "ikev1_hash.h"
#include "crypt_symkey.h"		/* for symkey_delref() */

#include "crypto.h"
#include "secrets.h"
#include "lswnss.h"

#include "ike_alg.h"
#include "ike_alg_hash.h"		/* for ike_alg_hash_sha1 */
#include "kernel_alg.h"
#include "plutoalg.h"
#include "ikev1.h"
#include "ikev1_continuations.h"
#include "ikev1_message.h"
#include "ikev1_xauth.h"
#include "crypt_prf.h"
#include "nat_traversal.h"
#include "ikev1_nat.h"
#include "ikev1_dpd.h"
#include "pluto_x509.h"
#include "crypt_ke.h"
#include "fips_mode.h"
#include "ip_address.h"
#include "send.h"
#include "ikev1_send.h"
#include "nss_cert_verify.h"
#include "iface.h"
#include "crypt_dh.h"
#include "unpack.h"
#include "ikev1_host_pair.h"
#include "ikev1_peer_id.h"
#include "lswnss.h"
#include "ikev1_vendorid.h"
#include "ikev1_cert.h"
#include "terminate.h"

static dh_shared_secret_cb main_inR2_outI3_continue;	/* type assertion */
static ke_and_nonce_cb main_inR1_outI2_continue;	/* type assertion */
static ke_and_nonce_cb main_inI2_outR2_continue1; /* type assertion */
static dh_shared_secret_cb main_inI2_outR2_continue2;	/* type assertion */

static bool emit_v1N_IPSEC_INITIAL_CONTACT(struct pbs_out *rbody, struct ike_sa *ike)
{
	struct isakmp_notification isan = {
		.isan_doi = ISAKMP_DOI_IPSEC,
		.isan_protoid = PROTO_ISAKMP,
		.isan_spisize = COOKIE_SIZE * 2,
		.isan_type = v1N_IPSEC_INITIAL_CONTACT,
	};

	struct pbs_out notify_pbs;
	if (!pbs_out_struct(rbody, &isakmp_notification_desc,
			    &isan, sizeof(notify_pbs), &notify_pbs)) {
		return false;
	}

	if (!pbs_out_raw(&notify_pbs, ike->sa.st_ike_spis.initiator.bytes, COOKIE_SIZE,
			 "notify icookie") ||
	    !pbs_out_raw(&notify_pbs, ike->sa.st_ike_spis.responder.bytes, COOKIE_SIZE,
			 "notify rcookie")) {
		return false;
	}

	/* zero length data payload */
	close_output_pbs(&notify_pbs);
	return true;
}

/*
 * Initiate an Oakley Main Mode exchange.
 * --> HDR;SA
 * Note: this is not called from demux.c
 */

struct ike_sa *main_outI1(struct connection *c,
			  struct ike_sa *predecessor,
			  const struct child_policy *policy,
			  const threadtime_t *inception,
			  bool background)
{
	struct ike_sa *ike = new_v1_istate(c, STATE_MAIN_I1);
	if (ike == NULL) {
		return NULL;
	}

	statetime_t start = statetime_backdate(&ike->sa, inception);

	if (has_child_policy(policy)) {
		/*
		 * When replacing the IKE (ISAKMP) SA, policy=LEMPTY
		 * so that a Child SA isn't also initiated and this
		 * code is skipped.
		 */
		append_pending(ike, c, policy,
			       (predecessor == NULL ? SOS_NOBODY :
				predecessor->sa.st_serialno),
			       null_shunk, true /* part of initiate */, background);
	}

	if (predecessor == NULL) {
		llog_sa(RC_LOG, ike, "initiating IKEv1 Main Mode connection");
	} else {
		llog_sa(RC_LOG, ike, "initiating IKEv1 Main Mode connection to replace #%lu",
			  predecessor->sa.st_serialno);
	}

	/* set up reply */
	reply_stream = open_pbs_out("reply packet", reply_buffer, sizeof(reply_buffer), ike->sa.logger);

	/* HDR out */
	struct pbs_out rbody;
	{
		struct isakmp_hdr hdr = {
			.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
				ISAKMP_MINOR_VERSION,
			.isa_xchg = ISAKMP_XCHG_IDPROT,
		};
		hdr.isa_ike_initiator_spi = ike->sa.st_ike_spis.initiator;
		/* R-cookie, flags and MessageID are left zero */

		if (impair.send_bogus_isakmp_flag) {
			hdr.isa_flags |= ISAKMP_FLAGS_RESERVED_BIT6;
		}

		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply_stream,
				&rbody)) {
			/* leak!?! */
			return NULL;
		}
	}

	/* SA out */
	{
		uint8_t *sa_start = rbody.cur;

		if (!ikev1_out_main_sa(&rbody, ike)) {
			llog(RC_LOG, ike->sa.logger, "outsa fail");
			/* leak!?! */
			return NULL;
		}

		/* no leak! (MUST be first time) */
		passert(ike->sa.st_p1isa.ptr == NULL);

		/* save initiator SA for later HASH */
		ike->sa.st_p1isa = clone_bytes_as_chunk(sa_start, rbody.cur - sa_start,
						    "sa in main_outI1");
	}

	/* send Vendor IDs */
	if (!out_v1VID_set(&rbody, c)) {
		return NULL;
	}

	/* as Initiator, spray NAT VIDs */
	if (!emit_nat_traversal_vid(&rbody, c)) {
		return NULL;
	}

	if (!close_v1_message(&rbody, ike)) {
		return NULL;
	}

	close_output_pbs(&reply_stream);

	/* Transmit */
	record_and_send_v1_ike_msg(&ike->sa, &reply_stream,
		"reply packet for main_outI1");

	delete_v1_event(&ike->sa);
	clear_retransmits(&ike->sa);
	start_retransmits(&ike->sa);

	if (predecessor != NULL) {
		move_pending(predecessor, ike);
		llog_sa(RC_LOG, ike, "%s, replacing "PRI_SO,
			ike->sa.st_state->story,
			pri_so(predecessor->sa.st_serialno));
	} else {
		llog(RC_LOG, ike->sa.logger, "%s", ike->sa.st_state->story);
	}

	statetime_stop(&start, "%s()", __func__);

	/* outI1 is not encrypted */
	PEXPECT(ike->sa.logger, ike->sa.st_v1_phase_1_iv.len == 0); /*outI1*/

	return ike;
}

/*
 * Generate HASH_I or HASH_R for ISAKMP Phase I.
 * This will *not* generate other hash payloads (eg. Phase II or Quick Mode,
 * New Group Mode, or ISAKMP Informational Exchanges).
 * If the hashi argument is TRUE, generate HASH_I; if FALSE generate HASH_R.
 * See RFC2409 IKE 5.
 *
 * Generating the SIG_I and SIG_R for DSS is an odd perversion of this:
 * Most of the logic is the same, but SHA-1 is used in place of HMAC-whatever.
 * The extensive common logic is embodied in main_mode_hash_body().
 * See draft-ietf-ipsec-ike-01.txt 4.1 and 6.1.1.2
 */

static void main_mode_hash_body(struct ike_sa *ike,
				enum sa_role role,
				shunk_t id_payload, /* ID payload, including header */
				struct crypt_prf *ctx)
{
	switch (role) {
	case SA_INITIATOR:
		crypt_prf_update_hunk(ctx, "gi", ike->sa.st_gi);
		crypt_prf_update_hunk(ctx, "gr", ike->sa.st_gr);
		crypt_prf_update_thing(ctx, "initiator", ike->sa.st_ike_spis.initiator);
		crypt_prf_update_thing(ctx, "responder", ike->sa.st_ike_spis.responder);
		break;
	case SA_RESPONDER:
		crypt_prf_update_hunk(ctx, "gr", ike->sa.st_gr);
		crypt_prf_update_hunk(ctx, "gi", ike->sa.st_gi);
		crypt_prf_update_thing(ctx, "responder", ike->sa.st_ike_spis.responder);
		crypt_prf_update_thing(ctx, "initiator", ike->sa.st_ike_spis.initiator);
		break;
	default:
		bad_case(role);
	}

	if (LDBGP(DBG_CRYPT, ike->sa.logger)) {
		LDBG_log(ike->sa.logger, "hashing %zu bytes of SA",
			 ike->sa.st_p1isa.len - sizeof(struct isakmp_generic));
	}

	/* SA_b */
	crypt_prf_update_bytes(ctx, "p1isa",
			       ike->sa.st_p1isa.ptr + sizeof(struct isakmp_generic),
			       ike->sa.st_p1isa.len - sizeof(struct isakmp_generic));

	/*
	 * Hash identification payload, without generic payload header
	 * (i.e., slice it off).
	 *
	 * We used to reconstruct ID Payload for this purpose, but now
	 * we use the bytes as they appear on the wire to avoid
	 * "spelling problems".
	 */
	shunk_t id_body = hunk_slice(id_payload,
				     sizeof(struct isakmp_generic),
				     id_payload.len);
	crypt_prf_update_hunk(ctx, "idpl", id_body);
}

struct crypt_mac main_mode_hash(struct ike_sa *ike,
				enum sa_role role,
				shunk_t id_payload) /* ID payload, including header */
{
	struct crypt_prf *ctx = crypt_prf_init_symkey("main mode",
						      ike->sa.st_oakley.ta_prf,
						      "skeyid", ike->sa.st_skeyid_nss,
						      ike->sa.logger);
	main_mode_hash_body(ike, role, id_payload, ctx);
	return crypt_prf_final_mac(&ctx, NULL);
}

/*
 * Create an RSA signature of a hash.
 * Poorly specified in draft-ietf-ipsec-ike-01.txt 6.1.1.2.
 * Use PKCS#1 version 1.5 encryption of hash (called
 * RSAES-PKCS1-V1_5) in PKCS#2.
 * Returns 0 on failure.
 */

struct hash_signature v1_sign_hash_RSA(const struct connection *c,
				       const struct crypt_mac *hash,
				       struct logger *logger)
{
	const struct secret_pubkey_stuff *pks = get_local_private_key(c, &pubkey_type_rsa,
								      logger);
	if (pks == NULL) {
		llog(RC_LOG, logger,
			    "unable to locate my private key for RSA Signature");
		return (struct hash_signature) { .len = 0, }; /* failure: no key to use */
	}

	struct hash_signature sig = pubkey_signer_raw_rsa.sign_hash(pks, hash->ptr, hash->len,
								    &ike_alg_hash_sha1, logger);
	return sig;
}

/*
 * State Transition Functions.
 *
 * The definition of v1_state_microcode_table in ikev1.c is a good
 * overview of these routines.
 *
 * - Called from process_packet; result handled by complete_v1_state_transition
 * - struct state_microcode member "processor" points to these
 * - these routine definitionss are in state order
 * - these routines must be restartable from any point of error return:
 *   beware of memory allocated before any error.
 * - output HDR is usually emitted by process_packet (if state_microcode
 *   member first_out_payload isn't ISAKMP_NEXT_NONE).
 *
 * The transition functions' functions include:
 * - process and judge payloads
 * - update st_iv (result of decryption is in st_new_iv)
 * - build reply packet
 */

/*
 * Handle a Main Mode Oakley first packet (responder side).
 * HDR;SA --> HDR;SA
 */

stf_status main_inI1_outR1(struct state *null_st,
			   struct msg_digest *md)
{
	PEXPECT(md->logger, null_st == NULL);

	/* ??? this code looks a lot like the middle of ikev2_parent_inI1outR1 */
	struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_SA];
	struct pbs_out r_sa_pbs;

	if (drop_new_exchanges(md->logger) != NULL) {
		/* already debug-logged; log would fill disk */
		return STF_IGNORE;
	}

	struct connection *c = find_v1_main_mode_connection(md); /* must delref */
	if (c == NULL) {
		/* XXX: already logged */
		/* XXX notification is in order! */
		return STF_IGNORE;
	}

	/* Set up state */
	struct ike_sa *ike = new_v1_rstate(c, md);
	md->v1_st = &ike->sa;

	/* inI1 is not encrypted */
	PEXPECT(ike->sa.logger, md->v1_decrypt_iv.len == 0); /*inI1*/
	PEXPECT(ike->sa.logger, ike->sa.st_v1_phase_1_iv.len == 0); /*inI1*/

	/* delref stack connection pointer */
	connection_delref(&c, md->logger);
	c = ike->sa.st_connection;

	passert(!ike->sa.st_oakley.doing_xauth);

	/* only as accurate as connection */
	ike->sa.st_policy = (struct child_policy){0};
	change_v1_state(&ike->sa, STATE_MAIN_R0);

	binlog_refresh_state(&ike->sa);

	merge_quirks(ike, md);

	check_nat_traversal_vid(ike, md);

	if (LDBGP(DBG_BASE, ike->sa.logger)) {
		LDBG_log(ike->sa.logger, "  ICOOKIE-DUMP:");
		LDBG_thing(ike->sa.logger, ike->sa.st_ike_spis.initiator);
		LDBG_log(ike->sa.logger, "  ICOOKIE-DUMP:");
		LDBG_thing(ike->sa.logger, ike->sa.st_ike_spis.initiator);
	}

	if (is_instance(c)) {
		endpoint_buf b;
		llog(RC_LOG, ike->sa.logger, "responding to Main Mode from unknown peer %s",
		     str_endpoint_sensitive(&md->sender, &b));
	} else {
		llog(RC_LOG, ike->sa.logger, "responding to Main Mode");
	}

	/*
	 * parse_isakmp_sa also spits out a winning SA into our reply,
	 * so we have to build our reply_stream and emit HDR before calling it.
	 */

	/*
	 * HDR out.
	 * We can't leave this to comm_handle() because we must
	 * fill in the cookie.
	 */
	reply_stream = open_pbs_out("reply packet", reply_buffer, sizeof(reply_buffer), ike->sa.logger);
	struct pbs_out rbody;
	{
		struct isakmp_hdr hdr = md->hdr;

		hdr.isa_flags = 0; /* clear all flags */
		hdr.isa_ike_responder_spi = ike->sa.st_ike_spis.responder;
		hdr.isa_np = ISAKMP_NEXT_NONE; /* clear NP */

		if (impair.send_bogus_isakmp_flag) {
			hdr.isa_flags |= ISAKMP_FLAGS_RESERVED_BIT6;
		}

		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply_stream,
					&rbody))
			return STF_INTERNAL_ERROR;
	}

	/* start of SA out */
	{
		struct isakmp_sa r_sa = {
			.isasa_doi = ISAKMP_DOI_IPSEC,
		};
		if (!out_struct(&r_sa, &isakmp_sa_desc, &rbody, &r_sa_pbs))
			return STF_INTERNAL_ERROR;
	}

	/* SA body in and out */
	RETURN_STF_FAIL_v1NURE(parse_isakmp_sa_body(&sa_pd->pbs,
						    &sa_pd->payload.sa,
						    &r_sa_pbs, false, ike));

	/* send Vendor IDs */
	if (!out_v1VID_set(&rbody, c))
		return STF_INTERNAL_ERROR;

	/* as Responder, send best NAT VID we received */
	if (ike->sa.hidden_variables.st_nat_traversal != LEMPTY) {
		if (!out_v1VID(&rbody, md->v1_quirks.qnat_traversal_vid))
			return STF_INTERNAL_ERROR;
	}

	if (!close_v1_message(&rbody, ike))
		return STF_INTERNAL_ERROR;

	/* save initiator SA for HASH */
	replace_chunk(&ike->sa.st_p1isa, pbs_in_all(&sa_pd->pbs), __func__);

	/* outR1 is not encrypted */
	PEXPECT(ike->sa.logger, ike->sa.st_v1_phase_1_iv.len == 0); /*outR1*/

	return STF_OK;
}

/*
 * STATE_MAIN_I1: HDR, SA --> auth dependent
 * PSK_AUTH, DS_AUTH: --> HDR, KE, Ni
 *
 * We do heavy computation here. For Main Mode, this is mostly okay,
 * since have already done a return routeability check.
 *
 */

stf_status main_inR1_outI2(struct state *ike_sa, struct msg_digest *md)
{
	struct ike_sa *ike = pexpect_ike_sa(ike_sa);
	if (ike == NULL) {
		return STF_INTERNAL_ERROR;
	}
	ldbg(ike->sa.logger, "%s() for "PRI_SO,
	     __func__, pri_so(ike->sa.st_serialno));

	if (impair.drop_i2) {
		dbg("dropping Main Mode I2 packet as per impair");
		return STF_IGNORE;
	}

	/* inR1 is not encrypted */
	PEXPECT(ike->sa.logger, ike->sa.st_v1_phase_1_iv.len == 0); /*inR1*/
	PEXPECT(ike->sa.logger, md->v1_decrypt_iv.len == 0); /*inR1*/

	/* verify echoed SA */
	{
		struct payload_digest *const sapd = md->chain[ISAKMP_NEXT_SA];

		RETURN_STF_FAIL_v1NURE(parse_isakmp_sa_body(&sapd->pbs,
							    &sapd->payload.sa,
							    NULL, true, ike));
	}

	if (is_fips_mode() && ike->sa.st_oakley.ta_prf == NULL) {
		llog(RC_LOG, ike->sa.logger,
		     "Missing prf - algo not allowed in fips mode (inR1_outI2)?");
		return STF_FAIL_v1N + v1N_SITUATION_NOT_SUPPORTED;
	}

	merge_quirks(ike, md);

	check_nat_traversal_vid(ike, md);

	submit_ke_and_nonce(/*callback*/&ike->sa, /*task*/&ike->sa, md,
			    ike->sa.st_oakley.ta_dh,
			    main_inR1_outI2_continue,
			    /*detach_whack*/false, HERE);
	return STF_SUSPEND;
}

/*
 * STATE_MAIN_I1: HDR, SA --> auth dependent
 * PSK_AUTH, DS_AUTH: --> HDR, KE, Ni
 *
 * The following are not yet implemented:
 * PKE_AUTH: --> HDR, KE, [ HASH(1), ] <IDi1_b>PubKey_r, <Ni_b>PubKey_r
 * RPKE_AUTH: --> HDR, [ HASH(1), ] <Ni_b>Pubkey_r, <KE_b>Ke_i,
 *                <IDi1_b>Ke_i [,<<Cert-I_b>Ke_i]
 *
 * We must verify that the proposal received matches one we sent.
 */

static stf_status main_inR1_outI2_continue(struct state *ike_sa,
					   struct msg_digest *md,
					   struct dh_local_secret *local_secret,
					   chunk_t *nonce/*steal*/)
{
	struct ike_sa *ike = pexpect_ike_sa(ike_sa);
	if (ike == NULL) {
		return STF_INTERNAL_ERROR;
	}
	ldbg(ike->sa.logger, "%s() for "PRI_SO": calculated ke+nonce, sending I2",
	     __func__, pri_so(ike->sa.st_serialno));

	/*
	 * HDR out.
	 * We can't leave this to comm_handle() because the isa_np
	 * depends on the type of Auth (eventually).
	 */
	struct pbs_out rbody;
	ikev1_init_pbs_out_from_md_hdr(md, /*encrypt*/false, &reply_stream,
				       reply_buffer, sizeof(reply_buffer),
				       &rbody, ike->sa.logger);

	/* KE out */
	if (!ikev1_ship_KE(&ike->sa, local_secret, &ike->sa.st_gi, &rbody))
		return STF_INTERNAL_ERROR;

	/* Ni out */
	if (!ikev1_ship_nonce(&ike->sa.st_ni, nonce, &rbody, "Ni"))
		return STF_INTERNAL_ERROR;

	if (impair.bust_mi2) {
		/*
		 * generate a pointless large VID payload to push message
		 * over MTU
		 */
		struct pbs_out vid_pbs;

		/*
		 * This next payload value will get rewritten
		 * if ikev1_nat_traversal_add_natd is called.
		 */
		if (!ikev1_out_generic(&isakmp_vendor_id_desc,
					&rbody,
					&vid_pbs))
			return STF_INTERNAL_ERROR;

		if (!pbs_out_zero(&vid_pbs, 1500/*MTU?*/, "Filler VID")) {
			/* already logged */
			return STF_INTERNAL_ERROR;
		}

		close_output_pbs(&vid_pbs);
	}

	dbg("NAT-T checking st_nat_traversal");
	if (ike->sa.hidden_variables.st_nat_traversal != LEMPTY) {
		dbg("NAT-T found (implies NAT_T_WITH_NATD)");
		/* send two ISAKMP_NEXT_NATD_RFC* hash payloads to support NAT */
		if (!ikev1_nat_traversal_add_natd(&rbody, md))
			return STF_INTERNAL_ERROR;
	}

	/* finish message */
	if (!close_v1_message(&rbody, ike))
		return STF_INTERNAL_ERROR;

	/* Reinsert the state, using the responder cookie we just received */
	update_st_ike_spis_responder(ike, &md->hdr.isa_ike_responder_spi);

	/* outI2 is not encrypted */
	PEXPECT(ike->sa.logger, ike->sa.st_v1_phase_1_iv.len == 0); /*outI2*/
	return STF_OK;
}

/*
 * STATE_MAIN_R1:
 * PSK_AUTH, DS_AUTH: HDR, KE, Ni --> HDR, KE, Nr
 *
 * The following are not yet implemented:
 * PKE_AUTH: HDR, KE, [ HASH(1), ] <IDi1_b>PubKey_r, <Ni_b>PubKey_r
 *	    --> HDR, KE, <IDr1_b>PubKey_i, <Nr_b>PubKey_i
 * RPKE_AUTH:
 *	    HDR, [ HASH(1), ] <Ni_b>Pubkey_r, <KE_b>Ke_i, <IDi1_b>Ke_i
 *	    [,<<Cert-I_b>Ke_i]
 *	    --> HDR, <Nr_b>PubKey_i, <KE_b>Ke_r, <IDr1_b>Ke_r
 */

stf_status main_inI2_outR2(struct state *ike_sa, struct msg_digest *md)
{
	struct ike_sa *ike = pexpect_ike_sa(ike_sa);
	if (ike == NULL) {
		return STF_INTERNAL_ERROR;
	}
	ldbg(ike->sa.logger, "%s() for "PRI_SO"",
	     __func__, pri_so(ike->sa.st_serialno));

	/* KE in */
	if (!unpack_KE(&ike->sa.st_gi, "Gi", ike->sa.st_oakley.ta_dh,
		       md->chain[ISAKMP_NEXT_KE], ike->sa.logger)) {
		return STF_FAIL_v1N + v1N_INVALID_KEY_INFORMATION;
	}

	/* Ni in */
	RETURN_STF_FAIL_v1NURE(accept_v1_nonce(ike->sa.logger, md, &ike->sa.st_ni, "Ni"));

	/* decode certificate requests */
	decode_v1_certificate_requests(ike, md);

	ikev1_natd_init(ike, md);

	submit_ke_and_nonce(/*callback*/&ike->sa, /*task*/&ike->sa, md,
			    ike->sa.st_oakley.ta_dh,
			    main_inI2_outR2_continue1,
			    /*detach_whack*/false, HERE);
	return STF_SUSPEND;
}

static stf_status main_inI2_outR2_continue1(struct state *ike_sa,
					    struct msg_digest *md,
					    struct dh_local_secret *local_secret,
					    chunk_t *nonce)
{
	struct ike_sa *ike = pexpect_ike_sa(ike_sa);
	if (ike == NULL) {
		return STF_INTERNAL_ERROR;
	}
	ldbg(ike->sa.logger, "%s() for "PRI_SO": calculated ke+nonce, sending I2",
	     __func__, pri_so(ike->sa.st_serialno));

	passert(md != NULL);

	if (is_fips_mode() && ike->sa.st_oakley.ta_prf == NULL) {
		log_state(RC_LOG, &ike->sa,
			  "Missing prf - algo not allowed in fips mode (inI2_outR2)?");
		return STF_FAIL_v1N + v1N_SITUATION_NOT_SUPPORTED;
	}

	/* send CR if auth is RSA and no preloaded RSA public key exists*/
	bool send_cr = false;

	/* Build output packet HDR;KE;Nr */

	send_cr = (ike->sa.st_oakley.auth == OAKLEY_RSA_SIG) &&
		!remote_has_preloaded_pubkey(ike) &&
		ike->sa.st_connection->remote->host.config->ca.ptr != NULL;

	/* HDR out */
	struct pbs_out rbody;
	ikev1_init_pbs_out_from_md_hdr(md, /*encrypt*/false, &reply_stream,
				       reply_buffer, sizeof(reply_buffer),
				       &rbody, ike->sa.logger);

	/* KE out */
	passert(ikev1_ship_KE(&ike->sa, local_secret, &ike->sa.st_gr, &rbody));

	/* Nr out */
	if (!ikev1_ship_nonce(&ike->sa.st_nr, nonce, &rbody, "Nr"))
		return STF_INTERNAL_ERROR;

	if (impair.bust_mr2) {
		/*
		 * generate a pointless large VID payload to push
		 * message over MTU
		 */
		struct pbs_out vid_pbs;
		if (!ikev1_out_generic(&isakmp_vendor_id_desc, &rbody,
				       &vid_pbs))
			return STF_INTERNAL_ERROR;
		if (!pbs_out_zero(&vid_pbs, 1500/*MTU?*/, "Filler VID")) {
			/* already logged */
			return STF_INTERNAL_ERROR;
		}

		close_output_pbs(&vid_pbs);
	}

	/* CR out */
	if (send_cr) {
		if (is_permanent(ike->sa.st_connection)) {
			if (!ikev1_build_and_ship_CR(CERT_X509_SIGNATURE,
						     ike->sa.st_connection->remote->host.config->ca,
						     &rbody))
				return STF_INTERNAL_ERROR;
		} else {
			generalName_t *ca = collect_rw_ca_candidates(md->iface->ip_dev->local_address, IKEv1);

			if (ca != NULL) {
				generalName_t *gn;

				for (gn = ca; gn != NULL; gn = gn->next) {
					if (!ikev1_build_and_ship_CR(CERT_X509_SIGNATURE,
								     gn->name,
								     &rbody)) {
						free_generalNames(ca, false);
						return STF_INTERNAL_ERROR;
					}
				}
				free_generalNames(ca, false);
			} else {
				if (!ikev1_build_and_ship_CR(CERT_X509_SIGNATURE,
							     EMPTY_CHUNK,
							     &rbody))
					return STF_INTERNAL_ERROR;
			}
		}
	}

	if (ike->sa.hidden_variables.st_nat_traversal != LEMPTY) {
		/* send two ISAKMP_NEXT_NATD_RFC* hash payloads to support NAT */
		if (!ikev1_nat_traversal_add_natd(&rbody, md))
			return STF_INTERNAL_ERROR;
	}

	/* finish message */
	if (!close_v1_message(&rbody, ike))
		return STF_INTERNAL_ERROR;

	/*
	 * next message will be encrypted, so, we need to have the DH
	 * value calculated. We can do this in the background, sending
	 * the reply right away. We have to be careful on the next
	 * state, since the other end may reply faster than we can
	 * calculate things. If it is the case, then the packet is
	 * placed in the continuation, and we let the continuation
	 * process it. If there is a retransmit, we keep only the last
	 * packet.
	 *
	 * Also, note that this is not a suspended state, since we are
	 * actually just doing work in the background.  md will not be
	 * retained.
	 */
	dbg("main inI2_outR2: starting async DH calculation (group=%d)",
	    ike->sa.st_oakley.ta_dh->group);
	submit_dh_shared_secret(/*callback*/&ike->sa, /*task*/&ike->sa,
				/*no-md:in-background*/NULL,
				ike->sa.st_gi/*responder needs initiator's KE*/,
				main_inI2_outR2_continue2, HERE);
	/* we are calculating in the background, so it doesn't count */
	dbg("#%lu %s:%u ike->sa.st_calculating = false;", ike->sa.st_serialno, __func__, __LINE__);
	ike->sa.st_v1_offloaded_task_in_background = true;

	/* outR2 is not encrypted; but callback will be filling in IV */
	PEXPECT(ike->sa.logger, ike->sa.st_v1_phase_1_iv.len == 0); /*outR2*/
	return STF_OK;
}

/*
 * main_inI2_outR2_calcdone is unlike every other crypto_req_cont_func:
 * the state that it is working for may not yet care about the result.
 * We are precomputing the DH.
 * This also means that it isn't good at reporting an NSS error.
 */

static stf_status main_inI2_outR2_continue2(struct state *ike_sa,
					    struct msg_digest *null_md)
{
	struct ike_sa *ike = pexpect_ike_sa(ike_sa);
	if (ike == NULL) {
		return STF_INTERNAL_ERROR;
	}
	ldbg(ike->sa.logger, "%s() for "PRI_SO": after dh-shared",
	     __func__, pri_so(ike->sa.st_serialno));

	/*no-md:in-background*/
	PEXPECT(ike->sa.logger, null_md == NULL);
	ike->sa.st_v1_offloaded_task_in_background = false;

	/*
	 * Ignore error.  It will be handled handled when the next
	 * message arrives?!?
	 */
	if (ike->sa.st_dh_shared_secret != NULL) {
		update_v1_phase_1_iv(ike, calc_v1_skeyid_and_iv(ike), HERE);
		/* IV ready for inI3 */
		PEXPECT(ike->sa.logger, ike->sa.st_v1_phase_1_iv.len > 0); /*main_inI2_outR2_continue2*/
	}

	/*
	 * If there was a packet received while we were calculating,
	 * then process it now.
	 *
	 * Otherwise, the result awaits the packet.
	 */
	if (ike->sa.st_v1_background_md != NULL) {
		/* steal */
		struct msg_digest *md = ike->sa.st_v1_background_md;
		ike->sa.st_v1_background_md = NULL;
		/*
		 * This will call complete_v1_state_transition() when
		 * needed.
		 *
		 * Now that decryption has been completed, update the
		 * IV needed to decrypt.
		 */
		md->v1_decrypt_iv = ike->sa.st_v1_phase_1_iv;
		process_v1_packet_tail(ike, NULL/*no-child*/, md);
		md_delref(&md);
	}
	return STF_SKIP_COMPLETE_STATE_TRANSITION;
}

/*
 * STATE_MAIN_I2:
 * SMF_PSK_AUTH: HDR, KE, Nr --> HDR*, IDi1, HASH_I
 * SMF_DS_AUTH: HDR, KE, Nr --> HDR*, IDi1, [ CERT, ] SIG_I
 *
 * The following are not yet implemented.
 * SMF_PKE_AUTH: HDR, KE, <IDr1_b>PubKey_i, <Nr_b>PubKey_i
 *	    --> HDR*, HASH_I
 * SMF_RPKE_AUTH: HDR, <Nr_b>PubKey_i, <KE_b>Ke_r, <IDr1_b>Ke_r
 *	    --> HDR*, HASH_I
 */

stf_status main_inR2_outI3(struct state *ike_sa, struct msg_digest *md)
{
	struct ike_sa *ike = pexpect_ike_sa(ike_sa);
	if (ike == NULL) {
		return STF_INTERNAL_ERROR;
	}
	ldbg(ike->sa.logger, "%s() for "PRI_SO, __func__, pri_so(ike->sa.st_serialno));

	/*
	 * XXX: have we been here before?
	 *
	 * Should this end rejects R2 because of auth failure, the
	 * other end will keep sending the same KE.  Which leads to a
	 * pexpect() as .st_dh_shared_secret et.al. are all expected
	 * to be empty.
	 *
	 * XXX: this seems lame, can the state machine detect and
	 * rejected the duplicate packet?
	 */
	symkey_delref(ike->sa.logger, "DH shared secret", &ike->sa.st_dh_shared_secret);
	symkey_delref(ike->sa.logger, "skeyid", &ike->sa.st_skeyid_nss);
	symkey_delref(ike->sa.logger, "skeyid_d", &ike->sa.st_v1_isakmp_skeyid_d);
	symkey_delref(ike->sa.logger, "skeyid_a", &ike->sa.st_skeyid_a_nss);
	symkey_delref(ike->sa.logger, "skeyid_e", &ike->sa.st_skeyid_e_nss);
	symkey_delref(ike->sa.logger, "enc_key", &ike->sa.st_enc_key_nss);

	/* KE in */
	if (!unpack_KE(&ike->sa.st_gr, "Gr", ike->sa.st_oakley.ta_dh,
		       md->chain[ISAKMP_NEXT_KE], ike->sa.logger)) {
		return STF_FAIL_v1N + v1N_INVALID_KEY_INFORMATION;
	}

	/* Nr in */
	RETURN_STF_FAIL_v1NURE(accept_v1_nonce(ike->sa.logger, md, &ike->sa.st_nr, "Nr"));
	submit_dh_shared_secret(/*callback*/&ike->sa, /*task*/&ike->sa, md,
				ike->sa.st_gr, main_inR2_outI3_continue, HERE);
	return STF_SUSPEND;
}

static stf_status main_inR2_outI3_continue(struct state *ike_sa,
					   struct msg_digest *md)
{
	struct ike_sa *ike = pexpect_ike_sa(ike_sa);
	if (ike == NULL) {
		return STF_INTERNAL_ERROR;
	}
	ldbg(ike->sa.logger, "%s() for "PRI_SO": finished DH shared",
	     __func__, pri_so(ike->sa.st_serialno));

	passert(md != NULL);	/* ??? how would this fail? */

	if (ike->sa.st_dh_shared_secret == NULL) {
		return STF_FAIL_v1N + v1N_INVALID_KEY_INFORMATION;
	}

	/* ready for encrypted outI3 */
	update_v1_phase_1_iv(ike, calc_v1_skeyid_and_iv(ike), HERE); /*main_inR2_outI3_continue*/
	PEXPECT(ike->sa.logger, ike->sa.st_v1_phase_1_iv.len > 0); /*main_inR2_outI3_continue*/

	struct pbs_out rbody[1]; /* hack */
	ikev1_init_pbs_out_from_md_hdr(md, /*encrypt*/true, &reply_stream,
				       reply_buffer, sizeof(reply_buffer),
				       rbody, ike->sa.logger);

	const struct connection *c = ike->sa.st_connection;
	const struct cert *mycert = c->local->host.config->cert.nss_cert != NULL ? &c->local->host.config->cert : NULL;

	/* decode certificate requests */
	decode_v1_certificate_requests(ike, md);
	bool cert_requested = (ike->sa.st_v1_requested_ca != NULL);

	/*
	 * send certificate if we have one and auth is RSA, and we were
	 * told we can send one if asked, and we were asked, or we were told
	 * to always send one.
	 */
	bool send_cert = (ike->sa.st_oakley.auth == OAKLEY_RSA_SIG && mycert != NULL &&
			  ((c->local->host.config->sendcert == SENDCERT_IFASKED && cert_requested) ||
			   (c->local->host.config->sendcert == SENDCERT_ALWAYS)));

	bool send_authcerts = (send_cert &&
			       c->config->send_ca != CA_SEND_NONE);

	/* must free_auth_chain(auth_chain, chain_len); */
	chunk_t auth_chain[MAX_CA_PATH_LEN] = { { NULL, 0 } };
	int chain_len = get_auth_chain(auth_chain, MAX_CA_PATH_LEN, mycert, c->config->send_ca);

	ldbg_doi_cert_thinking(ike, cert_ike_type(mycert),
			       cert_requested, send_cert, chain_len);

	/*
	 * send certificate request, if we don't have a preloaded RSA
	 * public key
	 */
	bool send_cr = send_cert && !remote_has_preloaded_pubkey(ike);

	dbg(" I am %ssending a certificate request",
	    send_cr ? "" : "not ");

	/* done parsing; initialize crypto */

	ikev1_natd_init(ike, md);

	/*
	 * Build output packet HDR*;IDii;HASH/SIG_I
	 *
	 * ??? NOTE: this is almost the same as main_inI3_outR3's code
	 */

	/* HDR* out done */

	/* IDii out */
	struct pbs_out id_pbs; /* ID Payload; used later for hash calculation */
	enum next_payload_types_ikev1 auth_payload =
		ike->sa.st_oakley.auth == OAKLEY_PRESHARED_KEY ?
			ISAKMP_NEXT_HASH : ISAKMP_NEXT_SIG;

	{
		/*
		 * id_hd should be struct isakmp_id, but struct isakmp_ipsec_id
		 * allows build_id_payload() to work for both phases.
		 */
		shunk_t id_b;
		struct isakmp_ipsec_id id_hd = build_v1_id_payload(&c->local->host, &id_b);
		if (!out_struct(&id_hd,
				&isakmp_ipsec_identification_desc,
				rbody,
				&id_pbs) ||
		    !out_hunk(id_b, &id_pbs, "my identity")) {
			free_auth_chain(auth_chain, chain_len);
			return STF_INTERNAL_ERROR;
		}

		close_output_pbs(&id_pbs);
	}

	/* CERT out */
	if (send_cert && impair.send_pkcs7_thingie) {
		llog(RC_LOG, ike->sa.logger, "IMPAIR: sending cert as pkcs7 blob");
		SECItem *pkcs7 = nss_pkcs7_blob(mycert, send_authcerts);
		if (!pexpect(pkcs7 != NULL)) {
			free_auth_chain(auth_chain, chain_len);
			return STF_INTERNAL_ERROR;
		}
		if (!ikev1_ship_CERT(CERT_PKCS7_WRAPPED_X509,
				     same_secitem_as_shunk(*pkcs7),
				     rbody)) {
			SECITEM_FreeItem(pkcs7, PR_TRUE);
			free_auth_chain(auth_chain, chain_len);
			return STF_INTERNAL_ERROR;
		}
	} else if (send_cert) {
		log_state(RC_LOG, &ike->sa, "I am sending my cert");

		if (!ikev1_ship_CERT(cert_ike_type(mycert), cert_der(mycert), rbody)) {
			free_auth_chain(auth_chain, chain_len);
			return STF_INTERNAL_ERROR;
		}

		if (send_authcerts) {
			/* we've got CA certificates to send */
			llog(RC_LOG, ike->sa.logger, "I am sending a CA cert chain");
			if (!ikev1_ship_chain(auth_chain,
					      chain_len,
					      rbody,
					      cert_ike_type(mycert))) {
				free_auth_chain(auth_chain, chain_len);
				return STF_INTERNAL_ERROR;
			}
		}
	}

	free_auth_chain(auth_chain, chain_len);

	/***** obligation to free_auth_chain has been discharged *****/

	/* CR out */
	if (send_cr) {
		llog(RC_LOG, ike->sa.logger, "I am sending a certificate request");
		if (!ikev1_build_and_ship_CR(cert_ike_type(mycert),
					     c->remote->host.config->ca,
					     rbody))
			return STF_INTERNAL_ERROR;
	}

	/* HASH_I or SIG_I out */
	{
		struct crypt_mac hash = main_mode_hash(ike, SA_INITIATOR,
						       pbs_out_all(&id_pbs));

		if (auth_payload == ISAKMP_NEXT_HASH) {
			/* HASH_I out */
			if (!ikev1_out_generic_raw(&isakmp_hash_desc,
						   rbody,
						   hash.ptr, hash.len, "HASH_I"))
				return STF_INTERNAL_ERROR;
		} else {
			/* SIG_I out */
			struct hash_signature sig;
			sig = v1_sign_hash_RSA(c, &hash, ike->sa.logger);
			if (sig.len == 0) {
				/* already logged */
				return STF_FAIL_v1N + v1N_AUTHENTICATION_FAILED;
			}

			if (!ikev1_out_generic_raw(&isakmp_signature_desc,
						   rbody,
						   sig.ptr, sig.len,
						   "SIG_I"))
				return STF_INTERNAL_ERROR;
		}
	}

	/*
	 * Mindlessly send INITIAL_CONTACT when enabled.  Old comment
	 * follows:
	 *
	 * We are INITIATOR in I2, this is not a Quick Mode rekey, so
	 * if there is a phase2 that we have for which the phase1
	 * expired, this state has no way of finding out, so this
	 * would mean adding the payload, which would destroy the
	 * remote phase2, and cause downtime until we establish the
	 * new phase2. It is better not to send this payload, which is
	 * why the per-connection keyword default for initial_contact
	 * is 'no'.  But some interop with Cisco requires this.
	 *
	 * In Quick Mode, we need to do a little more work, but that's
	 * in ikev1_quick.c
	 */
	if (c->config->send_initial_contact) {
		llog(RC_LOG, ike->sa.logger, "sending INITIAL_CONTACT");
		if (!emit_v1N_IPSEC_INITIAL_CONTACT(rbody, ike)) {
			return STF_INTERNAL_ERROR;
		}
	} else {
		pdbg(ike->sa.logger, "Not sending INITIAL_CONTACT");
	}

	/* encrypt message, except for fixed part of header */

	/* stores updated IV in .st_v1_phase_1_iv */
	if (!close_and_encrypt_v1_message(ike, rbody, &ike->sa.st_v1_phase_1_iv)) {
		return STF_INTERNAL_ERROR; /* ??? we may be partly committed */
	}

	/* outI3 is encrypted */
	PEXPECT(ike->sa.logger, ike->sa.st_v1_phase_1_iv.len > 0); /*outI3*/
	return STF_OK;
}

/*
 * STATE_MAIN_R2:
 * PSK_AUTH: HDR*, IDi1, HASH_I --> HDR*, IDr1, HASH_R
 * DS_AUTH: HDR*, IDi1, [ CERT, ] SIG_I --> HDR*, IDr1, [ CERT, ] SIG_R
 * PKE_AUTH, RPKE_AUTH: HDR*, HASH_I --> HDR*, HASH_R
 */

stf_status main_inI3_outR3(struct state *ike_sa, struct msg_digest *md)
{
	struct ike_sa *ike = pexpect_ike_sa(ike_sa);
	if (ike == NULL) {
		return STF_INTERNAL_ERROR;
	}
	ldbg(ike->sa.logger, "%s() for "PRI_SO, __func__, pri_so(ike->sa.st_serialno));

	/* inI3 is encrypted */
	PEXPECT(ike->sa.logger, md->v1_decrypt_iv.len > 0); /*inI3*/
	update_v1_phase_1_iv(ike, md->v1_decrypt_iv, HERE); /*inI3*/

	pexpect(&ike->sa == md->v1_st);

	/* handle case where NSS balked at generating DH */
	if (ike->sa.st_dh_shared_secret == NULL)
		return STF_FAIL_v1N + v1N_INVALID_KEY_INFORMATION;

	if (!v1_decode_certs(md)) {
		llog(RC_LOG, ike->sa.logger, "X509: CERT payload bogus or revoked");
		return STF_FAIL_v1N + v1N_INVALID_ID_INFORMATION;
	}

	/*
	 * ID Payload in.
	 *
	 * Note: may switch the connection being used!  We are a Main
	 * Mode Responder.
	 */

	if (!ikev1_decode_peer_id_main_mode_responder(ike, md)) {
		dbg("Peer ID failed to decode");
		return STF_FAIL_v1N + v1N_INVALID_ID_INFORMATION;
	}

	/* HASH_I or SIG_I */

	/* responder authenticating initiator */
	stf_status r = oakley_auth(ike, md, SA_INITIATOR, pbs_in_all(&md->chain[ISAKMP_NEXT_ID]->pbs));
	if (r != STF_OK) {
		return r;
	}

	struct connection *c = ike->sa.st_connection; /* may have changed */

	/* send certificate if we have one and auth is RSA */
	const struct cert *mycert = c->local->host.config->cert.nss_cert != NULL ? &c->local->host.config->cert : NULL;

	pexpect(ike->sa.st_clonedfrom == SOS_NOBODY); /* ISAKMP */
	bool cert_requested = (ike->sa.st_v1_requested_ca != NULL);
	bool send_cert = (ike->sa.st_oakley.auth == OAKLEY_RSA_SIG && mycert != NULL &&
			  ((c->local->host.config->sendcert == SENDCERT_IFASKED && cert_requested) ||
			   (c->local->host.config->sendcert == SENDCERT_ALWAYS)));

	bool send_authcerts = (send_cert && c->config->send_ca != CA_SEND_NONE);

	/* Must free_auth_chain(auth_chain, chain_len); */
	chunk_t auth_chain[MAX_CA_PATH_LEN] = { { NULL, 0 } };
	int chain_len = get_auth_chain(auth_chain, MAX_CA_PATH_LEN, mycert, c->config->send_ca);

	ldbg_doi_cert_thinking(ike, cert_ike_type(mycert),
			       cert_requested, send_cert, chain_len);

	/*
	 * Build output packet HDR*;IDir;HASH/SIG_R
	 *
	 * proccess_packet() would automatically generate the HDR*
	 * payload if smc->first_out_payload is not ISAKMP_NEXT_NONE.
	 * We don't do this because we wish there to be no partially
	 * built output packet if we need to suspend for asynch DNS.
	 *
	 * ??? NOTE: this is almost the same as main_inR2_outI3's code
	 */

	/*
	 * HDR* out
	 * If auth were PKE_AUTH or RPKE_AUTH, ISAKMP_NEXT_HASH would
	 * be first payload.
	 */
	struct pbs_out rbody;
	ikev1_init_pbs_out_from_md_hdr(md, /*encrypt*/true, &reply_stream,
				       reply_buffer, sizeof(reply_buffer),
				       &rbody, ike->sa.logger);

	enum next_payload_types_ikev1 auth_payload = ike->sa.st_oakley.auth == OAKLEY_PRESHARED_KEY ?
		ISAKMP_NEXT_HASH : ISAKMP_NEXT_SIG;

	/* IDir out */
	struct pbs_out r_id_pbs; /* ID Payload; used later for hash calculation */

	{
		/*
		 * id_hd should be struct isakmp_id, but struct isakmp_ipsec_id
		 * allows build_id_payload() to work for both phases.
		 */
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

	/* CERT out, if we have one */
	if (send_cert && impair.send_pkcs7_thingie) {
		llog(RC_LOG, ike->sa.logger, "IMPAIR: sending cert as pkcs7 blob");
		SECItem *pkcs7 = nss_pkcs7_blob(mycert, send_authcerts);
		if (!pexpect(pkcs7 != NULL)) {
			free_auth_chain(auth_chain, chain_len);
			return STF_INTERNAL_ERROR;
		}
		if (!ikev1_ship_CERT(CERT_PKCS7_WRAPPED_X509,
				     same_secitem_as_shunk(*pkcs7),
				     &rbody)) {
			SECITEM_FreeItem(pkcs7, PR_TRUE);
			free_auth_chain(auth_chain, chain_len);
			return STF_INTERNAL_ERROR;
		}
	} else if (send_cert) {
		llog(RC_LOG, ike->sa.logger, "I am sending my cert");
		if (!ikev1_ship_CERT(cert_ike_type(mycert), cert_der(mycert), &rbody)) {
			free_auth_chain(auth_chain, chain_len);
			return STF_INTERNAL_ERROR;
		}

		if (send_authcerts) {
			llog(RC_LOG, ike->sa.logger, "I am sending a CA cert chain");
			if (!ikev1_ship_chain(auth_chain, chain_len,
					      &rbody, cert_ike_type(mycert))) {
				free_auth_chain(auth_chain, chain_len);
				return STF_INTERNAL_ERROR;
			}
		}
	}

	free_auth_chain(auth_chain, chain_len);

	/***** obligation to free_auth_chain has been discharged *****/

	/* IKEv2 NOTIFY payload */

	/* HASH_R or SIG_R out */
	{
		struct crypt_mac hash = main_mode_hash(ike, SA_RESPONDER,
						       pbs_out_all(&r_id_pbs));

		if (auth_payload == ISAKMP_NEXT_HASH) {
			/* HASH_R out */
			if (!ikev1_out_generic_raw(&isakmp_hash_desc, &rbody,
						   hash.ptr, hash.len, "HASH_R"))
				return STF_INTERNAL_ERROR;
		} else {
			/* SIG_R out */
			struct hash_signature sig;
			sig = v1_sign_hash_RSA(c, &hash, ike->sa.logger);
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

	/*
	 * Assume initial contact when the peer needs, but doesn't yet
	 * have, a lease.  This assumes that there will be no further
	 * connection switches. The main-mode and Quick exchanges that
	 * follow also use this connection.  If that isn't the case,
	 * oops!
	 *
	 * For instance:
	 *
	 * + a road-warrior (instance) connection is established;
	 *   during this a lease is assigned using mode-config
	 *
	 * + the road-warrior goes to sleep; since it no longer
	 *   responds to DPD this end tears down the connection
	 *   throwing away the instance and lease
	 *
	 * + the road-warrior wakes up; it initiates a new ISAKMP SA
	 *   so that, presumably, it can reauth/rekey the connection;
	 *   Since the exchange has no INITIAL_CONTACT the peer
	 *   assumes its lease is still valid and mode-config can be
	 *   skipped
	 *
	 * As a result this end never assigns a lease.  This leaves
	 * the SPD uninitialized (well 0/0).  In v4 the SPD was left
	 * containing the equally bogus HOST address!
	 *
	 * This end rebooting will have a similar effect.
	 *
	 * Hence, in an attempt to prod the peer into asking for a new
	 * lease using a mode-config exchange, send INITIAL_CONTACT.
	 *
	 * XXX: IKEv1 only implements IPv4 leases.
	 */
	if (!c->config->send_initial_contact) {
		pdbg(ike->sa.logger, "responder is not sending IPSEC_INITIAL_CONTACT; initial-contact=false");
	} else if (!c->local->config->host.modecfg.server) {
		pdbg(ike->sa.logger, "responder is not sending IPSEC_INITIAL_CONTACT; local is not a modecfg server");
	} else if (c->remote->config->child.addresspools.len == 0) {
		pdbg(ike->sa.logger, "responder is not sending IPSEC_INITIAL_CONTACT; remote has no IPv4 addresspool range");
	} else if (c->remote->child.lease[IPv4_INDEX].is_set) {
		pdbg(ike->sa.logger, "responder is not sending IPSEC_INITIAL_CONTACT; remote already has a lease");
	} else {
		pdbg(ike->sa.logger, "responder is sending IPSEC_INITIAL_CONTACT; remote initiator needs to ask for a lease");
		if (!emit_v1N_IPSEC_INITIAL_CONTACT(&rbody, ike)) {
			return STF_INTERNAL_ERROR;
		}
	}

	/* encrypt message, sans fixed part of header */

	/* stores updated IV in .st_v1_phase_1_iv */
	if (!close_and_encrypt_v1_message(ike, &rbody, &ike->sa.st_v1_phase_1_iv)) {
		return STF_INTERNAL_ERROR; /* ??? we may be partly committed */
	}

	ldbg(ike->sa.logger, "phase1 IV finished");

	/*
	 * It seems as per Cisco implementation, XAUTH and MODECFG
	 * are not supposed to be performed again during rekey
	 */

	if (c->config->host.cisco.peer &&
	    c->established_ike_sa != SOS_NOBODY &&
	    c->local->host.config->xauth.client) {
		dbg("Skipping XAUTH for rekey for Cisco Peer compatibility.");
		ike->sa.hidden_variables.st_xauth_client_done = true;
		ike->sa.st_oakley.doing_xauth = false;

		if (c->local->host.config->modecfg.client) {
			dbg("Skipping ModeCFG for rekey for Cisco Peer compatibility.");
			ike->sa.hidden_variables.st_modecfg_vars_set = true;
			ike->sa.hidden_variables.st_modecfg_started = true;
		}
	}

	ISAKMP_SA_established(ike);

	/* outR3 is encrypted */
	PEXPECT(ike->sa.logger, ike->sa.st_v1_phase_1_iv.len > 0); /*outR3*/
	return STF_OK;
}

/*
 * STATE_MAIN_I3:
 * Handle HDR*;IDir;HASH/SIG_R from responder.
 *
 */

stf_status main_inR3(struct state *ike_sa, struct msg_digest *md)
{
	struct ike_sa *ike = pexpect_ike_sa(ike_sa);
	if (ike == NULL) {
		return STF_INTERNAL_ERROR;
	}
	ldbg(ike->sa.logger, "%s() for "PRI_SO, __func__, pri_so(ike->sa.st_serialno));

	/*
	 * save last IV from phase 1 so it can be restored later so anything
	 * between the end of phase 1 and the start of phase 2 i.e. mode config
	 * payloads etc. will not lose our IV
	 */
	/* inR3 is encrypted */
	PEXPECT(ike->sa.logger, md->v1_decrypt_iv.len > 0); /*inR3*/
	update_v1_phase_1_iv(ike, md->v1_decrypt_iv, HERE);
	ldbg(ike->sa.logger, "phase1 IV finalized");

	if (!v1_decode_certs(md)) {
		llog(RC_LOG, ike->sa.logger, "X509: CERT payload bogus or revoked");
		return STF_FAIL_v1N + v1N_INVALID_ID_INFORMATION;
	}

	/*
	 * ID Payload in.
	 *
	 * Note: will not switch the connection being used because we
	 * are the initiator.
	 */

	struct connection *c = ike->sa.st_connection;

	if (!ikev1_decode_peer_id_initiator(ike, md)) {
		dbg("Peer ID failed to decode");
		return STF_FAIL_v1N + v1N_INVALID_ID_INFORMATION;
	}

	passert(c == ike->sa.st_connection); /* no switch */

	/* HASH_R or SIG_R */

	/* initiator authenticating responder */
	stf_status r = oakley_auth(ike, md, SA_RESPONDER, pbs_in_all(&md->chain[ISAKMP_NEXT_ID]->pbs));
	if (r != STF_OK) {
		return r;
	}

	/* Done input */

	/*
	 * It seems as per Cisco implementation, XAUTH and MODECFG
	 * are not supposed to be performed again during rekey
	 */
	if (c->config->host.cisco.peer &&
	    c->established_ike_sa != SOS_NOBODY &&
	    c->local->host.config->xauth.client) {
		dbg("Skipping XAUTH for rekey for Cisco Peer compatibility.");
		ike->sa.hidden_variables.st_xauth_client_done = true;
		ike->sa.st_oakley.doing_xauth = false;

		if (c->local->host.config->modecfg.client) {
			dbg("Skipping ModeCFG for rekey for Cisco Peer compatibility.");
			ike->sa.hidden_variables.st_modecfg_vars_set = true;
			ike->sa.hidden_variables.st_modecfg_started = true;
		}
	}

	ISAKMP_SA_established(ike);

	PEXPECT(ike->sa.logger, ike->sa.st_v1_phase_1_iv.len > 0); /*main_inR3*/
	return STF_OK;
}
