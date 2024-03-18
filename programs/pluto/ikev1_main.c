/*
 * IPsec DOI and Oakley resolution routines
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
#include "fetch.h"
#include "asn1.h"
#include "pending.h"
#include "ikev1_hash.h"
#include "crypt_symkey.h"		/* for release_symkey() */

#include "crypto.h"
#include "secrets.h"
#include "lswnss.h"

#include "ike_alg.h"
#include "ike_alg_encrypt_ops.h"	/* XXX: oops */
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
#ifdef USE_XFRM_INTERFACE
# include "kernel_xfrm_interface.h"
#endif
#include "unpack.h"
#include "ikev1_host_pair.h"
#include "ikev1_peer_id.h"
#include "lswnss.h"
#include "ikev1_vendorid.h"
#include "ikev1_cert.h"
#include "terminate.h"

static bool emit_message_padding(struct pbs_out *pbs, const struct state *st);

/*
 * Initiate an Oakley Main Mode exchange.
 * --> HDR;SA
 * Note: this is not called from demux.c
 */

struct ike_sa *main_outI1(struct connection *c,
			  struct ike_sa *predecessor,
			  lset_t policy,
			  const threadtime_t *inception,
			  bool background)
{
	struct ike_sa *ike = new_v1_istate(c, STATE_MAIN_I1);
	if (ike == NULL) {
		return NULL;
	}

	struct state *st = &ike->sa;
	statetime_t start = statetime_backdate(st, inception);

	if (policy != LEMPTY) {
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
	reply_stream = open_pbs_out("reply packet", reply_buffer, sizeof(reply_buffer), st->logger);

	/* HDR out */
	struct pbs_out rbody;
	{
		struct isakmp_hdr hdr = {
			.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
				ISAKMP_MINOR_VERSION,
			.isa_xchg = ISAKMP_XCHG_IDPROT,
		};
		hdr.isa_ike_initiator_spi = st->st_ike_spis.initiator;
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

		if (!ikev1_out_sa(&rbody,
				  IKEv1_oakley_main_mode_db_sa(c),
				  st, true, false)) {
			log_state(RC_LOG, st, "outsa fail");
			/* leak!?! */
			return NULL;
		}

		/* no leak! (MUST be first time) */
		passert(st->st_p1isa.ptr == NULL);

		/* save initiator SA for later HASH */
		st->st_p1isa = clone_bytes_as_chunk(sa_start, rbody.cur - sa_start,
						    "sa in main_outI1");
	}

	/* send Vendor IDs */
	if (!out_v1VID_set(&rbody, c)) {
		return NULL;
	}

	/* as Initiator, spray NAT VIDs */
	if (!nat_traversal_insert_vid(&rbody, c)) {
		return NULL;
	}

	if (!ikev1_close_message(&rbody, st)) {
		return NULL;
	}

	close_output_pbs(&reply_stream);

	/* Transmit */
	record_and_send_v1_ike_msg(st, &reply_stream,
		"reply packet for main_outI1");

	delete_event(st);
	clear_retransmits(st);
	start_retransmits(st);

	if (predecessor != NULL) {
		move_pending(predecessor, pexpect_ike_sa(st));
		llog_sa(RC_LOG, ike, "%s, replacing "PRI_SO,
			st->st_state->story,
			pri_so(predecessor->sa.st_serialno));
	} else {
		llog_sa(RC_LOG, ike, "%s", st->st_state->story);
	}

	statetime_stop(&start, "%s()", __func__);
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

static void main_mode_hash_body(struct state *st,
				enum sa_role role,
				shunk_t id_payload, /* ID payload, including header */
				struct crypt_prf *ctx)
{
	switch (role) {
	case SA_INITIATOR:
		crypt_prf_update_hunk(ctx, "gi", st->st_gi);
		crypt_prf_update_hunk(ctx, "gr", st->st_gr);
		crypt_prf_update_thing(ctx, "initiator", st->st_ike_spis.initiator);
		crypt_prf_update_thing(ctx, "responder", st->st_ike_spis.responder);
		break;
	case SA_RESPONDER:
		crypt_prf_update_hunk(ctx, "gr", st->st_gr);
		crypt_prf_update_hunk(ctx, "gi", st->st_gi);
		crypt_prf_update_thing(ctx, "respoder", st->st_ike_spis.responder);
		crypt_prf_update_thing(ctx, "initiator", st->st_ike_spis.initiator);
		break;
	default:
		bad_case(role);
	}

	if (DBGP(DBG_CRYPT)) {
		DBG_log("hashing %zu bytes of SA",
			st->st_p1isa.len - sizeof(struct isakmp_generic));
	}

	/* SA_b */
	crypt_prf_update_bytes(ctx, "p1isa",
			       st->st_p1isa.ptr + sizeof(struct isakmp_generic),
			       st->st_p1isa.len - sizeof(struct isakmp_generic));

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

struct crypt_mac main_mode_hash(struct state *st,
				enum sa_role role,
				shunk_t id_payload) /* ID payload, including header */
{
	struct crypt_prf *ctx = crypt_prf_init_symkey("main mode",
						      st->st_oakley.ta_prf,
						      "skeyid", st->st_skeyid_nss,
						      st->logger);
	main_mode_hash_body(st, role, id_payload, ctx);
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
	const struct secret_stuff *pks = get_local_private_key(c, &pubkey_type_rsa,
								    logger);
	if (pks == NULL) {
		llog(RC_LOG_SERIOUS, logger,
			    "unable to locate my private key for RSA Signature");
		return (struct hash_signature) { .len = 0, }; /* failure: no key to use */
	}

	struct hash_signature sig = pubkey_signer_raw_rsa.sign_hash(pks, hash->ptr, hash->len,
								    &ike_alg_hash_sha1, logger);
	return sig;
}

/*
 * encrypt message, sans fixed part of header
 * IV is fetched from st->st_new_iv and stored into st->st_iv.
 * The theory is that there will be no "backing out", so we commit to IV.
 * We also close the pbs.
 */
bool ikev1_close_and_encrypt_message(struct pbs_out *pbs, struct state *st)
{
	const struct encrypt_desc *e = st->st_oakley.ta_encrypt;

	/*
	 * Pad the message (header and body) to message alignment
	 * which is normally 4-bytes.
	 */

	if (!emit_message_padding(pbs, st)) {
		/* already logged */
		return false; /*fatal*/
	}

	/*
	 * Next pad the encrypted part of the payload so it is
	 * alligned with the encryption's blocksize.
	 *
	 * Since the header is isn't encrypted, this doesn't include
	 * the header.  See the description associated with the
	 * definition of struct isakmp_hdr in packet.h.
	 *
	 * The alignment is probably 16-bytes, but can be 1-byte!
	 */
	shunk_t message = pbs_out_all(pbs);
	shunk_t unpadded_encrypt = hunk_slice(message, sizeof(struct isakmp_hdr), message.len);
	size_t encrypt_padding = pad_up(unpadded_encrypt.len, e->enc_blocksize);
	if (encrypt_padding != 0) {
		if (!pbs_out_zero(pbs, encrypt_padding, "encryption padding")) {
			/* already logged */
			return false; /*fatal*/
		}
	}

	/*
	 * Now mark out the block that will be encrypted.
	 *
	 * Hack to get at writeable buffer!  IKEv2 does something
	 * vaguely similar.
	 */
	chunk_t padded_message = chunk2(pbs->start, pbs_out_all(pbs).len);
	chunk_t padded_encrypt = hunk_slice(padded_message,
					    sizeof(struct isakmp_hdr),
					    padded_message.len);

	PASSERT(st->logger, st->st_v1_new_iv.len >= e->enc_blocksize);
	st->st_v1_new_iv.len = e->enc_blocksize;   /* truncate */

	/*
	 * Finally, re-pad the entire message (header and body) to
	 * message alignment.
	 *
	 * This should be a no-op?
	 *
	 * XXX: note the double padding (tripple if you count the code
	 * paths that call ikev1_close_message() before encrypting.
	 */

	if (!emit_message_padding(pbs, st)) {
		/* already logged */
		return false; /*fatal*/
	}

	close_output_pbs(pbs);

	/* XXX: not ldbg(pbs->logger) as can be NULL */
	dbg("encrypt unpadded %zu padding %zu padded %zu bytes",
	    unpadded_encrypt.len, encrypt_padding, padded_encrypt.len);
	if (DBGP(DBG_CRYPT)) {
		DBG_dump("encrypting:", padded_encrypt.ptr, padded_encrypt.len);
		DBG_dump_hunk("IV:", st->st_v1_new_iv);
	}

	e->encrypt_ops->do_crypt(e, padded_encrypt.ptr, padded_encrypt.len,
				 st->st_enc_key_nss,
				 st->st_v1_new_iv.ptr, true,
				 st->logger);

	update_iv(st);
	if (DBGP(DBG_CRYPT)) {
		DBG_dump_hunk("next IV:", st->st_v1_iv);
	}

	return true;
}

/*
 * In IKEv1, some implementations (including freeswan/openswan/libreswan)
 * interpreted the RFC that the whole IKE message must padded to a multiple
 * of 4 octets, but other implementations (i.e. Checkpoint in Aggressive Mode)
 * drop padded IKE packets. Some of the text on this topic can be found in the
 * IKEv1 RFC 2408 section 3.6 Transform Payload.
 *
 * The ikepad= option can be set to yes or no on a per-connection basis,
 * and defaults to yes.
 *
 * In IKEv2, there is no padding specified in the RFC and some implementations
 * will reject IKEv2 messages that are padded. As there are no known IKEv2
 * clients that REQUIRE padding, padding is never done for IKEv2. If IKEv2
 * clients are discovered in the wild, we will revisit this - please contact
 * the libreswan developers if you find such an implementation.
 * Therefore the ikepad= option has no effect on IKEv2 connections.
 *
 * @param pbs PB Stream
 */

static bool emit_message_padding(struct pbs_out *pbs, const struct state *st)
{
	size_t padding = pad_up(pbs_out_all(pbs).len, 4);
	if (padding == 0) {
		ldbg(st->logger, "no IKEv1 message padding required");
	} else if (!st->st_connection->config->ikepad) {
		ldbg(st->logger, "IKEv1 message padding of %zu bytes skipped by policy",
		     padding);
	} else {
		ldbg(st->logger, "padding IKEv1 message with %zu bytes", padding);
		if (!pbs_out_zero(pbs, padding, "message padding")) {
			/* already logged */
			return false; /*fatal*/
		}
	}
	return true;
}

bool ikev1_close_message(struct pbs_out *pbs, const struct state *st)
{
	if (pbad(st == NULL)) {
		return false;
	}

	if (!emit_message_padding(pbs, st)) {
		/* already logged */
		return false; /*fatal*/
	}

	close_output_pbs(pbs);
	return true;
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

stf_status main_inI1_outR1(struct state *unused_st UNUSED,
			   struct msg_digest *md)
{
	/* ??? this code looks a lot like the middle of ikev2_parent_inI1outR1 */
	struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_SA];
	struct pbs_out r_sa_pbs;

	if (drop_new_exchanges()) {
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
	struct state *st = md->v1_st = &ike->sa;

	/* delref stack connection pointer */
	connection_delref(&c, md->logger);
	c = ike->sa.st_connection;

	passert(!st->st_oakley.doing_xauth);

	/* only as accurate as connection */
	st->st_policy = LEMPTY;
	change_v1_state(st, STATE_MAIN_R0);

	binlog_refresh_state(st);

	merge_quirks(st, md);

	set_nat_traversal(st, md);

	if (DBGP(DBG_BASE)) {
		DBG_dump_thing("  ICOOKIE-DUMP:", st->st_ike_spis.initiator);
	}

	if (is_instance(c)) {
		endpoint_buf b;
		log_state(RC_LOG, st, "responding to Main Mode from unknown peer %s",
			  str_endpoint_sensitive(&md->sender, &b));
	} else {
		log_state(RC_LOG, st, "responding to Main Mode");
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
	reply_stream = open_pbs_out("reply packet", reply_buffer, sizeof(reply_buffer), st->logger);
	struct pbs_out rbody;
	{
		struct isakmp_hdr hdr = md->hdr;

		hdr.isa_flags = 0; /* clear all flags */
		hdr.isa_ike_responder_spi = st->st_ike_spis.responder;
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
						&r_sa_pbs, false, st));

	/* send Vendor IDs */
	if (!out_v1VID_set(&rbody, c))
		return STF_INTERNAL_ERROR;

	/* as Responder, send best NAT VID we received */
	if (st->hidden_variables.st_nat_traversal != LEMPTY) {
		if (!out_v1VID(&rbody, md->quirks.qnat_traversal_vid))
			return STF_INTERNAL_ERROR;
	}

	if (!ikev1_close_message(&rbody, st))
		return STF_INTERNAL_ERROR;

	/* save initiator SA for HASH */
	replace_chunk(&st->st_p1isa, pbs_in_all(&sa_pd->pbs), "sa in main_inI1_outR1()");

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

static ke_and_nonce_cb main_inR1_outI2_continue;	/* type assertion */

stf_status main_inR1_outI2(struct state *st, struct msg_digest *md)
{
	if (impair.drop_i2) {
		dbg("dropping Main Mode I2 packet as per impair");
		return STF_IGNORE;
	}

	/* verify echoed SA */
	{
		struct payload_digest *const sapd = md->chain[ISAKMP_NEXT_SA];

		RETURN_STF_FAIL_v1NURE(parse_isakmp_sa_body(&sapd->pbs,
							&sapd->payload.sa,
							NULL, true, st));
	}

	if (is_fips_mode() && st->st_oakley.ta_prf == NULL) {
		log_state(RC_LOG_SERIOUS, st,
			  "Missing prf - algo not allowed in fips mode (inR1_outI2)?");
		return STF_FAIL_v1N + v1N_SITUATION_NOT_SUPPORTED;
	}

	merge_quirks(st, md);

	set_nat_traversal(st, md);

	submit_ke_and_nonce(st, st->st_oakley.ta_dh,
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

static stf_status main_inR1_outI2_continue(struct state *st,
					   struct msg_digest *md,
					   struct dh_local_secret *local_secret,
					   chunk_t *nonce/*steal*/)
{
	struct ike_sa *ike = pexpect_ike_sa(st);
	ldbg_sa(ike, "main_inR1_outI2_continue for #%lu: calculated ke+nonce, sending I2",
		st->st_serialno);

	/*
	 * HDR out.
	 * We can't leave this to comm_handle() because the isa_np
	 * depends on the type of Auth (eventually).
	 */
	struct pbs_out rbody;
	ikev1_init_pbs_out_from_md_hdr(md, false,
				       &reply_stream, reply_buffer, sizeof(reply_buffer),
				       &rbody, st->logger);

	/* KE out */
	if (!ikev1_ship_KE(st, local_secret, &st->st_gi, &rbody))
		return STF_INTERNAL_ERROR;

	/* Ni out */
	if (!ikev1_ship_nonce(&st->st_ni, nonce, &rbody, "Ni"))
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
	if (st->hidden_variables.st_nat_traversal != LEMPTY) {
		dbg("NAT-T found (implies NAT_T_WITH_NATD)");
		/* send two ISAKMP_NEXT_NATD_RFC* hash payloads to support NAT */
		if (!ikev1_nat_traversal_add_natd(&rbody, md))
			return STF_INTERNAL_ERROR;
	}

	/* finish message */
	if (!ikev1_close_message(&rbody, st))
		return STF_INTERNAL_ERROR;

	/* Reinsert the state, using the responder cookie we just received */
	update_st_ike_spis_responder(ike, &md->hdr.isa_ike_responder_spi);

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

static ke_and_nonce_cb main_inI2_outR2_continue1; /* type assertion */

stf_status main_inI2_outR2(struct state *st, struct msg_digest *md)
{
	/* KE in */
	if (!unpack_KE(&st->st_gi, "Gi", st->st_oakley.ta_dh,
		       md->chain[ISAKMP_NEXT_KE], st->logger)) {
		return STF_FAIL_v1N + v1N_INVALID_KEY_INFORMATION;
	}

	/* Ni in */
	RETURN_STF_FAIL_v1NURE(accept_v1_nonce(st->logger, md, &st->st_ni, "Ni"));

	/* decode certificate requests */
	decode_v1_certificate_requests(st, md);

	ikev1_natd_init(st, md);

	submit_ke_and_nonce(st, st->st_oakley.ta_dh,
			    main_inI2_outR2_continue1,
			    /*detach_whack*/false, HERE);
	return STF_SUSPEND;
}

/*
 * main_inI2_outR2_calcdone is unlike every other crypto_req_cont_func:
 * the state that it is working for may not yet care about the result.
 * We are precomputing the DH.
 * This also means that it isn't good at reporting an NSS error.
 */
static dh_shared_secret_cb main_inI2_outR2_continue2;	/* type assertion */

static stf_status main_inI2_outR2_continue2(struct state *st,
					    struct msg_digest *md)
{
	dbg("main_inI2_outR2_calcdone for #%lu: calculate DH finished",
	    st->st_serialno);

	/*
	 * Ignore error.  It will be handled handled when the next
	 * message arrives?!?
	 */
	if (st->st_dh_shared_secret != NULL) {
		calc_v1_skeyid_and_iv(st);
		update_iv(st);
	}

	/*
	 * If there was a packet received while we were calculating, then
	 * process it now.
	 * Otherwise, the result awaits the packet.
	 */
	if (md != NULL) {
		/*
		 * This will call complete_v1_state_transition() when
		 * needed.
		 */
		process_packet_tail(md);
	}
	return STF_SKIP_COMPLETE_STATE_TRANSITION;
}


static stf_status main_inI2_outR2_continue1(struct state *st,
					    struct msg_digest *md,
					    struct dh_local_secret *local_secret,
					    chunk_t *nonce)
{
	dbg("main_inI2_outR2_continue for #%lu: calculated ke+nonce, sending R2",
	    st->st_serialno);

	passert(md != NULL);

	if (is_fips_mode() && st->st_oakley.ta_prf == NULL) {
		log_state(RC_LOG_SERIOUS, st,
			  "Missing prf - algo not allowed in fips mode (inI2_outR2)?");
		return STF_FAIL_v1N + v1N_SITUATION_NOT_SUPPORTED;
	}

	/* send CR if auth is RSA and no preloaded RSA public key exists*/
	bool send_cr = false;

	/* Build output packet HDR;KE;Nr */

	send_cr = (st->st_oakley.auth == OAKLEY_RSA_SIG) &&
		!remote_has_preloaded_pubkey(st) &&
		st->st_connection->remote->host.config->ca.ptr != NULL;

	/* HDR out */
	struct pbs_out rbody;
	ikev1_init_pbs_out_from_md_hdr(md, false,
				       &reply_stream, reply_buffer, sizeof(reply_buffer),
				       &rbody, st->logger);

	/* KE out */
	passert(ikev1_ship_KE(st, local_secret, &st->st_gr, &rbody));

	/* Nr out */
	if (!ikev1_ship_nonce(&st->st_nr, nonce, &rbody, "Nr"))
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
		if (is_permanent(st->st_connection)) {
			if (!ikev1_build_and_ship_CR(CERT_X509_SIGNATURE,
						     st->st_connection->remote->host.config->ca,
						     &rbody))
				return STF_INTERNAL_ERROR;
		} else {
			generalName_t *ca = collect_rw_ca_candidates(md);

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

	if (st->hidden_variables.st_nat_traversal != LEMPTY) {
		/* send two ISAKMP_NEXT_NATD_RFC* hash payloads to support NAT */
		if (!ikev1_nat_traversal_add_natd(&rbody, md))
			return STF_INTERNAL_ERROR;
	}

	/* finish message */
	if (!ikev1_close_message(&rbody, st))
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
	    st->st_oakley.ta_dh->group);
	submit_dh_shared_secret(st, st, st->st_gi/*responder needs initiator's KE*/,
				main_inI2_outR2_continue2, HERE);
	/* we are calculating in the background, so it doesn't count */
	dbg("#%lu %s:%u st->st_calculating = false;", st->st_serialno, __func__, __LINE__);
	st->st_offloaded_task_in_background = true;

	return STF_OK;
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

static dh_shared_secret_cb main_inR2_outI3_continue;	/* type assertion */

stf_status main_inR2_outI3(struct state *st, struct msg_digest *md)
{
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
	release_symkey(__func__, "DH shared secret", &st->st_dh_shared_secret);
	release_symkey(__func__, "skeyid", &st->st_skeyid_nss);
	release_symkey(__func__, "skeyid_d", &st->st_skeyid_d_nss);
	release_symkey(__func__, "skeyid_a", &st->st_skeyid_a_nss);
	release_symkey(__func__, "skeyid_e", &st->st_skeyid_e_nss);
	release_symkey(__func__, "enc_key", &st->st_enc_key_nss);

	/* KE in */
	if (!unpack_KE(&st->st_gr, "Gr", st->st_oakley.ta_dh,
		       md->chain[ISAKMP_NEXT_KE], st->logger)) {
		return STF_FAIL_v1N + v1N_INVALID_KEY_INFORMATION;
	}

	/* Nr in */
	RETURN_STF_FAIL_v1NURE(accept_v1_nonce(st->logger, md, &st->st_nr, "Nr"));
	submit_dh_shared_secret(st, st, st->st_gr, main_inR2_outI3_continue, HERE);
	return STF_SUSPEND;
}

static stf_status main_inR2_outI3_continue(struct state *st,
					   struct msg_digest *md)
{
	dbg("main_inR2_outI3_continue for #%lu: calculated DH, sending R1",
	    st->st_serialno);

	passert(md != NULL);	/* ??? how would this fail? */

	if (st->st_dh_shared_secret == NULL) {
		return STF_FAIL_v1N + v1N_INVALID_KEY_INFORMATION;
	}

	calc_v1_skeyid_and_iv(st);

	struct pbs_out rbody[1]; /* hack */
	ikev1_init_pbs_out_from_md_hdr(md, true,
				       &reply_stream, reply_buffer, sizeof(reply_buffer),
				       rbody, st->logger);

	const struct connection *c = st->st_connection;
	const struct cert *mycert = c->local->host.config->cert.nss_cert != NULL ? &c->local->host.config->cert : NULL;

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

	bool send_authcerts = (send_cert &&
			       c->config->send_ca != CA_SEND_NONE);

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

	/*
	 * send certificate request, if we don't have a preloaded RSA
	 * public key
	 */
	bool send_cr = send_cert && !remote_has_preloaded_pubkey(st);

	dbg(" I am %ssending a certificate request",
	    send_cr ? "" : "not ");

	/*
	 * Determine if we need to send INITIAL_CONTACT payload
	 *
	 * We are INITIATOR in I2, this is not a Quick Mode rekey, so if
	 * there is a phase2 that we have for which the phase1 expired, this
	 * state has no way of finding out, so this would mean adding
	 * the payload, which would destroy the remote phase2, and cause
	 * downtime until we establish the new phase2. It is better not to
	 * send this payload, which is why the per-connection keyword default
	 * for initial_contact is 'no'. But some interop with Cisco requires
	 * this.
	 *
	 * In Quick Mode, we need to do a little more work, but that's in
	 * ikev1_quick.c
	 *
	 */
	bool initial_contact = c->config->send_initial_contact;
	dbg("I will %ssend an initial contact payload",
	    initial_contact ? "" : "NOT ");

	/* done parsing; initialize crypto */

	ikev1_natd_init(st, md);

	/*
	 * Build output packet HDR*;IDii;HASH/SIG_I
	 *
	 * ??? NOTE: this is almost the same as main_inI3_outR3's code
	 */

	/* HDR* out done */

	/* IDii out */
	struct pbs_out id_pbs; /* ID Payload; used later for hash calculation */
	enum next_payload_types_ikev1 auth_payload =
		st->st_oakley.auth == OAKLEY_PRESHARED_KEY ?
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
		log_state(RC_LOG, st, "IMPAIR: sending cert as pkcs7 blob");
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
		log_state(RC_LOG, st, "I am sending my cert");

		if (!ikev1_ship_CERT(cert_ike_type(mycert), cert_der(mycert), rbody)) {
			free_auth_chain(auth_chain, chain_len);
			return STF_INTERNAL_ERROR;
		}

		if (send_authcerts) {
			/* we've got CA certificates to send */
			log_state(RC_LOG, st, "I am sending a CA cert chain");
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
		log_state(RC_LOG, st, "I am sending a certificate request");
		if (!ikev1_build_and_ship_CR(cert_ike_type(mycert),
					     c->remote->host.config->ca,
					     rbody))
			return STF_INTERNAL_ERROR;
	}

	/* HASH_I or SIG_I out */
	{
		struct crypt_mac hash = main_mode_hash(st, SA_INITIATOR,
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
			sig = v1_sign_hash_RSA(c, &hash, st->logger);
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

	/* INITIAL_CONTACT */
	if (initial_contact) {
		struct pbs_out notify_pbs;
		struct isakmp_notification isan = {
			.isan_doi = ISAKMP_DOI_IPSEC,
			.isan_protoid = PROTO_ISAKMP,
			.isan_spisize = COOKIE_SIZE * 2,
			.isan_type = v1N_IPSEC_INITIAL_CONTACT,
		};

		log_state(RC_LOG, st, "sending INITIAL_CONTACT");

		if (!out_struct(&isan, &isakmp_notification_desc, rbody,
					&notify_pbs) ||
		    !out_raw(st->st_ike_spis.initiator.bytes, COOKIE_SIZE, &notify_pbs,
				"notify icookie") ||
		    !out_raw(st->st_ike_spis.responder.bytes, COOKIE_SIZE, &notify_pbs,
				"notify rcookie"))
			return STF_INTERNAL_ERROR;

		/* zero length data payload */
		close_output_pbs(&notify_pbs);
	} else {
		dbg("Not sending INITIAL_CONTACT");
	}

	/* encrypt message, except for fixed part of header */

	/* st_new_iv was computed by generate_skeyids_iv (??? DOESN'T EXIST) */
	if (!ikev1_close_and_encrypt_message(rbody, st))
		return STF_INTERNAL_ERROR; /* ??? we may be partly committed */

	return STF_OK;
}

/*
 * STATE_MAIN_R2:
 * PSK_AUTH: HDR*, IDi1, HASH_I --> HDR*, IDr1, HASH_R
 * DS_AUTH: HDR*, IDi1, [ CERT, ] SIG_I --> HDR*, IDr1, [ CERT, ] SIG_R
 * PKE_AUTH, RPKE_AUTH: HDR*, HASH_I --> HDR*, HASH_R
 */

stf_status main_inI3_outR3(struct state *st, struct msg_digest *md)
{
	pexpect(st == md->v1_st);
	st = md->v1_st;

	/* handle case where NSS balked at generating DH */
	if (st->st_dh_shared_secret == NULL)
		return STF_FAIL_v1N + v1N_INVALID_KEY_INFORMATION;

	if (!v1_decode_certs(md)) {
		log_state(RC_LOG, st, "X509: CERT payload bogus or revoked");
		return STF_FAIL_v1N + v1N_INVALID_ID_INFORMATION;
	}

	/*
	 * ID Payload in.
	 *
	 * Note: may switch the connection being used!  We are a Main
	 * Mode Responder.
	 */

	if (!ikev1_decode_peer_id_main_mode_responder(st, md)) {
		dbg("Peer ID failed to decode");
		return STF_FAIL_v1N + v1N_INVALID_ID_INFORMATION;
	}

	/* HASH_I or SIG_I */

	/* responder authenticating initiator */
	stf_status r = oakley_auth(md, SA_INITIATOR);
	if (r != STF_OK) {
		return r;
	}

	struct connection *c = st->st_connection; /* may have changed */

	/* send certificate if we have one and auth is RSA */
	const struct cert *mycert = c->local->host.config->cert.nss_cert != NULL ? &c->local->host.config->cert : NULL;

	pexpect(st->st_clonedfrom == SOS_NOBODY); /* ISAKMP */
	bool cert_requested = (st->st_v1_requested_ca != NULL);
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
	ikev1_init_pbs_out_from_md_hdr(md, true,
				       &reply_stream, reply_buffer, sizeof(reply_buffer),
				       &rbody, st->logger);

	enum next_payload_types_ikev1 auth_payload = st->st_oakley.auth == OAKLEY_PRESHARED_KEY ?
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
		log_state(RC_LOG, st, "IMPAIR: sending cert as pkcs7 blob");
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
		log_state(RC_LOG, st, "I am sending my cert");
		if (!ikev1_ship_CERT(cert_ike_type(mycert), cert_der(mycert), &rbody)) {
			free_auth_chain(auth_chain, chain_len);
			return STF_INTERNAL_ERROR;
		}

		if (send_authcerts) {
			log_state(RC_LOG, st, "I am sending a CA cert chain");
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
		struct crypt_mac hash = main_mode_hash(st, SA_RESPONDER,
						       pbs_out_all(&r_id_pbs));

		if (auth_payload == ISAKMP_NEXT_HASH) {
			/* HASH_R out */
			if (!ikev1_out_generic_raw(&isakmp_hash_desc, &rbody,
						   hash.ptr, hash.len, "HASH_R"))
				return STF_INTERNAL_ERROR;
		} else {
			/* SIG_R out */
			struct hash_signature sig;
			sig = v1_sign_hash_RSA(c, &hash, st->logger);
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

	/* encrypt message, sans fixed part of header */

	if (!ikev1_close_and_encrypt_message(&rbody, st))
		return STF_INTERNAL_ERROR; /* ??? we may be partly committed */

	/* Last block of Phase 1 (R3), kept for Phase 2 IV generation */
	if (DBGP(DBG_CRYPT)) {
		DBG_dump_hunk("last encrypted block of Phase 1:",
			      st->st_v1_new_iv);
	}

	set_ph1_iv_from_new(st);

	/*
	 * It seems as per Cisco implementation, XAUTH and MODECFG
	 * are not supposed to be performed again during rekey
	 */

	if (c->config->remote_peer_cisco &&
	    c->established_ike_sa != SOS_NOBODY &&
	    c->local->host.config->xauth.client) {
		dbg("Skipping XAUTH for rekey for Cisco Peer compatibility.");
		st->hidden_variables.st_xauth_client_done = true;
		st->st_oakley.doing_xauth = false;

		if (c->local->host.config->modecfg.client) {
			dbg("Skipping ModeCFG for rekey for Cisco Peer compatibility.");
			st->hidden_variables.st_modecfg_vars_set = true;
			st->hidden_variables.st_modecfg_started = true;
		}
	}

#ifdef USE_XFRM_INTERFACE
	if (c->xfrmi != NULL && c->xfrmi->if_id != 0)
		if (!add_xfrm_interface(c, st->logger))
			return STF_FATAL;
#endif
	ISAKMP_SA_established(pexpect_ike_sa(st));
	return STF_OK;
}

/*
 * STATE_MAIN_I3:
 * Handle HDR*;IDir;HASH/SIG_R from responder.
 *
 */

stf_status main_inR3(struct state *st, struct msg_digest *md)
{
	if (!v1_decode_certs(md)) {
		log_state(RC_LOG, st, "X509: CERT payload bogus or revoked");
		return STF_FAIL_v1N + v1N_INVALID_ID_INFORMATION;
	}

	/*
	 * ID Payload in.
	 *
	 * Note: will not switch the connection being used because we
	 * are the initiator.
	 */

	struct connection *c = st->st_connection;

	if (!ikev1_decode_peer_id_initiator(st, md)) {
		dbg("Peer ID failed to decode");
		return STF_FAIL_v1N + v1N_INVALID_ID_INFORMATION;
	}

	passert(c == st->st_connection); /* no switch */

	/* HASH_R or SIG_R */

	/* initiator authenticating responder */
	stf_status r = oakley_auth(md, SA_RESPONDER);
	if (r != STF_OK) {
		return r;
	}

	/* Done input */

	/*
	 * It seems as per Cisco implementation, XAUTH and MODECFG
	 * are not supposed to be performed again during rekey
	 */
	if (c->config->remote_peer_cisco &&
		c->established_ike_sa != SOS_NOBODY &&
		c->local->host.config->xauth.client) {
		dbg("Skipping XAUTH for rekey for Cisco Peer compatibility.");
		st->hidden_variables.st_xauth_client_done = true;
		st->st_oakley.doing_xauth = false;

		if (c->local->host.config->modecfg.client) {
			dbg("Skipping ModeCFG for rekey for Cisco Peer compatibility.");
			st->hidden_variables.st_modecfg_vars_set = true;
			st->hidden_variables.st_modecfg_started = true;
		}
	}

#ifdef USE_XFRM_INTERFACE
	if (c->xfrmi != NULL && c->xfrmi->if_id != 0)
		if (!add_xfrm_interface(c, st->logger))
			return STF_FATAL;
#endif
	ISAKMP_SA_established(pexpect_ike_sa(st));

	passert((st->st_policy & POLICY_PFS) == 0 ||
		st->st_pfs_group != NULL);

	/*
	 * save last IV from phase 1 so it can be restored later so anything
	 * between the end of phase 1 and the start of phase 2 i.e. mode config
	 * payloads etc. will not lose our IV
	 */
	set_ph1_iv_from_new(st);

	update_iv(st); /* finalize our Phase 1 IV */

	return STF_OK;
}

stf_status send_isakmp_notification(struct state *st,
				    uint16_t type, const void *data,
				    size_t len)
{
	msgid_t msgid;
	struct pbs_out rbody;

	msgid = generate_msgid(st);

	reply_stream = open_pbs_out("reply packet", reply_buffer, sizeof(reply_buffer), st->logger);

	/* HDR* */
	{
		struct isakmp_hdr hdr = {
			.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
				ISAKMP_MINOR_VERSION,
			.isa_xchg = ISAKMP_XCHG_INFO,
			.isa_flags = ISAKMP_FLAGS_v1_ENCRYPTION,
			.isa_msgid = msgid,
		};
		hdr.isa_ike_initiator_spi = st->st_ike_spis.initiator;
		hdr.isa_ike_responder_spi = st->st_ike_spis.responder;
		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply_stream, &rbody))
			return STF_INTERNAL_ERROR;
	}

	struct v1_hash_fixup hash_fixup;
	if (!emit_v1_HASH(V1_HASH_1, "notification",
			  IMPAIR_v1_NOTIFICATION_EXCHANGE,
			  st, &hash_fixup, &rbody)) {
		return STF_INTERNAL_ERROR;
	}

	/* NOTIFY */
	{
		struct pbs_out notify_pbs;
		struct isakmp_notification isan = {
			.isan_doi = ISAKMP_DOI_IPSEC,
			.isan_protoid = PROTO_ISAKMP,
			.isan_spisize = COOKIE_SIZE * 2,
			.isan_type = type,
		};
		if (!out_struct(&isan, &isakmp_notification_desc, &rbody,
					&notify_pbs) ||
		    !out_raw(st->st_ike_spis.initiator.bytes, COOKIE_SIZE, &notify_pbs,
				"notify icookie") ||
		    !out_raw(st->st_ike_spis.responder.bytes, COOKIE_SIZE, &notify_pbs,
				"notify rcookie"))
			return STF_INTERNAL_ERROR;

		if (data != NULL && len > 0)
			if (!out_raw(data, len, &notify_pbs, "notify data"))
				return STF_INTERNAL_ERROR;

		close_output_pbs(&notify_pbs);
	}

	fixup_v1_HASH(st, &hash_fixup, msgid, rbody.cur);

	/*
	 * save old IV (this prevents from copying a whole new state object
	 * for NOTIFICATION / DELETE messages we don't need to maintain a state
	 * because there are no retransmissions...
	 */
	{
		struct crypt_mac old_new_iv;
		struct crypt_mac old_iv;

		save_iv(st, old_iv);
		save_new_iv(st, old_new_iv);

		init_phase2_iv(st, &msgid);
		if (!ikev1_close_and_encrypt_message(&rbody, st))
			return STF_INTERNAL_ERROR;

		send_pbs_out_using_state(st, "ISAKMP notify", &reply_stream);

		/* get back old IV for this state */
		restore_iv(st, old_iv);
		restore_new_iv(st, old_new_iv);
	}

	return STF_IGNORE;
}

/*
 * Send a notification to the peer. We could decide whether to send
 * the notification, based on the type and the destination, if we care
 * to.
 *
 * Note: msgid is in different order here from other calls :/
 */
static monotime_t last_malformed = MONOTIME_EPOCH;

static void send_v1_notification(struct logger *logger,
				 struct state *sndst,
				 v1_notification_t type,
				 struct ike_sa *isakmp_encrypt, /*possibly NULL*/
				 msgid_t msgid,
				 uint8_t *icookie,
				 uint8_t *rcookie,
				 uint8_t protoid)
{
	struct pbs_out r_hdr_pbs;
	const monotime_t now = mononow();

	switch (type) {
	case v1N_PAYLOAD_MALFORMED:
		/* only send one per second. */
		if (monotime_cmp(monotime_add(last_malformed, deltatime(1)), <, now))
			return;

		last_malformed = now;

		/*
		 * If a state gets too many of these, delete it.
		 *
		 * Note that the fake state of send_notification_from_md
		 * will never trigger this (a Good Thing since it
		 * must not be deleted).
		 */
		sndst->hidden_variables.st_malformed_sent++;
		if (sndst->hidden_variables.st_malformed_sent > MAXIMUM_MALFORMED_NOTIFY) {
			llog(RC_LOG, logger, "too many (%d) malformed payloads. Deleting state",
			     sndst->hidden_variables.st_malformed_sent);
			connection_delete_v1_state(&sndst, HERE);
			/* note: no md->v1_st to clear */
			return;
		}

		if (sndst->st_v1_iv.len != 0) {
			LLOG_JAMBUF(RC_LOG, logger, buf) {
				jam(buf, "payload malformed.  IV: ");
				jam_dump_bytes(buf, sndst->st_v1_iv.ptr,
					       sndst->st_v1_iv.len);
			}
		}

		/*
		 * Do not encrypt notification, since #1 reason for
		 * malformed payload is that the keys are all messed
		 * up.
		 */
		isakmp_encrypt = NULL;
		break;

	case v1N_INVALID_FLAGS:
		/*
		 * Invalid flags usually includes encryption flags, so
		 * do not send encrypted.
		 */
		isakmp_encrypt = NULL;
		break;

	default:
		/* quiet GCC warning */
		break;
	}

	/* handled by caller? */
	if (!PEXPECT(logger, (isakmp_encrypt == NULL ||
			      IS_V1_ISAKMP_ENCRYPTED(isakmp_encrypt->sa.st_state->kind)))) {
		return;
	}

	{
		endpoint_buf b;
		enum_buf nb;
		llog(RC_LOG, logger,
		     "sending %snotification %s to %s",
		     (isakmp_encrypt != NULL ? "encrypted " : ""),
		     str_enum_short(&v1_notification_names, type, &nb),
		     str_endpoint(&sndst->st_remote_endpoint, &b));
	}

	uint8_t buffer[1024];	/* ??? large enough for any notification? */
	struct pbs_out pbs = open_pbs_out("notification msg", buffer, sizeof(buffer), logger);

	/* HDR* */
	{
		/* ??? "keep it around for TPM" */
		struct isakmp_hdr hdr = {
			.isa_version = (ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
					ISAKMP_MINOR_VERSION),
			.isa_xchg = ISAKMP_XCHG_INFO,
			.isa_msgid = msgid,
			.isa_flags = (isakmp_encrypt != NULL ? ISAKMP_FLAGS_v1_ENCRYPTION : 0),
		};
		if (icookie != NULL)
			memcpy(hdr.isa_ike_initiator_spi.bytes, icookie, COOKIE_SIZE);
		if (rcookie != NULL)
			memcpy(hdr.isa_ike_responder_spi.bytes, rcookie, COOKIE_SIZE);
		passert(out_struct(&hdr, &isakmp_hdr_desc, &pbs, &r_hdr_pbs));
	}

	/* HASH -- value to be filled later */
	struct v1_hash_fixup hash_fixup = {0};
	if (isakmp_encrypt != NULL) {
		if (!emit_v1_HASH(V1_HASH_1, "send notification",
				  IMPAIR_v1_NOTIFICATION_EXCHANGE,
				  &isakmp_encrypt->sa, &hash_fixup, &r_hdr_pbs)) {
			/* return STF_INTERNAL_ERROR; */
			return;
		}
	}

	/* Notification Payload */
	{
		struct pbs_out not_pbs;
		struct isakmp_notification isan = {
			.isan_doi = ISAKMP_DOI_IPSEC,
			.isan_type = type,
			.isan_spisize = 0,
			.isan_protoid = protoid,
		};

		if (!out_struct(&isan, &isakmp_notification_desc,
					&r_hdr_pbs, &not_pbs)) {
			llog(RC_LOG, logger,
				    "failed to build notification in send_notification");
			return;
		}

		close_output_pbs(&not_pbs);
	}

	if (isakmp_encrypt != NULL) {
		/* calculate hash value and patch into Hash Payload */
		fixup_v1_HASH(&isakmp_encrypt->sa, &hash_fixup, msgid, r_hdr_pbs.cur);

		/* Encrypt message (preserve st_iv) */
		/* ??? why not preserve st_new_iv? */
		struct crypt_mac old_iv;

		save_iv(&isakmp_encrypt->sa, old_iv);

		if (!IS_V1_ISAKMP_SA_ESTABLISHED(&isakmp_encrypt->sa)) {
			update_iv(&isakmp_encrypt->sa);
		}
		init_phase2_iv(&isakmp_encrypt->sa, &msgid);
		passert(ikev1_close_and_encrypt_message(&r_hdr_pbs, &isakmp_encrypt->sa));

		restore_iv(&isakmp_encrypt->sa, old_iv);
	} else {
		close_output_pbs(&r_hdr_pbs);
	}

	send_pbs_out_using_state(sndst, "notification packet", &pbs);
}

void send_v1_notification_from_state(struct state *st, enum state_kind from_state,
				     v1_notification_t type)
{
	passert(st != NULL);

	if (from_state == STATE_UNDEFINED)
		from_state = st->st_state->kind;

	if (IS_V1_QUICK(from_state)) {
		/*
		 * Don't use established_isakmp_sa_for_state().
		 *
		 * It returns NULL when ST isn't established and here
		 * ST is still larval.
		 *
		 * Don't require a viable ISAKMP (i.e., can start new
		 * quick mode exchanges), but does it really matter?
		 */
		struct ike_sa *isakmp = find_ike_sa_by_connection(st->st_connection,
								  V1_ISAKMP_SA_ESTABLISHED_STATES,
								  /*viable-parent*/false);
		if (isakmp == NULL) {
			llog(RC_LOG_SERIOUS, st->logger,
			     "no ISAKMP SA for Quick mode notification");
			return;
		}
		if (!IS_V1_ISAKMP_ENCRYPTED(isakmp->sa.st_state->kind)) {
			/*passert?*/
			llog(RC_LOG_SERIOUS, st->logger,
			     "ISAKMP SA for Quick mode notification is not encrypted");
			return;
		}
		send_v1_notification(st->logger, st, type,
				     isakmp, generate_msgid(&isakmp->sa),
				     st->st_ike_spis.initiator.bytes,
				     st->st_ike_spis.responder.bytes,
				     PROTO_ISAKMP);
		return;
	}

	if (IS_V1_ISAKMP_ENCRYPTED(from_state)) {
		send_v1_notification(st->logger, st, type,
				     pexpect_parent_sa(st),
				     generate_msgid(st),
				     st->st_ike_spis.initiator.bytes,
				     st->st_ike_spis.responder.bytes,
				     PROTO_ISAKMP);
		return;
	}

	/* no ISAKMP SA established - don't encrypt notification */
	send_v1_notification(st->logger, st, type,
			     /*no-ISAKMP*/NULL, v1_MAINMODE_MSGID,
			     st->st_ike_spis.initiator.bytes,
			     st->st_ike_spis.responder.bytes,
			     PROTO_ISAKMP);
}

void send_v1_notification_from_md(struct msg_digest *md, v1_notification_t type)
{
	struct pbs_out r_hdr_pbs;
	const monotime_t now = mononow();

	switch (type) {
	case v1N_PAYLOAD_MALFORMED:
		/* only send one per second. */
		if (monotime_cmp(monotime_add(last_malformed, deltatime(1)), <, now))
			return;
		last_malformed = now;
		break;

	case v1N_INVALID_FLAGS:
		break;

	default:
		/* quiet GCC warning */
		break;
	}

	endpoint_buf b;
	enum_buf nb;
	llog(RC_LOG, md->logger,
	     "sending notification %s to %s",
	     str_enum_short(&v1_notification_names, type, &nb),
	     str_endpoint(&md->sender, &b));

	uint8_t buffer[1024];	/* ??? large enough for any notification? */
	struct pbs_out pbs = open_pbs_out("notification msg",
					  buffer, sizeof(buffer),
					  md->logger);

	/* HDR* */

	{
		/* ??? "keep it around for TPM" */
		struct isakmp_hdr hdr = {
			.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
				ISAKMP_MINOR_VERSION,
			.isa_xchg = ISAKMP_XCHG_INFO,
			.isa_msgid = 0,
			.isa_flags = 0,
			.isa_ike_initiator_spi = md->hdr.isa_ike_initiator_spi,
			.isa_ike_responder_spi = md->hdr.isa_ike_responder_spi,
		};
		passert(out_struct(&hdr, &isakmp_hdr_desc, &pbs, &r_hdr_pbs));
	}

	/* Notification Payload */

	{
		struct pbs_out not_pbs;
		struct isakmp_notification isan = {
			.isan_doi = ISAKMP_DOI_IPSEC,
			.isan_type = type,
			.isan_spisize = 0,
			.isan_protoid = PROTO_ISAKMP,
		};

		if (!out_struct(&isan, &isakmp_notification_desc,
					&r_hdr_pbs, &not_pbs)) {
			llog(RC_LOG, md->logger,
			     "failed to build notification in send_notification");
			return;
		}

		close_output_pbs(&not_pbs);
	}

	close_output_pbs(&r_hdr_pbs);
	send_pbs_out_using_md(md, "notification packet", &pbs);
}
