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
#include "spdb.h"
#include "timer.h"
#include "rnd.h"
#include "ipsec_doi.h" /* needs demux.h and state.h */
#include "whack.h"
#include "fetch.h"
#include "asn1.h"
#include "pending.h"
#include "ikev1_hash.h"
#include "hostpair.h"

#include "crypto.h"
#include "secrets.h"

#include "ike_alg.h"
#include "ike_alg_encrypt_ops.h"	/* XXX: oops */
#include "kernel_alg.h"
#include "plutoalg.h"
#include "pluto_crypt.h"
#include "ikev1.h"
#include "ikev1_continuations.h"
#include "ikev1_message.h"
#include "ikev1_xauth.h"
#include "crypt_prf.h"
#include "vendor.h"
#include "nat_traversal.h"
#include "ikev1_dpd.h"
#include "pluto_x509.h"

#include "lswfips.h"
#include "ip_address.h"
#include "send.h"
#include "ikev1_send.h"
#include "nss_cert_verify.h"
#include "iface.h"

#ifdef USE_XFRM_INTERFACE
# include "kernel_xfrm_interface.h"
#endif

/*
 * Initiate an Oakley Main Mode exchange.
 * --> HDR;SA
 * Note: this is not called from demux.c
 */
/* extern initiator_function main_outI1; */	/* type assertion */
void main_outI1(struct fd *whack_sock,
		struct connection *c,
		struct state *predecessor,
		lset_t policy,
		unsigned long try,
		const threadtime_t *inception,
		struct xfrm_user_sec_ctx_ike *uctx)
{
	struct ike_sa *ike = new_v1_istate(whack_sock);
	struct state *st = &ike->sa;
	statetime_t start = statetime_backdate(st, inception);

	/* set up new state */
	initialize_new_state(st, c, policy, try);
	push_cur_state(st);

	change_state(st, STATE_MAIN_I1);

	if (HAS_IPSEC_POLICY(policy)) {
		add_pending(whack_sock, ike, c, policy, 1,
			    predecessor == NULL ?
			    SOS_NOBODY : predecessor->st_serialno,
			    uctx,
			    true/* part of initiate */);
	}

	/* For main modes states, sec ctx is always null */
	st->sec_ctx = NULL;

	if (predecessor == NULL) {
		log_state(RC_LOG, &ike->sa, "initiating Main Mode");
	} else {
		log_state(RC_LOG, &ike->sa, "initiating Main Mode to replace #%lu",
			  predecessor->st_serialno);
	}

	/* set up reply */
	init_out_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
		"reply packet");

	/* HDR out */
	pb_stream rbody;
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
			reset_cur_state();
			return;
		}
	}

	/* SA out */
	{
		u_char *sa_start = rbody.cur;

		if (!ikev1_out_sa(&rbody, IKEv1_oakley_sadb(policy, c),
				  st, TRUE, FALSE)) {
			log_state(RC_LOG, st, "outsa fail");
			reset_cur_state();
			return;
		}

		/* no leak! (MUST be first time) */
		passert(st->st_p1isa.ptr == NULL);

		/* save initiator SA for later HASH */
		st->st_p1isa = clone_bytes_as_chunk(sa_start, rbody.cur - sa_start,
						    "sa in main_outI1");
	}

	/* send Vendor IDs */
	if (!out_vid_set(&rbody, c)) {
		reset_cur_state();
		return;
	}

	/* as Initiator, spray NAT VIDs */
	if (!nat_traversal_insert_vid(&rbody, c)) {
		reset_cur_state();
		return;
	}

	if (!ikev1_close_message(&rbody, st)) {
		reset_cur_state();
		return;
	}

	close_output_pbs(&reply_stream);

	/* Transmit */
	record_and_send_v1_ike_msg(st, &reply_stream,
		"reply packet for main_outI1");

	delete_event(st);
	clear_retransmits(st);
	start_retransmits(st);

	if (predecessor != NULL) {
		update_pending(pexpect_ike_sa(predecessor), pexpect_ike_sa(st));
		log_state(RC_NEW_V1_STATE + st->st_state->kind, &ike->sa,
			  "%s: %s, replacing #%lu",
			  st->st_state->name, st->st_state->story,
			  predecessor->st_serialno);
	} else {
		log_state(RC_NEW_V1_STATE + st->st_state->kind, &ike->sa,
			  "%s: %s", st->st_state->name, st->st_state->story);
	}

	statetime_stop(&start, "%s()", __func__);
	reset_cur_state();
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
				const pb_stream *idpl, /* ID payload, as PBS */
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
	 * Hash identification payload, without generic payload header.
	 * We used to reconstruct ID Payload for this purpose, but now
	 * we use the bytes as they appear on the wire to avoid
	 * "spelling problems".
	 */
	crypt_prf_update_bytes(ctx, "idpl",
			       idpl->start + sizeof(struct isakmp_generic),
			       pbs_offset(idpl) - sizeof(struct isakmp_generic));
}

struct crypt_mac main_mode_hash(struct state *st,
				enum sa_role role,
				const pb_stream *idpl) /* ID payload, as PBS; cur must be at end */
{
	struct crypt_prf *ctx = crypt_prf_init_symkey("main mode",
						      st->st_oakley.ta_prf,
						      "skeyid", st->st_skeyid_nss);
	main_mode_hash_body(st, role, idpl, ctx);
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
	const struct private_key_stuff *pks =
		get_connection_private_key(c, &pubkey_type_rsa,
					   logger);
	if (pks == NULL) {
		return (struct hash_signature) { .len = 0, }; /* failure: no key to use */
	}

	/* XXX: merge sign_hash_{RSA,ECDSA}()? */
	const struct RSA_private_key *k = &pks->u.RSA_private_key;

	size_t sz = k->pub.k;
	struct hash_signature sig;
	passert(RSA_MIN_OCTETS <= sz &&
		4 + hash->len < sz &&
		sz <= sizeof(sig.ptr/*array*/));
	sig = pubkey_type_rsa.sign_hash(pks, hash->ptr, hash->len,
					0/* for ikev2 only */,
					logger);
	passert(sig.len == 0 || sz == sig.len);
	return sig;
}

/*
 * Check a Main Mode RSA Signature against computed hash using RSA public
 * key k.
 *
 * As a side effect, on success, the public key is copied into the
 * state object to record the authenticator.
 *
 * Can fail because wrong public key is used or because hash disagrees.
 * We distinguish because diagnostics should also.
 *
 * The result is NULL if the Signature checked out.
 * Otherwise, the first character of the result indicates
 * how far along failure occurred.  A greater character signifies
 * greater progress.
 *
 * Classes:
 * 0	reserved for caller
 * 1	SIG length doesn't match key length -- wrong key
 * 2-8	malformed ECB after decryption -- probably wrong key
 * 9	decrypted hash != computed hash -- probably correct key
 * 10   NSS error
 * 11   NSS error
 * 12   NSS error
 *
 * Although the math should be the same for generating and checking signatures,
 * it is not: the knowledge of the private key allows more efficient (i.e.
 * different) computation for encryption.
 */
static err_t try_RSA_signature_v1(const struct crypt_mac *hash,
				const pb_stream *sig_pbs, struct pubkey *kr,
				struct state *st,
				const struct hash_desc *hash_algo_unused UNUSED /* for ikev2 only */)
{
	const u_char *sig_val = sig_pbs->cur;
	size_t sig_len = pbs_left(sig_pbs);
	const struct RSA_public_key *k = &kr->u.rsa;

	/* decrypt the signature -- reversing RSA_sign_hash */
	if (sig_len != k->k) {
		/* XXX notification: INVALID_KEY_INFORMATION */
		return "1" "SIG length does not match public key length";
	}

	err_t ugh = RSA_signature_verify_nss(k, hash, sig_val,
					sig_len, 0 /* for ikev2 only */);
	if (ugh != NULL)
		return ugh;

	/*
	 * Success: copy successful key into state.
	 * There might be an old one if we previously aborted this
	 * state transition.
	 */
	unreference_key(&st->st_peer_pubkey);
	st->st_peer_pubkey = reference_key(kr);

	return NULL; /* happy happy */
}

static stf_status RSA_check_signature(struct state *st,
				      struct crypt_mac *hash,
				      const pb_stream *sig_pbs,
				      enum ikev2_hash_algorithm hash_algo UNUSED /* for ikev2 only */)
{
	return check_signature_gen(st, hash, sig_pbs, 0 /* for ikev2 only */,
				   &pubkey_type_rsa, try_RSA_signature_v1);
}

notification_t accept_v1_nonce(struct logger *logger,
			       struct msg_digest *md, chunk_t *dest,
			       const char *name)
{
	pb_stream *nonce_pbs = &md->chain[ISAKMP_NEXT_NONCE]->pbs;
	size_t len = pbs_left(nonce_pbs);

	if (len < IKEv1_MINIMUM_NONCE_SIZE || IKEv1_MAXIMUM_NONCE_SIZE < len) {
		log_message(RC_LOG_SERIOUS, logger, "%s length not between %d and %d",
			    name, IKEv1_MINIMUM_NONCE_SIZE, IKEv1_MAXIMUM_NONCE_SIZE);
		return PAYLOAD_MALFORMED; /* ??? */
	}
	free_chunk_content(dest);
	*dest = clone_hunk(pbs_in_left_as_shunk(nonce_pbs), "nonce");
	passert(len == dest->len);
	return NOTHING_WRONG;
}

/*
 * encrypt message, sans fixed part of header
 * IV is fetched from st->st_new_iv and stored into st->st_iv.
 * The theory is that there will be no "backing out", so we commit to IV.
 * We also close the pbs.
 */
bool ikev1_encrypt_message(pb_stream *pbs, struct state *st)
{
	const struct encrypt_desc *e = st->st_oakley.ta_encrypt;
	uint8_t *enc_start = pbs->start + sizeof(struct isakmp_hdr);
	size_t enc_len = pbs_offset(pbs) - sizeof(struct isakmp_hdr);

	if (DBGP(DBG_CRYPT)) {
		DBG_dump("encrypting:", enc_start, enc_len);
		DBG_dump_hunk("IV:", st->st_v1_new_iv);
		DBG_log("unpadded size is: %u", (unsigned int)enc_len);
	}

	/*
	 * Pad up to multiple of encryption blocksize.
	 * See the description associated with the definition of
	 * struct isakmp_hdr in packet.h.
	 */
	{
		size_t padding = pad_up(enc_len, e->enc_blocksize);

		if (padding != 0) {
			if (!out_zero(padding, pbs, "encryption padding"))
				return FALSE;

			enc_len += padding;
		}
	}

	if (DBGP(DBG_CRYPT)) {
		DBG_log("encrypting %zu using %s", enc_len,
			st->st_oakley.ta_encrypt->common.fqn);
	}

	passert(st->st_v1_new_iv.len >= e->enc_blocksize);
	st->st_v1_new_iv.len = e->enc_blocksize;   /* truncate */

	/* close just before encrypting so NP backpatching isn't confused */
	if (!ikev1_close_message(pbs, st))
		return FALSE;

	e->encrypt_ops->do_crypt(e, enc_start, enc_len,
				 st->st_enc_key_nss,
				 st->st_v1_new_iv.ptr, TRUE);

	update_iv(st);
	if (DBGP(DBG_CRYPT)) {
		DBG_dump_hunk("next IV:", st->st_v1_iv);
	}

	return TRUE;
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
bool ikev1_close_message(pb_stream *pbs, const struct state *st)
{
	passert(st->st_ike_version == IKEv1);
	size_t padding = pad_up(pbs_offset(pbs), 4);

	if (padding == 0) {
		dbg("no IKEv1 message padding required");
	} else if (pexpect(st != NULL) && pexpect(st->st_connection != NULL) &&
		   (st->st_connection->policy & POLICY_NO_IKEPAD)) {
		dbg("IKEv1 message padding of %zu bytes skipped by policy",
		    padding);
	} else {
		dbg("padding IKEv1 message with %zu bytes", padding);
		if (!out_zero(padding, pbs, "message padding"))
			return FALSE;
	}

	close_output_pbs(pbs);
	return TRUE;
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
	struct connection *c;
	pb_stream r_sa_pbs;


	if (drop_new_exchanges()) {
		return STF_IGNORE;
	}

	/* random source ports are handled by find_host_connection */
	c = find_host_connection(&md->iface->local_endpoint, &md->sender,
				 POLICY_IKEV1_ALLOW, POLICY_AGGRESSIVE | POLICY_IKEV1_ALLOW);

	if (c == NULL) {
		lset_t policy = preparse_isakmp_sa_body(sa_pd->pbs) |
			POLICY_IKEV1_ALLOW;

		/*
		 * Other IKE clients, such as strongswan, send the XAUTH
		 * VID even for connections they do not want to run XAUTH on.
		 * We need to depend on the policy negotiation, not the VID.
		 * So we ignore md->quirks.xauth_vid
		 */

		/*
		 * See if a wildcarded connection can be found.
		 * We cannot pick the right connection, so we're making a guess.
		 * All Road Warrior connections are fair game:
		 * we pick the first we come across (if any).
		 * If we don't find any, we pick the first opportunistic
		 * with the smallest subnet that includes the peer.
		 * There is, of course, no necessary relationship between
		 * an Initiator's address and that of its client,
		 * but Food Groups kind of assumes one.
		 */
		{
			struct connection *d = find_host_connection(&md->iface->local_endpoint, NULL,
								    policy, POLICY_XAUTH | POLICY_AGGRESSIVE | POLICY_IKEV1_ALLOW);

			while (d != NULL) {
				if (d->kind == CK_GROUP) {
					/* ignore */
				} else {
					if (d->kind == CK_TEMPLATE) {
						/*
						 * must be Road Warrior:
						 * we have a winner
						 */
						c = d;
						break;
					}

					/*
					 * Opportunistic or Shunt:
					 * pick tightest match
					 */
					if (addrinsubnet(
						&md->sender,
						&d->spd.that.client) &&
					    (c == NULL ||
					     !subnetinsubnet(
						&c->spd.that.client,
						&d->spd.that.client))) {
						c = d;
					}
				}
				d = find_next_host_connection(d->hp_next,
					policy, POLICY_XAUTH | POLICY_AGGRESSIVE | POLICY_IKEV1_ALLOW);
			}
		}

		if (c == NULL) {
			log_md(RC_LOG_SERIOUS, md,
			       "initial Main Mode message received but no connection has been authorized with policy %s",
			       bitnamesof(sa_policy_bit_names, policy));
			/* XXX notification is in order! */
			return STF_IGNORE;
		} else if (c->kind != CK_TEMPLATE) {
			connection_buf cib;
			log_md(RC_LOG_SERIOUS, md,
			       "initial Main Mode message received but "PRI_CONNECTION" forbids connection",
			       pri_connection(c, &cib));
			/* XXX notification is in order! */
			return STF_IGNORE;
		} else {
			/*
			 * Create a temporary connection that is a copy
			 * of this one.
			 * Their ID isn't declared yet.
			 */
			connection_buf cib;
			dbg_md(md, "instantiating "PRI_CONNECTION" for initial Main Mode message",
			       pri_connection(c, &cib));
			ip_address sender_address = endpoint_address(&md->sender);
			c = rw_instantiate(c, &sender_address, NULL, NULL);
		}
	} else {
		/*
		 * we found a non-wildcard conn. double check if it needs
		 * instantiation anyway (eg vnet=)
		 */
		if (c->kind == CK_TEMPLATE && c->spd.that.virt) {
			dbg_md(md, "local endpoint has virt (vnet/vhost) set without wildcards - needs instantiation");
			ip_address sender_address = endpoint_address(&md->sender);
			c = rw_instantiate(c, &sender_address, NULL, NULL);
		}
		if (c->kind == CK_TEMPLATE && c->spd.that.has_id_wildcards) {
			dbg_md(md, "remote end has wildcard ID, needs instantiation");
			ip_address sender_address = endpoint_address(&md->sender);
			c = rw_instantiate(c, &sender_address, NULL, NULL);
		}
	}

	/* Set up state */
	struct ike_sa *ike = new_v1_rstate(md);
	struct state *st = md->st = &ike->sa;

	passert(!st->st_oakley.doing_xauth);

	update_state_connection(st, c);

	set_cur_state(st); /* (caller will reset cur_state) */
	st->st_try = 0; /* not our job to try again from start */
	/* only as accurate as connection */
	st->st_policy = c->policy & ~POLICY_IPSEC_MASK;
	change_state(st, STATE_MAIN_R0);

	binlog_refresh_state(st);

	merge_quirks(st, md);

	set_nat_traversal(st, md);

	if (DBGP(DBG_BASE)) {
		DBG_dump_thing("  ICOOKIE-DUMP:", st->st_ike_spis.initiator);
	}

	if (c->kind == CK_INSTANCE) {
		endpoint_buf b;
		log_state(RC_LOG, st, "responding to Main Mode from unknown peer %s",
			  str_sensitive_endpoint(&md->sender, &b));
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
	init_out_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
		"reply packet");
	pb_stream rbody;
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
	RETURN_STF_FAILURE(parse_isakmp_sa_body(&sa_pd->pbs,
						&sa_pd->payload.sa,
						&r_sa_pbs, FALSE, st));

	/* send Vendor IDs */
	if (!out_vid_set(&rbody, c))
		return STF_INTERNAL_ERROR;

	/* as Responder, send best NAT VID we received */
	if (st->hidden_variables.st_nat_traversal != LEMPTY) {
		if (!out_vid(&rbody, md->quirks.qnat_traversal_vid))
			return STF_INTERNAL_ERROR;
	}

	if (!ikev1_close_message(&rbody, st))
		return STF_INTERNAL_ERROR;

	/* save initiator SA for HASH */
	free_chunk_content(&st->st_p1isa);
	st->st_p1isa = clone_hunk(pbs_in_as_shunk(&sa_pd->pbs), "sa in main_inI1_outR1()");

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

static stf_status main_inR1_outI2_tail(struct state *st, struct msg_digest *md,
				       struct pluto_crypto_req *r);

static crypto_req_cont_func main_inR1_outI2_continue;	/* type assertion */

static void main_inR1_outI2_continue(struct state *st,
				     struct msg_digest *md,
				     struct pluto_crypto_req *r)
{
	dbg("main_inR1_outI2_continue for #%lu: calculated ke+nonce, sending I2",
	    st->st_serialno);

	passert(md != NULL);
	stf_status e = main_inR1_outI2_tail(st, md, r);
	complete_v1_state_transition(md, e);
}

stf_status main_inR1_outI2(struct state *st, struct msg_digest *md)
{
	if (impair.drop_i2) {
		dbg("dropping Main Mode I2 packet as per impair");
		return STF_IGNORE;
	}

	/* verify echoed SA */
	{
		struct payload_digest *const sapd = md->chain[ISAKMP_NEXT_SA];

		RETURN_STF_FAILURE(parse_isakmp_sa_body(&sapd->pbs,
							&sapd->payload.sa,
							NULL, TRUE, st));
	}

	if (libreswan_fipsmode() && st->st_oakley.ta_prf == NULL) {
		log_state(RC_LOG_SERIOUS, st,
			  "Missing prf - algo not allowed in fips mode (inR1_outI2)?");
		return STF_FAIL + SITUATION_NOT_SUPPORTED;
	}

	merge_quirks(st, md);

	set_nat_traversal(st, md);

	request_ke_and_nonce("outI2 KE", st,
			     st->st_oakley.ta_dh,
			     main_inR1_outI2_continue);
	return STF_SUSPEND;
}

/*
 * package up the calculate KE value, and emit it as a KE payload.
 * used by IKEv1: main, aggressive, and quick (in PFS mode).
 */
bool ikev1_justship_KE(struct logger *logger, chunk_t *g, pb_stream *outs)
{
	switch (impair.ke_payload) {
	case IMPAIR_EMIT_NO:
		return ikev1_out_generic_chunk(&isakmp_keyex_desc, outs, *g,
					       "keyex value");
	case IMPAIR_EMIT_OMIT:
		log_message(RC_LOG, logger, "IMPAIR: sending no KE (g^x) payload");
		return true;
	case IMPAIR_EMIT_EMPTY:
		log_message(RC_LOG, logger, "IMPAIR: sending empty KE (g^x)");
		return ikev1_out_generic_chunk(&isakmp_keyex_desc, outs,
					       EMPTY_CHUNK, "empty KE");
	case IMPAIR_EMIT_ROOF:
	default:
	{
		pb_stream z;
		uint8_t byte = impair.ke_payload - IMPAIR_EMIT_ROOF;
		log_message(RC_LOG, logger, "IMPAIR: sending bogus KE (g^x) == %u value to break DH calculations", byte);
		/* Only used to test sending/receiving bogus g^x */
		return ikev1_out_generic(&isakmp_keyex_desc, outs, &z) &&
			out_repeated_byte(byte, g->len, &z, "fake g^x") &&
			(close_output_pbs(&z), TRUE);
	}
	}
}

bool ikev1_ship_KE(struct state *st, struct pluto_crypto_req *r,
		   chunk_t *g, pb_stream *outs)
{
	unpack_KE_from_helper(st, r, g);
	return ikev1_justship_KE(st->st_logger, g, outs);
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
static stf_status main_inR1_outI2_tail(struct state *st, struct msg_digest *md,
				       struct pluto_crypto_req *r)
{
	/*
	 * HDR out.
	 * We can't leave this to comm_handle() because the isa_np
	 * depends on the type of Auth (eventually).
	 */
	pb_stream rbody;
	ikev1_init_out_pbs_echo_hdr(md, FALSE,
				    &reply_stream, reply_buffer, sizeof(reply_buffer),
				    &rbody);

	/* KE out */
	if (!ikev1_ship_KE(st, r, &st->st_gi, &rbody))
		return STF_INTERNAL_ERROR;

	/* Ni out */
	if (!ikev1_ship_nonce(&st->st_ni, r, &rbody, "Ni"))
		return STF_INTERNAL_ERROR;

	if (impair.bust_mi2) {
		/*
		 * generate a pointless large VID payload to push message
		 * over MTU
		 */
		pb_stream vid_pbs;

		/*
		 * This next payload value will get rewritten
		 * if ikev1_nat_traversal_add_natd is called.
		 */
		if (!ikev1_out_generic(&isakmp_vendor_id_desc,
					&rbody,
					&vid_pbs))
			return STF_INTERNAL_ERROR;

		if (!out_zero(1500 /*MTU?*/, &vid_pbs, "Filler VID"))
			return STF_INTERNAL_ERROR;

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
	rehash_state(st, &md->hdr.isa_ike_responder_spi);

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

static stf_status main_inI2_outR2_continue1_tail(struct state *st, struct msg_digest *md,
						struct pluto_crypto_req *r);

static crypto_req_cont_func main_inI2_outR2_continue1;	/* type assertion */

static void main_inI2_outR2_continue1(struct state *st,
				      struct msg_digest *md,
				      struct pluto_crypto_req *r)
{
	dbg("main_inI2_outR2_continue for #%lu: calculated ke+nonce, sending R2",
	    st->st_serialno);

	passert(md != NULL);
	stf_status e = main_inI2_outR2_continue1_tail(st, md, r);
	complete_v1_state_transition(md, e);
}

stf_status main_inI2_outR2(struct state *st, struct msg_digest *md)
{
	/* KE in */
	if (!accept_KE(&st->st_gi, "Gi", st->st_oakley.ta_dh,
		       md->chain[ISAKMP_NEXT_KE])) {
		return STF_FAIL + INVALID_KEY_INFORMATION;
	}

	/* Ni in */
	RETURN_STF_FAILURE(accept_v1_nonce(st->st_logger, md, &st->st_ni, "Ni"));

	/* decode certificate requests */
	ikev1_decode_cr(md);

	if (st->st_requested_ca != NULL)
		st->hidden_variables.st_got_certrequest = TRUE;

	ikev1_natd_init(st, md);

	request_ke_and_nonce("inI2_outR2 KE", st,
			     st->st_oakley.ta_dh,
			     main_inI2_outR2_continue1);
	return STF_SUSPEND;
}

/*
 * main_inI2_outR2_calcdone is unlike every other crypto_req_cont_func:
 * the state that it is working for may not yet care about the result.
 * We are precomputing the DH.
 * This also means that it isn't good at reporting an NSS error.
 */
static crypto_req_cont_func main_inI2_outR2_continue2;	/* type assertion */

static void main_inI2_outR2_continue2(struct state *st,
				      struct msg_digest *md,
				      struct pluto_crypto_req *r)
{
	dbg("main_inI2_outR2_calcdone for #%lu: calculate DH finished",
	    st->st_serialno);

	set_cur_state(st);

	if (finish_dh_secretiv(st, r))
		update_iv(st);

	/*
	 * If there was a packet received while we were calculating, then
	 * process it now.
	 * Otherwise, the result awaits the packet.
	 */
	if (md != NULL) {
		process_packet_tail(md);
	}
	reset_cur_state();
}

stf_status main_inI2_outR2_continue1_tail(struct state *st, struct msg_digest *md,
					  struct pluto_crypto_req *r)
{
	if (libreswan_fipsmode() && st->st_oakley.ta_prf == NULL) {
		log_state(RC_LOG_SERIOUS, st,
			  "Missing prf - algo not allowed in fips mode (inI2_outR2)?");
		return STF_FAIL + SITUATION_NOT_SUPPORTED;
	}

	/* send CR if auth is RSA and no preloaded RSA public key exists*/
	bool send_cr = FALSE;

	/* Build output packet HDR;KE;Nr */

	send_cr = (st->st_oakley.auth == OAKLEY_RSA_SIG) &&
		!has_preloaded_public_key(st) &&
		st->st_connection->spd.that.ca.ptr != NULL;

	/* HDR out */
	pb_stream rbody;
	ikev1_init_out_pbs_echo_hdr(md, FALSE,
				    &reply_stream, reply_buffer, sizeof(reply_buffer),
				    &rbody);

	/* KE out */
	passert(ikev1_ship_KE(st, r, &st->st_gr, &rbody));

	{
		/* Nr out */
		if (!ikev1_ship_nonce(&st->st_nr, r, &rbody, "Nr"))
			return STF_INTERNAL_ERROR;

		if (impair.bust_mr2) {
			/*
			 * generate a pointless large VID payload to push
			 * message over MTU
			 */
			pb_stream vid_pbs;

			if (!ikev1_out_generic(&isakmp_vendor_id_desc, &rbody,
					       &vid_pbs))
				return STF_INTERNAL_ERROR;

			if (!out_zero(1500 /*MTU?*/, &vid_pbs, "Filler VID"))
				return STF_INTERNAL_ERROR;

			close_output_pbs(&vid_pbs);
		}
	}

	/* CR out */
	if (send_cr) {
		if (st->st_connection->kind == CK_PERMANENT) {
			if (!ikev1_build_and_ship_CR(CERT_X509_SIGNATURE,
						     st->st_connection->spd.that.ca,
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
						free_generalNames(ca, FALSE);
						return STF_INTERNAL_ERROR;
					}
				}
				free_generalNames(ca, FALSE);
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
	 * next message will be encrypted, so, we need to have
	 * the DH value calculated. We can do this in the background,
	 * sending the reply right away. We have to be careful on the next
	 * state, since the other end may reply faster than we can calculate
	 * things. If it is the case, then the packet is placed in the
	 * continuation, and we let the continuation process it. If there
	 * is a retransmit, we keep only the last packet.
	 *
	 * Also, note that this is not a suspended state, since we are
	 * actually just doing work in the background.  md will not be
	 * retained.
	 */
	{
		dbg("main inI2_outR2: starting async DH calculation (group=%d)",
		    st->st_oakley.ta_dh->group);

		start_dh_v1_secretiv(main_inI2_outR2_continue2, "main_inI2_outR2_tail",
				     st, SA_RESPONDER, st->st_oakley.ta_dh);

		/* we are calculating in the background, so it doesn't count */
		dbg("#%lu %s:%u st->st_calculating = FALSE;", st->st_serialno, __func__, __LINE__);
		st->st_v1_offloaded_task_in_background = true;
	}
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
static stf_status main_inR2_outI3_continue_tail(struct msg_digest *md,
						pb_stream *rbody,
						struct pluto_crypto_req *r)
{
	struct state *const st = md->st;
	const struct connection *c = st->st_connection;
	const cert_t mycert = c->spd.this.cert;

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
		mycert.ty != CERT_NONE && mycert.u.nss_cert != NULL &&
		((c->spd.this.sendcert == CERT_SENDIFASKED &&
		  st->hidden_variables.st_got_certrequest) ||
		 c->spd.this.sendcert == CERT_ALWAYSSEND);

	bool send_authcerts = (send_cert &&
			  c->send_ca != CA_SEND_NONE);

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
			send_cert,
			send_authcerts);

	/*
	 * send certificate request, if we don't have a preloaded RSA
	 * public key
	 */
	bool send_cr = send_cert && !has_preloaded_public_key(st);

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
	bool initial_contact = c->initial_contact;
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
	pb_stream id_pbs; /* ID Payload; used later for hash calculation */
	enum next_payload_types_ikev1 auth_payload =
		st->st_oakley.auth == OAKLEY_PRESHARED_KEY ?
			ISAKMP_NEXT_HASH : ISAKMP_NEXT_SIG;

	{
		/*
		 * id_hd should be struct isakmp_id, but struct isakmp_ipsec_id
		 * allows build_id_payload() to work for both phases.
		 */
		shunk_t id_b;
		struct isakmp_ipsec_id id_hd = build_v1_id_payload(&c->spd.this, &id_b);
		if (!out_struct(&id_hd,
				&isakmp_ipsec_identification_desc,
				rbody,
				&id_pbs) ||
		    !pbs_out_hunk(id_b, &id_pbs, "my identity")) {
			free_auth_chain(auth_chain, chain_len);
			return STF_INTERNAL_ERROR;
		}

		close_output_pbs(&id_pbs);
	}

	/* CERT out */
	if (send_cert && impair.send_pkcs7_thingie) {
		log_state(RC_LOG, st, "IMPAIR: sending cert as pkcs7 blob");
		SECItem *pkcs7 = nss_pkcs7_blob(mycert.u.nss_cert, send_authcerts);
		if (!pexpect(pkcs7 != NULL)) {
			free_auth_chain(auth_chain, chain_len);
			return STF_INTERNAL_ERROR;
		}
		if (!ikev1_ship_CERT(CERT_PKCS7_WRAPPED_X509,
				     same_secitem_as_chunk(*pkcs7),
				     rbody)) {
			SECITEM_FreeItem(pkcs7, PR_TRUE);
			free_auth_chain(auth_chain, chain_len);
			return STF_INTERNAL_ERROR;
		}
	} else if (send_cert) {
		log_state(RC_LOG, st, "I am sending my cert");

		if (!ikev1_ship_CERT(mycert.ty,
				   get_dercert_from_nss_cert(mycert.u.nss_cert),
				   rbody)) {
			free_auth_chain(auth_chain, chain_len);
			return STF_INTERNAL_ERROR;
		}

		if (send_authcerts) {
			/* we've got CA certificates to send */
			log_state(RC_LOG, st, "I am sending a CA cert chain");
			if (!ikev1_ship_chain(auth_chain,
					      chain_len,
					      rbody,
					      mycert.ty)) {
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
		if (!ikev1_build_and_ship_CR(mycert.ty,
					     c->spd.that.ca,
					     rbody))
			return STF_INTERNAL_ERROR;
	}

	/* HASH_I or SIG_I out */
	{
		struct crypt_mac hash = main_mode_hash(st, SA_INITIATOR, &id_pbs);

		if (auth_payload == ISAKMP_NEXT_HASH) {
			/* HASH_I out */
			if (!ikev1_out_generic_raw(&isakmp_hash_desc,
						   rbody,
						   hash.ptr, hash.len, "HASH_I"))
				return STF_INTERNAL_ERROR;
		} else {
			/* SIG_I out */
			struct hash_signature sig;
			passert(sizeof(sig.ptr/*array*/) >= RSA_MAX_OCTETS);
			sig = v1_sign_hash_RSA(c, &hash, st->st_logger);
			if (sig.len == 0) {
				log_state(RC_LOG_SERIOUS, st,
					  "unable to locate my private key for RSA Signature");
				return STF_FAIL + AUTHENTICATION_FAILED;
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
		pb_stream notify_pbs;
		struct isakmp_notification isan = {
			.isan_doi = ISAKMP_DOI_IPSEC,
			.isan_protoid = PROTO_ISAKMP,
			.isan_spisize = COOKIE_SIZE * 2,
			.isan_type = IPSEC_INITIAL_CONTACT,
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
	if (!ikev1_encrypt_message(rbody, st))
		return STF_INTERNAL_ERROR; /* ??? we may be partly committed */

	return STF_OK;
}

static crypto_req_cont_func main_inR2_outI3_continue;	/* type assertion */

static void main_inR2_outI3_continue(struct state *st,
				     struct msg_digest *md,
				     struct pluto_crypto_req *r)
{
	dbg("main_inR2_outI3_cryptotail for #%lu: calculated DH, sending R1",
	    st->st_serialno);

	passert(md != NULL);	/* ??? how would this fail? */

	pb_stream rbody;
	ikev1_init_out_pbs_echo_hdr(md, TRUE,
				    &reply_stream, reply_buffer, sizeof(reply_buffer),
				    &rbody);
	stf_status e = main_inR2_outI3_continue_tail(md, &rbody, r);
	complete_v1_state_transition(md, e);
}

stf_status main_inR2_outI3(struct state *st, struct msg_digest *md)
{
	/* KE in */
	if (!accept_KE(&st->st_gr, "Gr",
		       st->st_oakley.ta_dh,
		       md->chain[ISAKMP_NEXT_KE])) {
		return STF_FAIL + INVALID_KEY_INFORMATION;
	}

	/* Nr in */
	RETURN_STF_FAILURE(accept_v1_nonce(st->st_logger, md, &st->st_nr, "Nr"));
	start_dh_v1_secretiv(main_inR2_outI3_continue, "aggr outR1 DH",
			     st, SA_INITIATOR, st->st_oakley.ta_dh);
	return STF_SUSPEND;
}

/*
 * Process the Main Mode ID Payload and the Authenticator
 * (Hash or Signature Payload).
 * Note: oakley_id_and_auth may switch the connection being used!
 * But only if we are a Main Mode Responder.
 * XXX: This is used by aggressive mode too, move to ikev1.c ???
 */
stf_status oakley_id_and_auth(struct msg_digest *md, bool initiator,
			bool aggrmode)
{
	struct state *st = md->st;
	stf_status r = STF_OK;

	/*
	 * ID Payload in.
	 * Note: ikev1_decode_peer_id may switch the connection being used!
	 * But only if we are a Main Mode Responder.
	 */
	if (!st->st_peer_alt_id) {
		if (!ikev1_decode_peer_id(md, initiator, aggrmode)) {
			dbg("Peer ID failed to decode");
			return STF_FAIL + INVALID_ID_INFORMATION;
		}
	}

	/*
	 * process any CERT payloads if aggrmode
	 */
	if (!st->st_peer_alt_id) {
		if (!v1_verify_certs(md)) {
			return STF_FAIL + INVALID_ID_INFORMATION;
		}
	}

	/*
	 * Hash the ID Payload.
	 * main_mode_hash requires idpl->cur to be at end of payload
	 * so we temporarily set if so.
	 */
	struct crypt_mac hash;
	{
		pb_stream *idpl = &md->chain[ISAKMP_NEXT_ID]->pbs;
		uint8_t *old_cur = idpl->cur;

		idpl->cur = idpl->roof;
		/* authenticating other end, flip role! */
		hash = main_mode_hash(st, initiator ? SA_RESPONDER : SA_INITIATOR, idpl);
		idpl->cur = old_cur;
	}

	switch (st->st_oakley.auth) {
	case OAKLEY_PRESHARED_KEY:
	{
		pb_stream *const hash_pbs = &md->chain[ISAKMP_NEXT_HASH]->pbs;

		/*
		 * XXX: looks a lot like the hack CHECK_QUICK_HASH(),
		 * except this one doesn't return.  Strong indicator
		 * that CHECK_QUICK_HASH should be changed to a
		 * function and also not magically force caller to
		 * return.
		 */
		if (pbs_left(hash_pbs) != hash.len ||
			!memeq(hash_pbs->cur, hash.ptr, hash.len)) {
			if (DBGP(DBG_CRYPT)) {
				DBG_dump("received HASH:",
					 hash_pbs->cur, pbs_left(hash_pbs));
			}
			log_state(RC_LOG_SERIOUS, st,
				  "received Hash Payload does not match computed value");
			/* XXX Could send notification back */
			r = STF_FAIL + INVALID_HASH_INFORMATION;
		} else {
			dbg("received '%s' message HASH_%s data ok",
			    aggrmode ? "Aggr" : "Main",
			    initiator ? "R" : "I" /*reverse*/);
		}
		break;
	}

	case OAKLEY_RSA_SIG:
	{
		r = RSA_check_signature(st, &hash,
					&md->chain[ISAKMP_NEXT_SIG]->pbs, 0 /* for ikev2 only*/);
		if (r != STF_OK) {
			dbg("received '%s' message SIG_%s data did not match computed value",
			    aggrmode ? "Aggr" : "Main",
			    initiator ? "R" : "I" /*reverse*/);
		}
		break;
	}
	/* These are the only IKEv1 AUTH methods we support */
	default:
		bad_case(st->st_oakley.auth);
	}

	if (r == STF_OK)
		dbg("authentication succeeded");
	return r;
}


/*
 * STATE_MAIN_R2:
 * PSK_AUTH: HDR*, IDi1, HASH_I --> HDR*, IDr1, HASH_R
 * DS_AUTH: HDR*, IDi1, [ CERT, ] SIG_I --> HDR*, IDr1, [ CERT, ] SIG_R
 * PKE_AUTH, RPKE_AUTH: HDR*, HASH_I --> HDR*, HASH_R
 */

stf_status main_inI3_outR3(struct state *st, struct msg_digest *md)
{
	pexpect(st == md->st);
	st = md->st;

	/* handle case where NSS balked at generating DH */
	if (st->st_shared_nss == NULL)
		return STF_FAIL + INVALID_KEY_INFORMATION;

	if (!v1_decode_certs(md)) {
		log_state(RC_LOG, st, "X509: CERT payload bogus or revoked");
		return STF_FAIL + INVALID_ID_INFORMATION;
	}

	/*
	 * ID and HASH_I or SIG_I in
	 * Note: oakley_id_and_auth may switch the connection being used
	 * since we are a Main Mode Responder.
	 */
	{
		stf_status r = oakley_id_and_auth(md, FALSE, FALSE);
		if (r != STF_OK)
			return r;
	}
	struct connection *c = st->st_connection;

	/* send certificate if we have one and auth is RSA */
	cert_t mycert = c->spd.this.cert;

	bool send_cert = st->st_oakley.auth == OAKLEY_RSA_SIG &&
		mycert.ty != CERT_NONE && mycert.u.nss_cert != NULL &&
		((c->spd.this.sendcert == CERT_SENDIFASKED &&
		  st->hidden_variables.st_got_certrequest) ||
		 c->spd.this.sendcert == CERT_ALWAYSSEND);

	bool send_authcerts = (send_cert &&
			  c->send_ca != CA_SEND_NONE);

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
			send_cert,
			send_authcerts);

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
	pb_stream rbody;
	ikev1_init_out_pbs_echo_hdr(md, TRUE,
				    &reply_stream, reply_buffer, sizeof(reply_buffer),
				    &rbody);

	enum next_payload_types_ikev1 auth_payload = st->st_oakley.auth == OAKLEY_PRESHARED_KEY ?
		ISAKMP_NEXT_HASH : ISAKMP_NEXT_SIG;

	/* IDir out */
	pb_stream r_id_pbs; /* ID Payload; used later for hash calculation */

	{
		/*
		 * id_hd should be struct isakmp_id, but struct isakmp_ipsec_id
		 * allows build_id_payload() to work for both phases.
		 */
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

	/* CERT out, if we have one */
	if (send_cert && impair.send_pkcs7_thingie) {
		log_state(RC_LOG, st, "IMPAIR: sending cert as pkcs7 blob");
		SECItem *pkcs7 = nss_pkcs7_blob(mycert.u.nss_cert, send_authcerts);
		if (!pexpect(pkcs7 != NULL)) {
			free_auth_chain(auth_chain, chain_len);
			return STF_INTERNAL_ERROR;
		}
		if (!ikev1_ship_CERT(CERT_PKCS7_WRAPPED_X509,
				     same_secitem_as_chunk(*pkcs7),
				     &rbody)) {
			SECITEM_FreeItem(pkcs7, PR_TRUE);
			free_auth_chain(auth_chain, chain_len);
			return STF_INTERNAL_ERROR;
		}
	} else if (send_cert) {
		log_state(RC_LOG, st, "I am sending my cert");
		if (!ikev1_ship_CERT(mycert.ty,
				     get_dercert_from_nss_cert(mycert.u.nss_cert),
				     &rbody)) {
			free_auth_chain(auth_chain, chain_len);
			return STF_INTERNAL_ERROR;
		}

		if (send_authcerts) {
			log_state(RC_LOG, st, "I am sending a CA cert chain");
			if (!ikev1_ship_chain(auth_chain, chain_len,
					      &rbody, mycert.ty)) {
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
		struct crypt_mac hash = main_mode_hash(st, SA_RESPONDER, &r_id_pbs);

		if (auth_payload == ISAKMP_NEXT_HASH) {
			/* HASH_R out */
			if (!ikev1_out_generic_raw(&isakmp_hash_desc, &rbody,
						   hash.ptr, hash.len, "HASH_R"))
				return STF_INTERNAL_ERROR;
		} else {
			/* SIG_R out */
			struct hash_signature sig;
			passert(sizeof(sig.ptr/*array*/) >= RSA_MAX_OCTETS);
			sig = v1_sign_hash_RSA(c, &hash, st->st_logger);
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

	/* encrypt message, sans fixed part of header */

	if (!ikev1_encrypt_message(&rbody, st))
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

	if (c->remotepeertype == CISCO &&
	    c->newest_isakmp_sa != SOS_NOBODY &&
	    c->spd.this.xauth_client) {
		dbg("Skipping XAUTH for rekey for Cisco Peer compatibility.");
		st->hidden_variables.st_xauth_client_done = TRUE;
		st->st_oakley.doing_xauth = FALSE;

		if (c->spd.this.modecfg_client) {
			dbg("Skipping ModeCFG for rekey for Cisco Peer compatibility.");
			st->hidden_variables.st_modecfg_vars_set = TRUE;
			st->hidden_variables.st_modecfg_started = TRUE;
		}
	}

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
 * STATE_MAIN_I3:
 * Handle HDR*;IDir;HASH/SIG_R from responder.
 *
 */

stf_status main_inR3(struct state *st, struct msg_digest *md)
{
	if (!v1_decode_certs(md)) {
		log_state(RC_LOG, st, "X509: CERT payload bogus or revoked");
		return STF_FAIL + INVALID_ID_INFORMATION;
	}

	/*
	 * ID and HASH_R or SIG_R in
	 * Note: oakley_id_and_auth will not switch the connection being used
	 * because we are the Responder.
	 */
	{
		stf_status r = oakley_id_and_auth(md, TRUE, FALSE);
		if (r != STF_OK)
			return r;
	}
	struct connection *c = st->st_connection;

	/* Done input */

	/*
	 * It seems as per Cisco implementation, XAUTH and MODECFG
	 * are not supposed to be performed again during rekey
	 */
	if (c->remotepeertype == CISCO &&
		c->newest_isakmp_sa != SOS_NOBODY &&
		c->spd.this.xauth_client) {
		dbg("Skipping XAUTH for rekey for Cisco Peer compatibility.");
		st->hidden_variables.st_xauth_client_done = TRUE;
		st->st_oakley.doing_xauth = FALSE;

		if (c->spd.this.modecfg_client) {
			dbg("Skipping ModeCFG for rekey for Cisco Peer compatibility.");
			st->hidden_variables.st_modecfg_vars_set = TRUE;
			st->hidden_variables.st_modecfg_started = TRUE;
		}
	}

	IKE_SA_established(pexpect_ike_sa(st));
#ifdef USE_XFRM_INTERFACE
	if (c->xfrmi != NULL && c->xfrmi->if_id != yn_no)
		if (add_xfrmi(c, st->st_logger))
			return STF_FATAL;
#endif
	linux_audit_conn(st, LAK_PARENT_START);

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
	pb_stream rbody;

	msgid = generate_msgid(st);

	init_out_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
		"ISAKMP notify");

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
		pb_stream notify_pbs;
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
		if (!ikev1_encrypt_message(&rbody, st))
			return STF_INTERNAL_ERROR;

		send_ike_msg_without_recording(st, &reply_stream, "ISAKMP notify");

		/* get back old IV for this state */
		restore_iv(st, old_iv);
		restore_new_iv(st, old_new_iv);
	}

	return STF_IGNORE;
}

/*
 * Send a notification to the peer. We could decide
 * whether to send the notification, based on the type and the
 * destination, if we care to.
 * Note: some calls are from send_notification_from_md and
 * those calls pass a fake state as sndst.
 * Note: msgid is in different order here from other calls :/
 */
static void send_notification(struct logger *logger,
			      struct state *sndst /*possibly fake*/,
			      notification_t type,
			      struct state *encst,
			      msgid_t msgid, u_char *icookie, u_char *rcookie,
			      u_char protoid)
{
	/* buffer in which to marshal our notification.
	 * We don't use reply_buffer/reply_stream because they might be in use.
	 */
	u_char buffer[1024];	/* ??? large enough for any notification? */
	pb_stream pbs;

	pb_stream r_hdr_pbs;
	static monotime_t last_malformed = MONOTIME_EPOCH;
	monotime_t n = mononow();

	switch (type) {
	case PAYLOAD_MALFORMED:
		/* only send one per second. */
		/* ??? this depends on monotime_t having a one-second granularity */
		if (monobefore(last_malformed, n))
			return;

		last_malformed = n;

		/*
		 * If a state gets too many of these, delete it.
		 *
		 * Note that the fake state of send_notification_from_md
		 * will never trigger this (a Good Thing since it
		 * must not be deleted).
		 */
		sndst->hidden_variables.st_malformed_sent++;
		if (sndst->hidden_variables.st_malformed_sent >
		    MAXIMUM_MALFORMED_NOTIFY) {
			log_message(RC_LOG, logger, "too many (%d) malformed payloads. Deleting state",
				    sndst->hidden_variables.st_malformed_sent);
			delete_state(sndst);
			/* note: no md->st to clear */
			return;
		}

		if (sndst->st_v1_iv.len != 0) {
			LOG_MESSAGE(RC_LOG, logger, buf) {
				jam(buf, "payload malformed.  IV: ");
				jam_dump_bytes(buf, sndst->st_v1_iv.ptr,
					       sndst->st_v1_iv.len);
			}
		}

		/*
		 * do not encrypt notification, since #1 reason for malformed
		 * payload is that the keys are all messed up.
		 */
		encst = NULL;
		break;

	case INVALID_FLAGS:
		/*
		 * invalid flags usually includes encryption flags, so do not
		 * send encrypted.
		 */
		encst = NULL;
		break;
	default:
		/* quiet GCC warning */
		break;
	}

	if (encst != NULL && !IS_ISAKMP_ENCRYPTED(encst->st_state->kind))
		encst = NULL;

	{
		/*
		 * This will pick up cur_state, if any (which means it
		 * is still relying on cur_state :-().  Can't use
		 * SNDST as that may be fake.
		 */
		endpoint_buf b;
		log_message(RC_NOTIFICATION + type, logger,
			    "sending %snotification %s to %s",
			    encst ? "encrypted " : "",
			    enum_name(&ikev1_notify_names, type),
			    str_endpoint(&sndst->st_remote_endpoint, &b));
	}

	init_out_pbs(&pbs, buffer, sizeof(buffer), "notification msg");

	/* HDR* */
	{
		/* ??? "keep it around for TPM" */
		struct isakmp_hdr hdr = {
			.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
				ISAKMP_MINOR_VERSION,
			.isa_xchg = ISAKMP_XCHG_INFO,
			.isa_msgid = msgid,
			.isa_flags = encst ? ISAKMP_FLAGS_v1_ENCRYPTION : 0,
		};
		if (icookie != NULL)
			memcpy(hdr.isa_ike_initiator_spi.bytes, icookie, COOKIE_SIZE);
		if (rcookie != NULL)
			memcpy(hdr.isa_ike_responder_spi.bytes, rcookie, COOKIE_SIZE);
		passert(out_struct(&hdr, &isakmp_hdr_desc, &pbs, &r_hdr_pbs));
	}

	/* HASH -- value to be filled later */
	struct v1_hash_fixup hash_fixup;
	if (encst != NULL) {
		if (!emit_v1_HASH(V1_HASH_1, "send notification",
				  IMPAIR_v1_NOTIFICATION_EXCHANGE,
				  encst, &hash_fixup, &r_hdr_pbs)) {
			/* return STF_INTERNAL_ERROR; */
			return;
		}
	}

	/* Notification Payload */
	{
		pb_stream not_pbs;
		struct isakmp_notification isan = {
			.isan_doi = ISAKMP_DOI_IPSEC,
			.isan_type = type,
			.isan_spisize = 0,
			.isan_protoid = protoid,
		};

		if (!out_struct(&isan, &isakmp_notification_desc,
					&r_hdr_pbs, &not_pbs)) {
			log_message(RC_LOG, logger,
				    "failed to build notification in send_notification");
			return;
		}

		close_output_pbs(&not_pbs);
	}

	/* calculate hash value and patch into Hash Payload */
	if (encst != NULL) {
		fixup_v1_HASH(encst, &hash_fixup, msgid, r_hdr_pbs.cur);
	}

	if (encst != NULL) {
		/* Encrypt message (preserve st_iv) */
		/* ??? why not preserve st_new_iv? */
		struct crypt_mac old_iv;

		save_iv(encst, old_iv);

		if (!IS_ISAKMP_SA_ESTABLISHED(encst->st_state)) {
			update_iv(encst);
		}
		init_phase2_iv(encst, &msgid);
		passert(ikev1_encrypt_message(&r_hdr_pbs, encst));

		restore_iv(encst, old_iv);
	} else {
		close_output_pbs(&r_hdr_pbs);
	}

	send_ike_msg_without_recording(sndst, &pbs, "notification packet");
}

void send_notification_from_state(struct state *st, enum state_kind from_state,
				notification_t type)
{
	struct state *p1st;

	passert(st != NULL);

	if (from_state == STATE_UNDEFINED)
		from_state = st->st_state->kind;

	if (IS_QUICK(from_state)) {
		p1st = find_phase1_state(st->st_connection,
					ISAKMP_SA_ESTABLISHED_STATES);
		if ((p1st == NULL) ||
			(!IS_ISAKMP_SA_ESTABLISHED(p1st->st_state))) {
			log_state(RC_LOG_SERIOUS, st,
				  "no Phase1 state for Quick mode notification");
			return;
		}
		send_notification(st->st_logger, st, type, p1st, generate_msgid(p1st),
				  st->st_ike_spis.initiator.bytes, st->st_ike_spis.responder.bytes,
				  PROTO_ISAKMP);
	} else if (IS_ISAKMP_ENCRYPTED(from_state)) {
		send_notification(st->st_logger, st, type, st, generate_msgid(st),
				st->st_ike_spis.initiator.bytes, st->st_ike_spis.responder.bytes,
				PROTO_ISAKMP);
	} else {
		/* no ISAKMP SA established - don't encrypt notification */
		send_notification(st->st_logger, st, type, NULL, v1_MAINMODE_MSGID,
				st->st_ike_spis.initiator.bytes, st->st_ike_spis.responder.bytes,
				PROTO_ISAKMP);
	}
}

void send_notification_from_md(struct msg_digest *md, notification_t type)
{
	/*
	 * Create a fake state object to be able to use send_notification.
	 * This is somewhat dangerous: the fake state must not be deleted
	 * or have almost any other operation performed on it.
	 * Ditto for fake connection.
	 *
	 * ??? how can we be sure to have faked all salient fields correctly?
	 *
	 * Most details must be left blank (eg. pointers
	 * set to NULL).  struct initialization is good at this.
	 *
	 * We need to set [??? we don't -- is this still true?]:
	 *   st_connection->that.host_addr
	 *   st_connection->that.host_port
	 *   st_connection->interface
	 */
	struct connection fake_connection = {
		.interface = md->iface,
		.policy = POLICY_IKE_FRAG_FORCE, 	/* for should_fragment_ike_msg() */
	};

	struct ike_sa fake_ike = {
		.sa = {
			.st_serialno = SOS_NOBODY,
			.st_connection = &fake_connection,	/* for should_fragment_ike_msg() */
			.st_state = finite_states[STATE_UNDEFINED],
			.st_remote_endpoint = md->sender,
		},
	};

	passert(md != NULL);

	update_ike_endpoints(&fake_ike, md);
	send_notification(md->md_logger, &fake_ike.sa, type, NULL, 0,
			  md->hdr.isa_ike_initiator_spi.bytes, md->hdr.isa_ike_responder_spi.bytes,
			  PROTO_ISAKMP);
}

/*
 * Send a Delete Notification to announce deletion of ISAKMP SA or
 * inbound IPSEC SAs. Does nothing if no such SAs are being deleted.
 * Delete Notifications cannot announce deletion of outbound IPSEC/ISAKMP SAs.
 *
 * @param st State struct (we hope it has some SA's related to it)
 */
void send_v1_delete(struct state *st)
{
	/* buffer in which to marshal our deletion notification.
	 * We don't use reply_buffer/reply_stream because they might be in use.
	 */
	u_char buffer[8192];	/* ??? large enough for any deletion notification? */
	pb_stream reply_pbs;

	pb_stream r_hdr_pbs;
	msgid_t msgid;
	struct state *p1st;
	ip_said said[EM_MAXRELSPIS];
	ip_said *ns = said;
	bool isakmp_sa = FALSE;

	/* If there are IPsec SA's related to this state struct... */
	if (IS_IPSEC_SA_ESTABLISHED(st)) {
		/* Find their phase1 state object */
		p1st = find_phase1_state(st->st_connection,
					ISAKMP_SA_ESTABLISHED_STATES);
		if (p1st == NULL) {
			dbg("no Phase 1 state for Delete");
			return;
		}

		if (st->st_ah.present) {
			*ns = said3(&st->st_connection->spd.this.host_addr, st->st_ah.our_spi, &ip_protocol_ah);
			ns++;
		}
		if (st->st_esp.present) {
			*ns = said3(&st->st_connection->spd.this.host_addr, st->st_esp.our_spi, &ip_protocol_esp);
			ns++;
		}

		passert(ns != said); /* there must be some SAs to delete */
	} else if (IS_ISAKMP_SA_ESTABLISHED(st->st_state)) {
		/* or ISAKMP SA's... */
		p1st = st;
		isakmp_sa = TRUE;
	} else {
		return; /* nothing to do */
	}

	msgid = generate_msgid(p1st);

	init_out_pbs(&reply_pbs, buffer, sizeof(buffer), "delete msg");

	/* HDR* */
	{
		struct isakmp_hdr hdr = {
			.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
				ISAKMP_MINOR_VERSION,
			.isa_xchg = ISAKMP_XCHG_INFO,
			.isa_msgid = msgid,
			.isa_flags = ISAKMP_FLAGS_v1_ENCRYPTION,
		};
		hdr.isa_ike_initiator_spi = p1st->st_ike_spis.initiator;
		hdr.isa_ike_responder_spi = p1st->st_ike_spis.responder;
		passert(out_struct(&hdr, &isakmp_hdr_desc, &reply_pbs,
				   &r_hdr_pbs));
	}

	/* HASH -- value to be filled later */
	struct v1_hash_fixup hash_fixup;
	if (!emit_v1_HASH(V1_HASH_1, "send delete",
			  IMPAIR_v1_DELETE_EXCHANGE,
			  p1st, &hash_fixup, &r_hdr_pbs)) {
		return /* STF_INTERNAL_ERROR */;
	}

	/* Delete Payloads */
	if (isakmp_sa) {
		pb_stream del_pbs;
		struct isakmp_delete isad = {
			.isad_doi = ISAKMP_DOI_IPSEC,
			.isad_spisize = 2 * COOKIE_SIZE,
			.isad_protoid = PROTO_ISAKMP,
			.isad_nospi = 1,
		};

		passert(out_struct(&isad, &isakmp_delete_desc, &r_hdr_pbs,
				   &del_pbs));
		passert(out_raw(st->st_ike_spis.initiator.bytes, COOKIE_SIZE,
				&del_pbs, "initiator SPI"));
		passert(out_raw(st->st_ike_spis.responder.bytes, COOKIE_SIZE,
				&del_pbs, "responder SPI"));
		close_output_pbs(&del_pbs);
	} else {
		while (ns != said) {
			pb_stream del_pbs;
			ns--;
			struct isakmp_delete isad = {
				.isad_doi = ISAKMP_DOI_IPSEC,
				.isad_spisize = sizeof(ipsec_spi_t),
				.isad_protoid = ns->proto->ikev1,
				.isad_nospi = 1,
			};

			passert(out_struct(&isad, &isakmp_delete_desc,
					   &r_hdr_pbs, &del_pbs));
			passert(out_raw(&ns->spi, sizeof(ipsec_spi_t),
					&del_pbs, "delete payload"));
			close_output_pbs(&del_pbs);

			if (impair.ikev1_del_with_notify) {
				pb_stream cruft_pbs;

				log_state(RC_LOG, st, "IMPAIR: adding bogus Notify payload after IKE Delete payload");
				struct isakmp_notification isan = {
					.isan_doi = ISAKMP_DOI_IPSEC,
					.isan_protoid = PROTO_ISAKMP,
					.isan_spisize = COOKIE_SIZE * 2,
					.isan_type = INVALID_PAYLOAD_TYPE,
				};

				passert(out_struct(&isan, &isakmp_notification_desc, &r_hdr_pbs,
					&cruft_pbs));
				passert(out_raw(&ns->spi, sizeof(ipsec_spi_t), &cruft_pbs,
					"notify payload"));
				close_output_pbs(&cruft_pbs);
			}
		}
	}

	/* calculate hash value and patch into Hash Payload */
	fixup_v1_HASH(p1st, &hash_fixup, msgid, r_hdr_pbs.cur);

	/*
	 * Do a dance to avoid needing a new state object.
	 * We use the Phase 1 State. This is the one with right
	 * IV, for one thing.
	 * The tricky bits are:
	 * - we need to preserve (save/restore) st_iv (but not st_iv_new)
	 * - we need to preserve (save/restore) st_tpacket.
	 */
	{
		struct crypt_mac old_iv;

		save_iv(p1st, old_iv);
		init_phase2_iv(p1st, &msgid);

		passert(ikev1_encrypt_message(&r_hdr_pbs, p1st));

		send_ike_msg_without_recording(p1st, &reply_pbs, "delete notify");

		/* get back old IV for this state */
		restore_iv(p1st, old_iv);
	}
}

/*
 * Accept a Delete SA notification, and process it if valid.
 *
 * @param st State structure
 * @param md Message Digest
 * @param p Payload digest
 *
 * returns TRUE to indicate st needs to be deleted.
 *	We dare not do that ourselves because st is still in use.
 *	accept_self_delete must be called to do this
 *	at a more appropriate time.
 */
bool accept_delete(struct msg_digest *md,
		struct payload_digest *p)
{
	struct state *st = md->st;
	struct isakmp_delete *d = &(p->payload.delete);
	size_t sizespi;
	int i;
	bool self_delete = FALSE;

	/* We only listen to encrypted notifications */
	if (!md->encrypted) {
		log_state(RC_LOG_SERIOUS, st,
			  "ignoring Delete SA payload: not encrypted");
		return FALSE;
	}

	/* If there is no SA related to this request, but it was encrypted */
	if (!IS_ISAKMP_SA_ESTABLISHED(st->st_state)) {
		/* can't happen (if msg is encrypt), but just to be sure */
		log_state(RC_LOG_SERIOUS, st,
			  "ignoring Delete SA payload: ISAKMP SA not established");
		return FALSE;
	}

	if (d->isad_nospi == 0) {
		log_state(RC_LOG_SERIOUS, st,
			  "ignoring Delete SA payload: no SPI");
		return FALSE;
	}

	switch (d->isad_protoid) {
	case PROTO_ISAKMP:
		sizespi = 2 * COOKIE_SIZE;
		break;

	case PROTO_IPSEC_AH:
	case PROTO_IPSEC_ESP:
		sizespi = sizeof(ipsec_spi_t);
		break;

	case PROTO_IPCOMP:
		/* nothing interesting to delete */
		return FALSE;

	default:
		log_state(RC_LOG_SERIOUS, st,
			  "ignoring Delete SA payload: unknown Protocol ID (%s)",
			  enum_show(&ikev1_protocol_names, d->isad_protoid));
		return false;
	}

	if (d->isad_spisize != sizespi) {
		log_state(RC_LOG_SERIOUS, st,
			  "ignoring Delete SA payload: bad SPI size (%d) for %s",
			  d->isad_spisize,
			  enum_show(&ikev1_protocol_names, d->isad_protoid));
		return false;
	}

	if (pbs_left(&p->pbs) != d->isad_nospi * sizespi) {
		log_state(RC_LOG_SERIOUS, st,
			  "ignoring Delete SA payload: invalid payload size");
		return false;
	}

	for (i = 0; i < d->isad_nospi; i++) {
		if (d->isad_protoid == PROTO_ISAKMP) {
			/*
			 * ISAKMP
			 */
			ike_spis_t cookies;
			struct state *dst;

			if (!in_raw(&cookies.initiator, COOKIE_SIZE, &p->pbs, "iCookie"))
				return FALSE;

			if (!in_raw(&cookies.responder, COOKIE_SIZE, &p->pbs, "rCookie"))
				return FALSE;

			dst = find_state_ikev1(&cookies, v1_MAINMODE_MSGID);

			if (dst == NULL) {
				log_state(RC_LOG_SERIOUS, st, "ignoring Delete SA payload: ISAKMP SA not found (maybe expired)");
			} else if (!same_peer_ids(st->st_connection,
							dst->st_connection,
							NULL)) {
				/*
				 * we've not authenticated the relevant
				 * identities
				 */
				log_state(RC_LOG_SERIOUS, st, "ignoring Delete SA payload: ISAKMP SA used to convey Delete has different IDs from ISAKMP SA it deletes");
			} else if (dst == st) {
				/*
				 * remember this for later:
				 * we need st to do any remaining deletes
				 */
				self_delete = TRUE;
			} else {
				/* note: this code is cloned for handling self_delete */
				log_state(RC_LOG_SERIOUS, st, "received Delete SA payload: deleting ISAKMP State #%lu",
					  dst->st_serialno);
				if (nat_traversal_enabled && dst->st_connection->ikev1_natt != NATT_NONE) {
					nat_traversal_change_port_lookup(md, dst);
					v1_maybe_natify_initiator_endpoints(st, HERE);
			}
				delete_state(dst);
			}
		} else {
			/*
			 * IPSEC (ESP/AH)
			 */
			ipsec_spi_t spi;	/* network order */

			if (!in_raw(&spi, sizeof(spi), &p->pbs, "SPI"))
				return FALSE;

			bool bogus;
			struct state *dst = find_phase2_state_to_delete(st,
							d->isad_protoid,
							spi,
							&bogus);

			passert(dst != st);	/* st is an IKE SA */
			if (dst == NULL) {
				log_state(RC_LOG_SERIOUS, st,
					  "ignoring Delete SA payload: %s SA(0x%08" PRIx32 ") not found (maybe expired)",
					  enum_show(&ikev1_protocol_names,
						    d->isad_protoid),
					  ntohl(spi));
			} else {
				if (bogus) {
					log_state(RC_LOG_SERIOUS, st,
						  "warning: Delete SA payload: %s SA(0x%08" PRIx32 ") is our own SPI (bogus implementation) - deleting anyway",
						  enum_show(&ikev1_protocol_names,
							    d->isad_protoid),
						  ntohl(spi));
				}

				struct connection *rc = dst->st_connection;
				struct connection *oldc = push_cur_connection(rc);

				if (nat_traversal_enabled && dst->st_connection->ikev1_natt != NATT_NONE) {
					nat_traversal_change_port_lookup(md, dst);
					v1_maybe_natify_initiator_endpoints(st, HERE);
				}

				if (rc->newest_ipsec_sa == dst->st_serialno &&
					(rc->policy & POLICY_UP)) {
					/*
					 * Last IPsec SA for a permanent
					 * connection that we have initiated.
					 * Replace it.
					 *
					 * Useful if the other peer is
					 * rebooting.
					 */
					log_state(RC_LOG_SERIOUS, st,
						  "received Delete SA payload: replace IPsec State #%lu now",
						  dst->st_serialno);
					dst->st_replace_margin = deltatime(0);
					event_force(EVENT_SA_REPLACE, dst);
				} else {
					log_state(RC_LOG_SERIOUS, st,
						  "received Delete SA(0x%08" PRIx32 ") payload: deleting IPsec State #%lu",
						  ntohl(spi),
						  dst->st_serialno);
					delete_state(dst);
					if (md->st == dst)
						md->st = NULL;
				}

				if (rc->newest_ipsec_sa == SOS_NOBODY) {
					dbg("connection '%s' -POLICY_UP", rc->name);
					rc->policy &= ~POLICY_UP;
					if (!shared_phase1_connection(rc)) {
						flush_pending_by_connection(rc);
						/* why loop? there can be only one IKE SA, just delete_state(st) ? */
						delete_states_by_connection(rc, FALSE,
									    null_fd/*no-whack?*/);
						md->st = NULL;
					}
					reset_cur_connection();
				}
				/* reset connection */
				pop_cur_connection(oldc);
			}
		}
	}

	return self_delete;
}

/* now it is safe to delete our sponsor */
void accept_self_delete(struct msg_digest *md)
{
	struct state *st = md->st;

	/* note: this code is cloned from handling ISAKMP non-self_delete */
	log_state(RC_LOG_SERIOUS, st, "received Delete SA payload: self-deleting ISAKMP State #%lu",
		  st->st_serialno);
	if (nat_traversal_enabled && st->st_connection->ikev1_natt != NATT_NONE) {
		nat_traversal_change_port_lookup(md, st);
		v1_maybe_natify_initiator_endpoints(st, HERE);
	}
	delete_state(st);
	md->st = st = NULL;
}
