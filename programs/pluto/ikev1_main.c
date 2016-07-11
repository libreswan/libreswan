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
 * Copyright (C) 2010-2013 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
 * Copyright (C) 2013 Wolfgang Nothdurft <wolfgang@linogate.de>
 * Copyright (C) 2013 Paul Wouters <pwouters@redhat.com>
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
#include <sys/time.h> /* for gettimeofday */
#include <resolv.h>

#include <libreswan.h>
#include "libreswan/pfkeyv2.h"

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
#include "dnskey.h" /* needs keys.h and adns.h */
#include "kernel.h" /* needs connections.h */
#include "log.h"
#include "cookie.h"
#include "server.h"
#include "spdb.h"
#include "timer.h"
#include "rnd.h"
#include "ipsec_doi.h" /* needs demux.h and state.h */
#include "whack.h"
#include "fetch.h"
#include "asn1.h"
#include "pending.h"

#include "sha1.h"
#include "md5.h"
#include "crypto.h" /* requires sha1.h and md5.h */
#include "secrets.h"

#include "ike_alg.h"
#include "kernel_alg.h"
#include "plutoalg.h"
#include "pluto_crypt.h"
#include "ikev1.h"
#include "ikev1_continuations.h"

#include "ikev1_xauth.h"

#include "vendor.h"
#include "nat_traversal.h"
#include "ikev1_dpd.h"
#include "pluto_x509.h"

#include "lswfips.h"

/*
 * Initiate an Oakley Main Mode exchange.
 * --> HDR;SA
 * Note: this is not called from demux.c
 */
stf_status main_outI1(int whack_sock,
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
	struct msg_digest md; /* use reply/rbody found inside */

	int numvidtosend = 1; /* we always send DPD VID */

	if (drop_new_exchanges()) {
		/* Only drop outgoing opportunistic connections */
		if (c->policy & POLICY_OPPORTUNISTIC) {
			return STF_IGNORE;
		}
	}

	st = new_state();

	/* Increase VID counter for VID_IKE_FRAGMENTATION */
	if (c->policy & POLICY_IKE_FRAG_ALLOW)
		numvidtosend++;

	if (nat_traversal_enabled)
		numvidtosend++;

	if (c->cisco_unity) {
		numvidtosend++;
	}

	if (c->fake_strongswan) {
		numvidtosend++;
	}

	if (c->send_vendorid) {
		numvidtosend++;
	}

	if (c->spd.this.xauth_client || c->spd.this.xauth_server)
		numvidtosend++;

	/* set up new state */
	get_cookie(TRUE, st->st_icookie, &c->spd.that.host_addr);
	initialize_new_state(st, c, policy, try, whack_sock, importance);
	change_state(st, STATE_MAIN_I1);

	if (HAS_IPSEC_POLICY(policy)) {
		add_pending(dup_any(whack_sock), st, c, policy, 1,
			predecessor == NULL ?
			  SOS_NOBODY : predecessor->st_serialno
#ifdef HAVE_LABELED_IPSEC
			, uctx
#endif
			);
	}

#ifdef HAVE_LABELED_IPSEC
	/* For main modes states, sec ctx is always null */
	st->sec_ctx = NULL;
#endif

	if (predecessor == NULL)
		libreswan_log("initiating Main Mode");
	else
		libreswan_log("initiating Main Mode to replace #%lu",
			predecessor->st_serialno);

	/* set up reply */
	init_out_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
		"reply packet");

	/* HDR out */
	{
		struct isakmp_hdr hdr;

		zero(&hdr);	/* OK: no pointer fields */
		hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
			ISAKMP_MINOR_VERSION;
		hdr.isa_np = ISAKMP_NEXT_SA;
		hdr.isa_xchg = ISAKMP_XCHG_IDPROT;
		memcpy(hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
		/* R-cookie, flags and MessageID are left zero */

		if (DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
			hdr.isa_flags |= ISAKMP_FLAGS_RESERVED_BIT6;
		}

		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply_stream,
				&md.rbody)) {
			reset_cur_state();
			return STF_INTERNAL_ERROR;
		}
	}

	/* SA out */
	{
		u_char *sa_start = md.rbody.cur;
		enum next_payload_types_ikev1 np =
			numvidtosend > 0 ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;

		if (!ikev1_out_sa(&md.rbody, IKEv1_oakley_sadb(policy, c),
				  st, TRUE, FALSE, np)) {
			libreswan_log("outsa fail");
			reset_cur_state();
			return STF_INTERNAL_ERROR;
		}

		/* no leak! (MUST be first time) */
		passert(st->st_p1isa.ptr == NULL);

		/* save initiator SA for later HASH */
		clonetochunk(st->st_p1isa, sa_start, md.rbody.cur - sa_start,
			"sa in main_outI1");
	}

	if (c->send_vendorid) {
		int np = --numvidtosend >0 ?
			ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;

		if (!ikev1_out_generic_raw(np, &isakmp_vendor_id_desc, &md.rbody,
					pluto_vendorid, strlen(pluto_vendorid), "Pluto Vendor ID")) {
			reset_cur_state();	/* ??? was missing */
			return STF_INTERNAL_ERROR;
		}
	}

	/* Send DPD VID */
	{
		int np = --numvidtosend > 0 ?
			ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;

		if (!out_vid(np, &md.rbody, VID_MISC_DPD)) {
			reset_cur_state();
			return STF_INTERNAL_ERROR;
		}
	}

	if (c->cisco_unity) {
		int np = --numvidtosend > 0 ?
			ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;

		if (!out_vid(np, &md.rbody, VID_CISCO_UNITY)) {
			reset_cur_state();
			return STF_INTERNAL_ERROR;
		}
	}

	if (c->fake_strongswan) {
		int np = --numvidtosend > 0 ?
			ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;

		if (!out_vid(np, &md.rbody, VID_STRONGSWAN)) {
			reset_cur_state();
			return STF_INTERNAL_ERROR;
		}
	}

	/* Announce our ability to do IKE Fragmentation */
	if (c->policy & POLICY_IKE_FRAG_ALLOW) {
		int np = --numvidtosend > 0 ?
			ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;

		if (!out_vid(np, &md.rbody, VID_IKE_FRAGMENTATION)) {
			reset_cur_state();
			return STF_INTERNAL_ERROR;
		}
	}

	DBG(DBG_NATT, DBG_log("nat traversal enabled: %d",
				nat_traversal_enabled));
	if (nat_traversal_enabled) {
		int np = --numvidtosend > 0 ?
			ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;

		/* Add supported NAT-Traversal VID */
		if (!nat_traversal_insert_vid(np, &md.rbody, st)) {
			reset_cur_state();
			return STF_INTERNAL_ERROR;
		}
	}

	if (c->spd.this.xauth_client || c->spd.this.xauth_server) {
		int np = --numvidtosend > 0 ?
			ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;

		if (!out_vid(np, &md.rbody, VID_MISC_XAUTH)) {
			reset_cur_state();
			return STF_INTERNAL_ERROR;
		}
	}

	/* if we are not 0 then something went very wrong above */
	if (numvidtosend != 0)
		libreswan_log(
			"payload alignment problem please check the code in main_inR1_outR2 (num=%d)",
			numvidtosend);

	if (!close_message(&md.rbody, st))
		return STF_INTERNAL_ERROR;

	close_output_pbs(&reply_stream);

	/* Transmit */
	record_and_send_ike_msg(st, &reply_stream,
		"reply packet for main_outI1");

	delete_event(st);
	event_schedule_ms(EVENT_v1_RETRANSMIT, c->r_interval, st);

	if (predecessor != NULL) {
		update_pending(predecessor, st);
		whack_log(RC_NEW_STATE + STATE_MAIN_I1,
			"%s: initiate, replacing #%lu",
			enum_name(&state_names, st->st_state),
			predecessor->st_serialno);
	} else {
		whack_log(RC_NEW_STATE + STATE_MAIN_I1,
			"%s: initiate",
			enum_name(&state_names, st->st_state));
	}
	reset_cur_state();
	return STF_OK;
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
			bool hashi, /* Initiator? */
			const pb_stream *idpl, /* ID payload, as PBS */
			struct hmac_ctx *ctx,
			hash_update_t hash_update_void UNUSED)
{
	hash_update_void = NULL;

	if (hashi) {
		hmac_update_chunk(ctx, st->st_gi);
		hmac_update_chunk(ctx, st->st_gr);
		hmac_update(ctx, st->st_icookie, COOKIE_SIZE);
		hmac_update(ctx, st->st_rcookie, COOKIE_SIZE);
	} else {
		hmac_update_chunk(ctx, st->st_gr);
		hmac_update_chunk(ctx, st->st_gi);
		hmac_update(ctx, st->st_rcookie, COOKIE_SIZE);
		hmac_update(ctx, st->st_icookie, COOKIE_SIZE);
	}

	DBG(DBG_CRYPT,
		DBG_log("hashing %lu bytes of SA",
			(unsigned long) (st->st_p1isa.len -
					sizeof(struct isakmp_generic))));

	/* SA_b */
	hmac_update(ctx, st->st_p1isa.ptr + sizeof(struct isakmp_generic),
		st->st_p1isa.len - sizeof(struct isakmp_generic));

	/*
	 * Hash identification payload, without generic payload header.
	 * We used to reconstruct ID Payload for this purpose, but now
	 * we use the bytes as they appear on the wire to avoid
	 * "spelling problems".
	 */
	hmac_update(ctx,
		idpl->start + sizeof(struct isakmp_generic),
		pbs_offset(idpl) - sizeof(struct isakmp_generic));

#undef hash_update_chunk
#undef hash_update
}

size_t /* length of hash */
main_mode_hash(struct state *st,
	u_char *hash_val, /* resulting bytes */
	bool hashi, /* Initiator? */
	const pb_stream *idpl) /* ID payload, as PBS; cur must be at end */
{
	struct hmac_ctx ctx;

	hmac_init(&ctx, st->st_oakley.prf_hasher, st->st_skeyid_nss);
	main_mode_hash_body(st, hashi, idpl, &ctx, NULL);
	hmac_final(hash_val, &ctx);
	return ctx.hmac_digest_len;
}

/*
 * Create an RSA signature of a hash.
 * Poorly specified in draft-ietf-ipsec-ike-01.txt 6.1.1.2.
 * Use PKCS#1 version 1.5 encryption of hash (called
 * RSAES-PKCS1-V1_5) in PKCS#2.
 * Returns 0 on failure.
 */
size_t RSA_sign_hash(struct connection *c,
		u_char sig_val[RSA_MAX_OCTETS],
		const u_char *hash_val, size_t hash_len)
{
	size_t sz;
	int shr;
	const struct RSA_private_key *k = get_RSA_private_key(c);

	if (k == NULL)
		return 0; /* failure: no key to use */

	sz = k->pub.k;
	passert(RSA_MIN_OCTETS <= sz &&
		4 + hash_len < sz &&
		sz <= RSA_MAX_OCTETS);
	shr = sign_hash(k, hash_val, hash_len, sig_val, sz);
	passert(shr == 0 || (int)sz == shr);
	return shr;
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
static err_t try_RSA_signature_v1(const u_char hash_val[MAX_DIGEST_LEN],
				size_t hash_len,
				const pb_stream *sig_pbs, struct pubkey *kr,
				struct state *st)
{
	const u_char *sig_val = sig_pbs->cur;
	size_t sig_len = pbs_left(sig_pbs);
	const struct RSA_public_key *k = &kr->u.rsa;

	/* decrypt the signature -- reversing RSA_sign_hash */
	if (sig_len != k->k) {
		/* XXX notification: INVALID_KEY_INFORMATION */
		return "1" "SIG length does not match public key length";
	}

	err_t ugh = RSA_signature_verify_nss(k, hash_val, hash_len, sig_val,
					sig_len);
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
				const u_char hash_val[MAX_DIGEST_LEN],
				size_t hash_len,
				const pb_stream *sig_pbs,
#ifdef USE_KEYRR
				const struct pubkey_list *keys_from_dns,
#endif /* USE_KEYRR */
				const struct gw_info *gateways_from_dns)
{
	return RSA_check_signature_gen(st, hash_val, hash_len,
				sig_pbs,
#ifdef USE_KEYRR
				keys_from_dns,
#endif
				gateways_from_dns,
				try_RSA_signature_v1);
}

notification_t accept_v1_nonce(struct msg_digest *md, chunk_t *dest,
			const char *name)
{
	pb_stream *nonce_pbs = &md->chain[ISAKMP_NEXT_NONCE]->pbs;
	size_t len = pbs_left(nonce_pbs);

	if (len < IKEv1_MINIMUM_NONCE_SIZE || IKEv1_MAXIMUM_NONCE_SIZE < len) {
		loglog(RC_LOG_SERIOUS, "%s length not between %d and %d",
		       name, IKEv1_MINIMUM_NONCE_SIZE, IKEv1_MAXIMUM_NONCE_SIZE);
		return PAYLOAD_MALFORMED; /* ??? */
	}
	clonereplacechunk(*dest, nonce_pbs->cur, len, "nonce");
	return NOTHING_WRONG;
}

/*
 * encrypt message, sans fixed part of header
 * IV is fetched from st->st_new_iv and stored into st->st_iv.
 * The theory is that there will be no "backing out", so we commit to IV.
 * We also close the pbs.
 */
bool encrypt_message(pb_stream *pbs, struct state *st)
{
	const struct encrypt_desc *e = st->st_oakley.encrypter;
	u_int8_t *enc_start = pbs->start + sizeof(struct isakmp_hdr);
	size_t enc_len = pbs_offset(pbs) - sizeof(struct isakmp_hdr);

	DBG_cond_dump(DBG_CRYPT | DBG_RAW, "encrypting:", enc_start,
		enc_len);
	DBG_cond_dump(DBG_CRYPT | DBG_RAW, "IV:",
		st->st_new_iv,
		st->st_new_iv_len);
	DBG(DBG_CRYPT, DBG_log("unpadded size is: %u", (unsigned int)enc_len));

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

	DBG(DBG_CRYPT,
		DBG_log("encrypting %d using %s",
			(unsigned int)enc_len,
			enum_show(&oakley_enc_names, st->st_oakley.encrypt)));

	crypto_cbc_encrypt(e, TRUE, enc_start, enc_len, st);

	update_iv(st);
	DBG_cond_dump(DBG_CRYPT, "next IV:", st->st_iv, st->st_iv_len);

	if (!close_message(pbs, st))
		return FALSE;

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

stf_status main_inI1_outR1(struct msg_digest *md)
{
	/* ??? this code looks a lot like the middle of ikev2parent_inI1outR1 */
	struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_SA];
	struct state *st;
	struct connection *c;
	pb_stream r_sa_pbs;

	/* Determine how many Vendor ID payloads we will be sending */
	int numvidtosend = 1; /* we always send DPD VID */

	if (drop_new_exchanges()) {
		return STF_IGNORE;
	}

	/* random source ports are handled by find_host_connection */
	c = find_host_connection(
		&md->iface->ip_addr, pluto_port,
		&md->sender, md->sender_port,
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
			struct connection *d = find_host_connection(
				&md->iface->ip_addr, pluto_port,
				(ip_address *)NULL, md->sender_port,
				policy, POLICY_XAUTH | POLICY_AGGRESSIVE | POLICY_IKEV1_ALLOW);

			while (d != NULL) {
				if (d->kind == CK_GROUP) {
					/* ignore */
				} else {
					if (d->kind == CK_TEMPLATE &&
						!(d->policy & POLICY_OPPORTUNISTIC)) {
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
			ipstr_buf b;

			loglog(RC_LOG_SERIOUS,
				"initial Main Mode message received on %s:%u but no connection has been authorized with policy %s",
				ipstr(&md->iface->ip_addr, &b),
				ntohs(portof(&md->iface->ip_addr)),
				bitnamesof(sa_policy_bit_names, policy));
			/* XXX notification is in order! */
			return STF_IGNORE;
		} else if (c->kind != CK_TEMPLATE) {
			ipstr_buf b;
			char cib[CONN_INST_BUF];

			loglog(RC_LOG_SERIOUS,
				"initial Main Mode message received on %s:%u but \"%s\"%s forbids connection",
				ipstr(&md->iface->ip_addr, &b), pluto_port,
				c->name, fmt_conn_instance(c, cib));
			/* XXX notification is in order! */
			return STF_IGNORE;
		} else {
			/*
			 * Create a temporary connection that is a copy
			 * of this one.
			 * His ID isn't declared yet.
			 */
			DBG(DBG_CONTROL, {
				ipstr_buf b;
				char cib[CONN_INST_BUF];
				DBG_log("instantiating \"%s\"%s for initial Main Mode message received on %s:%u",
					c->name, fmt_conn_instance(c, cib),
					ipstr(&md->iface->ip_addr, &b),
					pluto_port);
			});
			c = rw_instantiate(c, &md->sender,
					NULL, NULL);
		}
	} else {
		/*
		 * we found a non-wildcard conn. double check if it needs
		 * instantiation anyway (eg vnet=)
		 */
		if (c->kind == CK_TEMPLATE && c->spd.that.virt) {
			DBG(DBG_CONTROL,
				DBG_log("local endpoint has virt (vnet/vhost) set without wildcards - needs instantiation"));
			c = rw_instantiate(c, &md->sender, NULL, NULL);
		}
		if (c->kind == CK_TEMPLATE && c->spd.that.has_id_wildcards) {
			DBG(DBG_CONTROL,
				DBG_log("remote end has wildcard ID, needs instantiation"));
			c = rw_instantiate(c, &md->sender, NULL, NULL);
		}
	}

	/* Set up state */
	md->st = st = new_rstate(md);

	passert(!st->st_oakley.doing_xauth);

	st->st_connection = c;	/* safe: from new_state */

	set_cur_state(st); /* (caller will reset cur_state) */
	st->st_try = 0; /* not our job to try again from start */
	/* only as accurate as connection */
	st->st_policy = c->policy & ~POLICY_IPSEC_MASK;
	change_state(st, STATE_MAIN_R0);

	memcpy(st->st_icookie, md->hdr.isa_icookie, COOKIE_SIZE);
	get_cookie(FALSE, st->st_rcookie, &md->sender);

	insert_state(st); /* needs cookies, connection, and msgid (0) */

	merge_quirks(st, md);

	set_nat_traversal(st, md);

	if ((c->kind == CK_INSTANCE) && (c->spd.that.host_port_specific)) {
		ipstr_buf b;

		libreswan_log(
			"responding to Main Mode from unknown peer %s:%u",
			ipstr(&c->spd.that.host_addr, &b),
			c->spd.that.host_port);
	} else if (c->kind == CK_INSTANCE) {
		ipstr_buf b;

		libreswan_log("responding to Main Mode from unknown peer %s",
			ipstr(&c->spd.that.host_addr, &b));
	} else {
		libreswan_log("responding to Main Mode");
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
	{
		struct isakmp_hdr hdr = md->hdr;

		hdr.isa_flags = 0; /* clear all flags */
		memcpy(hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
		hdr.isa_np = ISAKMP_NEXT_SA;

		if (DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
			hdr.isa_flags |= ISAKMP_FLAGS_RESERVED_BIT6;
		}

		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply_stream,
					&md->rbody))
			return STF_INTERNAL_ERROR;
	}

	/* Increase VID counter for NAT-T VID */
	if (st->hidden_variables.st_nat_traversal != LEMPTY) {
		DBG(DBG_NATT, DBG_log("NAT-T VID detected, sending NAT-T VID"));
		numvidtosend++;
	}

	/* Increase VID counter for VID_CISCO_UNITY */
	if (c->send_vendorid) {
		numvidtosend++;
	}

	/* Increase VID counter for VID_IKE_FRAGMENTATION */
	if (c->policy & POLICY_IKE_FRAG_ALLOW)
		numvidtosend++;

	/* Increase VID counter for VID_MISC_XAUTH */
	if (c->spd.this.xauth_server || c->spd.this.xauth_client)
		numvidtosend++;

	/* start of SA out */
	{
		struct isakmp_sa r_sa;

		zero(&r_sa);	/* OK: no pointer fields */
		r_sa.isasa_doi = ISAKMP_DOI_IPSEC;

		/*
		 * Almost guaranteed to send a VID, set the NEXT payload
		 * correctly
		 */
		r_sa.isasa_np =
			numvidtosend ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;
		if (!out_struct(&r_sa, &isakmp_sa_desc, &md->rbody, &r_sa_pbs))
			return STF_INTERNAL_ERROR;
	}

	/* SA body in and out */
	RETURN_STF_FAILURE(parse_isakmp_sa_body(&sa_pd->pbs,
						&sa_pd->payload.sa,
						&r_sa_pbs, FALSE, st));

	/*
	 * NOW SEND VENDOR ID payloads
	 */

	if (c->send_vendorid) {
		int np = --numvidtosend ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;

		if (!ikev1_out_generic_raw(np, &isakmp_vendor_id_desc, &md->rbody,
					pluto_vendorid, strlen(pluto_vendorid), "Vendor ID"))
			return STF_INTERNAL_ERROR;
	}

	{
		/*
		 * always announce our ability to do RFC 3706
		 * Dead Peer Detection
		 */
		int np = --numvidtosend ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;

		if (!out_vid(np, &md->rbody, VID_MISC_DPD))
			return STF_INTERNAL_ERROR;
	}

	/* Announce our ability to do (non-RFC) IKE Fragmentation */
	if (c->policy & POLICY_IKE_FRAG_ALLOW) {
		int np = --numvidtosend > 0 ?
			ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;

		if (!out_vid(np, &md->rbody, VID_IKE_FRAGMENTATION))
			return STF_INTERNAL_ERROR;
	}

	/*
	 * If XAUTH is required, insert draft-ietf-ipsec-isakmp-xauth-06
	 * Vendor ID
	 */
	if (c->spd.this.xauth_server || c->spd.this.xauth_client) {
		int np = --numvidtosend ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;

		if (!out_vid(np, &md->rbody, VID_MISC_XAUTH))
			return STF_INTERNAL_ERROR;
	}

	if (st->hidden_variables.st_nat_traversal != LEMPTY) {
		int np = --numvidtosend ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;

		if (!out_vid(np, &md->rbody, md->quirks.qnat_traversal_vid))
			return STF_INTERNAL_ERROR;
	}

	/* Ensure our 'next payload' types sync'ed up */
	passert(numvidtosend == 0);

	if (!close_message(&md->rbody, st))
		return STF_INTERNAL_ERROR;

	/* save initiator SA for HASH */
	clonereplacechunk(st->st_p1isa, sa_pd->pbs.start, pbs_room(
				&sa_pd->pbs), "sa in main_inI1_outR1()");

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

static stf_status main_inR1_outI2_tail(struct pluto_crypto_req_cont *ke,
				struct pluto_crypto_req *r);

static crypto_req_cont_func main_inR1_outI2_continue;	/* type assertion */

static void main_inR1_outI2_continue(struct pluto_crypto_req_cont *ke,
				struct pluto_crypto_req *r)
{
	struct msg_digest *md = ke->pcrc_md;
	struct state *const st = md->st;
	stf_status e;

	DBG(DBG_CONTROL,
		DBG_log("main_inR1_outI2_continue for #%lu: calculated ke+nonce, sending I2",
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

	e = main_inR1_outI2_tail(ke, r);

	passert(ke->pcrc_md != NULL);
	complete_v1_state_transition(&ke->pcrc_md, e);
	release_any_md(&ke->pcrc_md);

	reset_cur_state();
}

stf_status main_inR1_outI2(struct msg_digest *md)
{
	struct state *const st = md->st;

	/* verify echoed SA */
	{
		struct payload_digest *const sapd = md->chain[ISAKMP_NEXT_SA];

		RETURN_STF_FAILURE(parse_isakmp_sa_body(&sapd->pbs,
							&sapd->payload.sa,
							NULL, TRUE, st));
	}

#ifdef FIPS_CHECK
	if (libreswan_fipsmode() && st->st_oakley.prf_hasher == NULL) {
		loglog(RC_LOG_SERIOUS, "Missing prf - algo not allowed in fips mode (inR1_outI2)?");
		return STF_FAIL + SITUATION_NOT_SUPPORTED;
	}
#endif

	merge_quirks(st, md);

	set_nat_traversal(st, md);

	{
		struct pluto_crypto_req_cont *ke = new_pcrc(
			main_inR1_outI2_continue, "outI2 KE",
			st, md);

		passert(!st->st_sec_in_use);
		return build_ke_and_nonce(ke, st->st_oakley.group,
				st->st_import);
	}
}

/*
 * package up the calculate KE value, and emit it as a KE payload.
 * used by IKEv1: main, aggressive, and quick (in PFS mode).
 */
bool ikev1_justship_KE(chunk_t *g,
		pb_stream *outs, u_int8_t np)
{
	if (DBGP(IMPAIR_SEND_ZERO_GX)) {
		pb_stream z;

		libreswan_log("sending bogus g^x == 0 value to break DH calculations because impair-send-zero-gx was set");
		/* Only used to test sending/receiving bogus g^x */
		return ikev1_out_generic(np, &isakmp_keyex_desc, outs, &z) &&
			out_zero(g->len, &z, "fake g^x") &&
			(close_output_pbs(&z), TRUE);
	} else {
		return ikev1_out_generic_chunk(np, &isakmp_keyex_desc, outs, *g,
				"keyex value");
	}
}

bool ikev1_ship_KE(struct state *st,
	struct pluto_crypto_req *r,
	chunk_t *g,
	pb_stream *outs, u_int8_t np)
{
	unpack_KE_from_helper(st, r, g);
	return ikev1_justship_KE(g, outs, np);
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
static stf_status main_inR1_outI2_tail(struct pluto_crypto_req_cont *ke,
				struct pluto_crypto_req *r)
{
	struct msg_digest *md = ke->pcrc_md;
	struct state *const st = md->st;

	/* Build output packet HDR;KE;Ni */
	zero(&reply_buffer);	/* redundant */
	init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
		"reply packet");

	/*
	 * HDR out.
	 * We can't leave this to comm_handle() because the isa_np
	 * depends on the type of Auth (eventually).
	 */
	ikev1_echo_hdr(md, FALSE, ISAKMP_NEXT_KE);

	/* KE out */
	if (!ikev1_ship_KE(st, r, &st->st_gi,
			&md->rbody, ISAKMP_NEXT_NONCE))
		return STF_INTERNAL_ERROR;

	/* Ni out */
	if (!ikev1_ship_nonce(&st->st_ni, r, &md->rbody,
				(cur_debugging &
					IMPAIR_BUST_MI2) ? ISAKMP_NEXT_VID :
				ISAKMP_NEXT_NONE,
				"Ni"))
		return STF_INTERNAL_ERROR;

	if (cur_debugging & IMPAIR_BUST_MI2) {
		/*
		 * generate a pointless large VID payload to push message
		 * over MTU
		 */
		pb_stream vid_pbs;

		/*
		 * This next payload value will get rewritten to one of the two
		 * NAT payload types when needed, using out_modify_previous_np()
		 * in the below call to ikev1_nat_traversal_add_natd()
		 */
		if (!ikev1_out_generic(ISAKMP_NEXT_NONE, &isakmp_vendor_id_desc,
					&md->rbody,
					&vid_pbs))
			return STF_INTERNAL_ERROR;

		if (!out_zero(1500 /*MTU?*/, &vid_pbs, "Filler VID"))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&vid_pbs);
	}

	DBG(DBG_NATT, DBG_log("NAT-T checking st_nat_traversal"));
	if (st->hidden_variables.st_nat_traversal != LEMPTY) {
		DBG(DBG_NATT,
			DBG_log("NAT-T found (implies NAT_T_WITH_NATD)"));
		if (!ikev1_nat_traversal_add_natd(ISAKMP_NEXT_NONE, &md->rbody, md))
			return STF_INTERNAL_ERROR;
	}

	/* finish message */
	if (!close_message(&md->rbody, st))
		return STF_INTERNAL_ERROR;

	/* Reinsert the state, using the responder cookie we just received */
	rehash_state(st, md->hdr.isa_rcookie);

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
static stf_status main_inI2_outR2_tail(struct pluto_crypto_req_cont *ke,
				struct pluto_crypto_req *r);

static crypto_req_cont_func main_inI2_outR2_continue;	/* type assertion */

static void main_inI2_outR2_continue(struct pluto_crypto_req_cont *ke,
				struct pluto_crypto_req *r)
{
	struct msg_digest *md = ke->pcrc_md;
	struct state *const st = md->st;
	stf_status e;

	DBG(DBG_CONTROL,
		DBG_log("main_inI2_outR2_continue for #%lu: calculated ke+nonce, sending R2",
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
	e = main_inI2_outR2_tail(ke, r);

	passert(ke->pcrc_md != NULL);
	complete_v1_state_transition(&ke->pcrc_md, e);
	release_any_md(&ke->pcrc_md);
	reset_cur_state();
}

stf_status main_inI2_outR2(struct msg_digest *md)
{
	struct state *const st = md->st;

	/* KE in */
	RETURN_STF_FAILURE(accept_KE(&st->st_gi, "Gi", st->st_oakley.group,
				     &md->chain[ISAKMP_NEXT_KE]->pbs));

	/* Ni in */
	RETURN_STF_FAILURE(accept_v1_nonce(md, &st->st_ni, "Ni"));

	/* decode certificate requests */
	ikev1_decode_cr(md);

	if (st->st_requested_ca != NULL)
		st->hidden_variables.st_got_certrequest = TRUE;

	ikev1_natd_init(st, md);

	{
		struct pluto_crypto_req_cont *ke = new_pcrc(
			main_inI2_outR2_continue, "inI2_outR2 KE",
			st, md);

		passert(!st->st_sec_in_use);
		return build_ke_and_nonce(ke,
			st->st_oakley.group, st->st_import);
	}
}

/*
 * main_inI2_outR2_calcdone is unlike every other crypto_req_cont_func:
 * the state that it is working for may not yet care about the result.
 * We are precomputing the DH.
 * This also means that it isn't good at reporting an NSS error.
 */
static crypto_req_cont_func main_inI2_outR2_calcdone;	/* type assertion */

static void main_inI2_outR2_calcdone(struct pluto_crypto_req_cont *dh,
				struct pluto_crypto_req *r)
{
	struct state *st;

	DBG(DBG_CONTROL,
		DBG_log("main_inI2_outR2_calcdone for #%lu: calculate DH finished",
			dh->pcrc_serialno));

	if (dh->pcrc_serialno == SOS_NOBODY) {
		libreswan_log("state #%lu disappeared during crypto",
			dh->pcrc_serialno);
		/* note: no md exists in this odd case */
		return;
	}
	st = state_with_serialno(dh->pcrc_serialno);

	set_cur_state(st);

	if (finish_dh_secretiv(st, r))
		update_iv(st);

	/*
	 * If there was a packet received while we were calculating, then
	 * process it now.
	 * Otherwise, the result awaits the packet.
	 */
	if (st->st_suspended_md != NULL) {
		struct msg_digest *md = st->st_suspended_md;

		unset_suspended(st);
		process_packet_tail(&md);
		release_any_md(&md);
	}
	reset_cur_state();
}

stf_status main_inI2_outR2_tail(struct pluto_crypto_req_cont *ke,
				struct pluto_crypto_req *r)
{
	struct msg_digest *md = ke->pcrc_md;
	struct state *st = md->st;

#ifdef FIPS_CHECK
	if (libreswan_fipsmode() && st->st_oakley.prf_hasher == NULL) {
		loglog(RC_LOG_SERIOUS,
		       "Missing prf - algo not allowed in fips mode (inI2_outR2)?");
		return STF_FAIL + SITUATION_NOT_SUPPORTED;
	}
#endif

	/* send CR if auth is RSA and no preloaded RSA public key exists*/
	bool send_cr = FALSE;

	/* Build output packet HDR;KE;Nr */

	send_cr = (st->st_oakley.auth == OAKLEY_RSA_SIG) &&
		!has_preloaded_public_key(st) &&
		st->st_connection->spd.that.ca.ptr != NULL;

	/* HDR out */
	ikev1_echo_hdr(md, FALSE, ISAKMP_NEXT_KE);

	/* KE out */
	if (!ikev1_ship_KE(st, r, &st->st_gr,
			&md->rbody, ISAKMP_NEXT_NONCE)) {
		lsw_abort();
		return STF_INTERNAL_ERROR;
	}

	{
		/* Nr out */
		int next_payload;
		next_payload = ISAKMP_NEXT_NONE;

		if (cur_debugging & IMPAIR_BUST_MR2)
			next_payload = ISAKMP_NEXT_VID;
		if (send_cr)
			next_payload = ISAKMP_NEXT_CR;
		if (!ikev1_ship_nonce(&st->st_nr, r,
					&md->rbody,
					next_payload,
					"Nr"))
			return STF_INTERNAL_ERROR;

		if (cur_debugging & IMPAIR_BUST_MR2) {
			/*
			 * generate a pointless large VID payload to push
			 * message over MTU
			 */
			pb_stream vid_pbs;

			if (!ikev1_out_generic((send_cr) ? ISAKMP_NEXT_CR :
					ISAKMP_NEXT_NONE,
					&isakmp_vendor_id_desc, &md->rbody,
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
						&md->rbody, ISAKMP_NEXT_NONE))
				return STF_INTERNAL_ERROR;
		} else {
			generalName_t *ca = collect_rw_ca_candidates(md);

			if (ca != NULL) {
				generalName_t *gn;

				for (gn = ca; gn != NULL; gn = gn->next) {
					if (!ikev1_build_and_ship_CR(
							CERT_X509_SIGNATURE,
							gn->name,
							&md->rbody,
							gn->next ==NULL ?
							  ISAKMP_NEXT_NONE :
							  ISAKMP_NEXT_CR))
						return STF_INTERNAL_ERROR;
				}
				free_generalNames(ca, FALSE);
			} else {
				if (!ikev1_build_and_ship_CR(CERT_X509_SIGNATURE,
							empty_chunk,
							&md->rbody,
							ISAKMP_NEXT_NONE))
					return STF_INTERNAL_ERROR;
			}
		}
	}

	if (st->hidden_variables.st_nat_traversal != LEMPTY) {
		if (!ikev1_nat_traversal_add_natd(ISAKMP_NEXT_NONE, &md->rbody, md))
			return STF_INTERNAL_ERROR;
	}

	/* finish message */
	if (!close_message(&md->rbody, st))
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
		struct pluto_crypto_req_cont *dh = new_pcrc(
			main_inI2_outR2_calcdone, "main_inI2_outR2_tail",
			st, NULL);
		stf_status e;

		passert(st->st_suspended_md == NULL);

		DBG(DBG_CONTROLMORE,
			DBG_log("main inI2_outR2: starting async DH calculation (group=%d)",
				st->st_oakley.group->group));

		e = start_dh_secretiv(dh, st,
				st->st_import,
				ORIGINAL_RESPONDER,
				st->st_oakley.group->group);

		DBG(DBG_CONTROLMORE,
			DBG_log("started dh_secretiv, returned: stf=%s",
				enum_name(&stfstatus_name, e)));

		if (e == STF_FAIL) {
			loglog(RC_LOG_SERIOUS,
				"failed to start async DH calculation, stf=%s",
				enum_name(&stfstatus_name, e));
			return e;
		}

		/* we are calculating in the background, so it doesn't count */
		DBG(DBG_CONTROLMORE, DBG_log("#%lu %s:%u st->st_calculating = FALSE;", st->st_serialno, __FUNCTION__, __LINE__));
		if (e == STF_SUSPEND)
			st->st_calculating = FALSE;
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
static stf_status main_inR2_outI3_continue(struct msg_digest *md,
					struct pluto_crypto_req *r)
{
	struct state *const st = md->st;
	int auth_payload = st->st_oakley.auth == OAKLEY_PRESHARED_KEY ?
		ISAKMP_NEXT_HASH : ISAKMP_NEXT_SIG;
	pb_stream id_pbs; /* ID Payload; also used for hash calculation */
	bool send_cert = FALSE;
	bool send_cr = FALSE;
	bool send_authcerts = FALSE;
	bool send_full_chain = FALSE;
	bool initial_contact = FALSE;
	cert_t mycert = st->st_connection->spd.this.cert;
	chunk_t auth_chain[MAX_CA_PATH_LEN] = { { NULL, 0 } };
	int chain_len = 0;

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
		((st->st_connection->spd.this.sendcert == cert_sendifasked &&
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
			send_cert,
			send_authcerts);

	/*
	 * send certificate request, if we don't have a preloaded RSA
	 * public key
	 */
	send_cr = send_cert && !has_preloaded_public_key(st);

	DBG(DBG_CONTROL,
		DBG_log(" I am %ssending a certificate request",
			send_cr ? "" : "not "));

	/*
	 * free collected certificate requests
	 * note: when we are able to ship based on the request
	 * contents, we'll need them then.
	 */
	free_generalNames(st->st_requested_ca, TRUE);

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
	initial_contact = st->st_connection->initial_contact;
	DBG(DBG_CONTROLMORE,
		DBG_log("I will %ssend an initial contact payload",
			initial_contact ? "" : "NOT "));

	/* done parsing; initialize crypto */

	ikev1_natd_init(st, md);

	/*
	 * Build output packet HDR*;IDii;HASH/SIG_I
	 *
	 * ??? NOTE: this is almost the same as main_inI3_outR3's code
	 */

	/* HDR* out done */

	/* IDii out */
	{
		struct isakmp_ipsec_id id_hd;
		chunk_t id_b;

		build_id_payload(&id_hd, &id_b, &st->st_connection->spd.this);
		id_hd.isaiid_np =
			(send_cert) ? ISAKMP_NEXT_CERT : auth_payload;
		if (!out_struct(&id_hd,
				&isakmp_ipsec_identification_desc,
				&md->rbody,
				&id_pbs) ||
		    !out_chunk(id_b, &id_pbs, "my identity"))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&id_pbs);
	}

	/* CERT out */
	if (send_cert) {
		u_int8_t np;

		if (!send_cr && !send_authcerts)
			np = ISAKMP_NEXT_SIG;
		else
			np = send_authcerts ? ISAKMP_NEXT_CERT : ISAKMP_NEXT_CR;

		libreswan_log("I am sending my cert");

		if (!ikev1_ship_CERT(mycert.ty,
				   get_dercert_from_nss_cert(mycert.u.nss_cert),
				   &md->rbody, np))
			return STF_INTERNAL_ERROR;

		if (np == ISAKMP_NEXT_CERT) {
			/* we've got CA certificates to send */
			libreswan_log("I am sending a CA cert chain");
			if (!ikev1_ship_chain(auth_chain,
					      chain_len,
					      &md->rbody,
					      mycert.ty,
					      send_cr ? ISAKMP_NEXT_CR :
							ISAKMP_NEXT_SIG))
				return STF_INTERNAL_ERROR;
		}
	}

	/* CR out */
	if (send_cr) {
		libreswan_log("I am sending a certificate request");
		if (!ikev1_build_and_ship_CR(mycert.ty,
					st->st_connection->spd.that.ca,
					&md->rbody, ISAKMP_NEXT_SIG))
			return STF_INTERNAL_ERROR;
	}

	/* HASH_I or SIG_I out */
	{
		u_char hash_val[MAX_DIGEST_LEN];
		size_t hash_len = main_mode_hash(st, hash_val, TRUE, &id_pbs);

		if (auth_payload == ISAKMP_NEXT_HASH) {
			/* HASH_I out */
			if (!ikev1_out_generic_raw(initial_contact ? ISAKMP_NEXT_N :
						ISAKMP_NEXT_NONE,
						&isakmp_hash_desc,
						&md->rbody,
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

			if (!ikev1_out_generic_raw(initial_contact ? ISAKMP_NEXT_N :
						ISAKMP_NEXT_NONE,
						&isakmp_signature_desc,
						&md->rbody,
						sig_val,
						sig_len,
						"SIG_I"))
				return STF_INTERNAL_ERROR;
		}
	}

	/* INITIAL_CONTACT */
	if (initial_contact) {
		pb_stream notify_pbs;
		struct isakmp_notification isan;

		libreswan_log("sending INITIAL_CONTACT");

		isan.isan_np = ISAKMP_NEXT_NONE;
		isan.isan_doi = ISAKMP_DOI_IPSEC;
		isan.isan_protoid = PROTO_ISAKMP;
		isan.isan_spisize = COOKIE_SIZE * 2;
		isan.isan_type = IPSEC_INITIAL_CONTACT;
		if (!out_struct(&isan, &isakmp_notification_desc, &md->rbody,
					&notify_pbs))
			return STF_INTERNAL_ERROR;

		if (!out_raw(st->st_icookie, COOKIE_SIZE, &notify_pbs,
				"notify icookie"))
			return STF_INTERNAL_ERROR;

		if (!out_raw(st->st_rcookie, COOKIE_SIZE, &notify_pbs,
				"notify rcookie"))
			return STF_INTERNAL_ERROR;

		/* zero length data payload */
		close_output_pbs(&notify_pbs);
	} else {
		DBG(DBG_CONTROL, DBG_log("Not sending INITIAL_CONTACT"));
	}

	/* encrypt message, except for fixed part of header */

	/* st_new_iv was computed by generate_skeyids_iv (??? DOESN'T EXIST) */
	if (!encrypt_message(&md->rbody, st))
		return STF_INTERNAL_ERROR; /* ??? we may be partly committed */

	return STF_OK;
}

static crypto_req_cont_func main_inR2_outI3_cryptotail;	/* type assertion */

static void main_inR2_outI3_cryptotail(struct pluto_crypto_req_cont *dh,
				struct pluto_crypto_req *r)
{
	struct msg_digest *md = dh->pcrc_md;
	struct state *const st = md->st;
	stf_status e;

	DBG(DBG_CONTROL,
		DBG_log("main_inR2_outI3_cryptotail for #%lu: calculated DH, sending R1",
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

	e = main_inR2_outI3_continue(md, r);

	passert(dh->pcrc_md != NULL);	/* ??? how would this fail? */
	if (dh->pcrc_md != NULL) {
		complete_v1_state_transition(&dh->pcrc_md, e);
		release_any_md(&dh->pcrc_md);
	}
	reset_cur_state();
}

stf_status main_inR2_outI3(struct msg_digest *md)
{
	struct pluto_crypto_req_cont *dh;
	struct state *const st = md->st;

	/* KE in */
	RETURN_STF_FAILURE(accept_KE(&st->st_gr, "Gr",
				     st->st_oakley.group,
				     &md->chain[ISAKMP_NEXT_KE]->pbs));

	/* Nr in */
	RETURN_STF_FAILURE(accept_v1_nonce(md, &st->st_nr, "Nr"));

	dh = new_pcrc(main_inR2_outI3_cryptotail, "aggr outR1 DH",
		st, md);
	return start_dh_secretiv(dh, st,
				st->st_import,
				ORIGINAL_INITIATOR,
				st->st_oakley.group->group);
}

/*
 * Shared logic for asynchronous lookup of DNS KEY records.
 * Used for STATE_MAIN_R2 and STATE_MAIN_I3.
 */

static void report_key_dns_failure(struct id *id, err_t ugh)
{
	char id_buf[IDTOA_BUF]; /* arbitrary limit on length of ID reported */

	(void) idtoa(id, id_buf, sizeof(id_buf));
	loglog(RC_LOG_SERIOUS,
		"no RSA public key known for '%s'; DNS search for KEY failed (%s)",
		id_buf, ugh);
}

/*
 * Processs the Main Mode ID Payload and the Authenticator
 * (Hash or Signature Payload).
 *
 * If a DNS query is still needed to get the other host's public key,
 * the query is initiated and STF_SUSPEND is returned.
 * Note: parameter kc is a continuation containing the results from
 * the previous DNS query, or NULL indicating no query has been issued.
 */
stf_status oakley_id_and_auth(struct msg_digest *md,
			bool initiator, /* are we the Initiator? */
			bool aggrmode, /* aggressive mode? */
			cont_fn_t cont_fn UNUSED, /* ADNS continuation function */
			/* current state, can be NULL */
			const struct key_continuation *kc)
{
	struct state *st = md->st;
	u_char hash_val[MAX_DIGEST_LEN];
	size_t hash_len;
	stf_status r = STF_OK;

	/*
	 * ID Payload in.
	 * Note: this may switch the connection being used!
	 */
	if (!aggrmode && !ikev1_decode_peer_id(md, initiator, FALSE))
		return STF_FAIL + INVALID_ID_INFORMATION;

	/*
	 * Hash the ID Payload.
	 * main_mode_hash requires idpl->cur to be at end of payload
	 * so we temporarily set if so.
	 */
	{
		pb_stream *idpl = &md->chain[ISAKMP_NEXT_ID]->pbs;
		u_int8_t *old_cur = idpl->cur;

		idpl->cur = idpl->roof;
		hash_len = main_mode_hash(st, hash_val, !initiator, idpl);
		idpl->cur = old_cur;
	}

	switch (st->st_oakley.auth) {
	case OAKLEY_PRESHARED_KEY:
	{
		pb_stream *const hash_pbs = &md->chain[ISAKMP_NEXT_HASH]->pbs;

		if (pbs_left(hash_pbs) != hash_len ||
			!memeq(hash_pbs->cur, hash_val, hash_len)) {
			DBG_cond_dump(DBG_CRYPT, "received HASH:",
				hash_pbs->cur, pbs_left(hash_pbs));
			loglog(RC_LOG_SERIOUS,
				"received Hash Payload does not match computed value");
			/* XXX Could send notification back */
			r = STF_FAIL + INVALID_HASH_INFORMATION;
		}
	}
	break;

	case OAKLEY_RSA_SIG:
		r = RSA_check_signature(st, hash_val, hash_len,
					&md->chain[ISAKMP_NEXT_SIG]->pbs,
#ifdef USE_KEYRR
					kc == NULL ? NULL :
					kc->ac.keys_from_dns,
#endif /* USE_KEYRR */
					kc == NULL ? NULL :
					kc->ac.gateways_from_dns);

		if (r == STF_SUSPEND) {
			/* initiate/resume asynchronous DNS lookup for key */
			struct key_continuation *nkc =
				alloc_thing(struct key_continuation,
					"key continuation");
			enum key_oppo_step step_done =
				kc == NULL ? kos_null : kc->step;
			err_t ugh = NULL;

			/* Record that state is used by a suspended md */
			passert(st->st_suspended_md == NULL);
			set_suspended(st, md);

			nkc->failure_ok = FALSE;
			nkc->md = md;

			switch (step_done) {
			case kos_null:
				/* first try: look for the TXT records */
				nkc->step = kos_his_txt;
#ifdef USE_KEYRR
				nkc->failure_ok = TRUE;
#endif
				break;

#ifdef USE_KEYRR
			case kos_his_txt:
				/* second try: look for the KEY records */
				nkc->step = kos_his_key;
				break;
#endif /* USE_KEYRR */

			default:
				bad_case(step_done);
			}

			if (ugh != NULL) {
				report_key_dns_failure(
					&st->st_connection->spd.that.id, ugh);
				unset_suspended(st);
				r = STF_FAIL + INVALID_KEY_INFORMATION;
			} else {
				/*
				 * since this state is waiting for a DNS query,
				 * delete any events that might kill it.
				 */
				delete_event(st);
			}
		}
		break;

	default:
		bad_case(st->st_oakley.auth);
	}
	if (r == STF_OK)
		DBG(DBG_CRYPT, DBG_log("authentication succeeded"));
	return r;
}

/*
 * This continuation is called as part of either
 * the main_inI3_outR3 state or main_inR3 state.
 *
 * The "tail" function is the corresponding tail
 * function main_inI3_outR3_tail | main_inR3_tail,
 * either directly when the state is started, or via
 * adns continuation.
 *
 * Basically, we go around in a circle:
 *   main_in?3* -> key_continue
 *                ^            \
 *               /              V
 *             adns            main_in?3*_tail
 *              ^               |
 *               \              V
 *                main_id_and_auth
 *
 * until such time as main_id_and_auth is able
 * to find authentication, or we run out of things
 * to try.
 */
void key_continue(struct adns_continuation *cr,
		err_t ugh,
		key_tail_fn *tail)
{
	struct key_continuation *kc = (void *)cr;
	struct msg_digest *md = kc->md;
	struct state *st;

	if (md == NULL)
		return;

	st = md->st;

	passert(cur_state == NULL);

	/* if st == NULL, our state has been deleted -- just clean up */
	if (st != NULL && st->st_suspended_md != NULL) {
		stf_status r;

		passert(st->st_suspended_md == kc->md);
		unset_suspended(st); /* no longer connected or suspended */
		cur_state = st;

		/* cancel any DNS event, since we got an anwer */
		delete_event(st);

		if (!kc->failure_ok && ugh != NULL) {
			report_key_dns_failure(&st->st_connection->spd.that.id,
					ugh);
			r = STF_FAIL + INVALID_KEY_INFORMATION;
		} else {

#ifdef USE_KEYRR
			passert(kc->step == kos_his_txt ||
				kc->step == kos_his_key);
#else
			passert(kc->step == kos_his_txt);
#endif
			/* record previous error in case we need it */
			kc->last_ugh = ugh;
			r = (*tail)(kc->md, kc);
		}
		complete_v1_state_transition(&kc->md, r);
	}
	release_any_md(&kc->md);
	cur_state = NULL;
}

/*
 * STATE_MAIN_R2:
 * PSK_AUTH: HDR*, IDi1, HASH_I --> HDR*, IDr1, HASH_R
 * DS_AUTH: HDR*, IDi1, [ CERT, ] SIG_I --> HDR*, IDr1, [ CERT, ] SIG_R
 * PKE_AUTH, RPKE_AUTH: HDR*, HASH_I --> HDR*, HASH_R
 *
 * Broken into parts to allow asynchronous DNS lookup.
 *
 * - main_inI3_outR3 to start
 * - main_inI3_outR3_tail to finish or suspend for DNS lookup
 * - main_inI3_outR3_continue to start main_inI3_outR3_tail again
 */
static key_tail_fn main_inI3_outR3_tail; /* forward */

stf_status main_inI3_outR3(struct msg_digest *md)
{
	/* handle case where NSS balked at generating DH */
	return md->st->st_shared_nss == NULL ?
		STF_FAIL + INVALID_KEY_INFORMATION :
		main_inI3_outR3_tail(md, NULL);
}

static inline stf_status main_id_and_auth(struct msg_digest *md,
					/* are we the Initiator? */
					bool initiator,
					/* continuation function */
					cont_fn_t cont_fn,
					/* argument */
					struct key_continuation *kc)
{
	return oakley_id_and_auth(md, initiator, FALSE, cont_fn, kc);
}

static void main_inI3_outR3_continue(struct adns_continuation *cr, err_t ugh)
{
	key_continue(cr, ugh, main_inI3_outR3_tail);
}

static stf_status main_inI3_outR3_tail(struct msg_digest *md,
				struct key_continuation *kc)
{
	struct state *const st = md->st;
	u_int8_t auth_payload;
	pb_stream r_id_pbs; /* ID Payload; also used for hash calculation */
	cert_t mycert;
	bool send_cert = FALSE;
	bool send_authcerts = FALSE;
	bool send_full_chain = FALSE;
	chunk_t auth_chain[MAX_CA_PATH_LEN] = { { NULL, 0 } };
	int chain_len = 0;
	u_int8_t np;

	/*
	 * ID and HASH_I or SIG_I in
	 * Note: this may switch the connection being used!
	 */
	{
		stf_status r = main_id_and_auth(md, FALSE,
						main_inI3_outR3_continue,
						kc);

		if (r != STF_OK)
			return r;
	}

	/* send certificate if we have one and auth is RSA */
	mycert = st->st_connection->spd.this.cert;

	send_cert = st->st_oakley.auth == OAKLEY_RSA_SIG &&
		mycert.ty != CERT_NONE && mycert.u.nss_cert != NULL &&
		((st->st_connection->spd.this.sendcert == cert_sendifasked &&
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
	 **/

	/*
	 * HDR* out
	 * If auth were PKE_AUTH or RPKE_AUTH, ISAKMP_NEXT_HASH would
	 * be first payload.
	 */
	ikev1_echo_hdr(md, TRUE, ISAKMP_NEXT_ID);

	auth_payload = st->st_oakley.auth == OAKLEY_PRESHARED_KEY ?
		ISAKMP_NEXT_HASH : ISAKMP_NEXT_SIG;

	/* IDir out */
	{
		/*
		 * id_hd should be struct isakmp_id, but struct isakmp_ipsec_id
		 * allows build_id_payload() to work for both phases.
		 */
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

	/* CERT out, if we have one */
	if (send_cert) {
		u_int8_t npp = send_authcerts ? ISAKMP_NEXT_CERT :
						ISAKMP_NEXT_SIG;

		libreswan_log("I am sending my cert");
		if (!ikev1_ship_CERT(mycert.ty,
				   get_dercert_from_nss_cert(mycert.u.nss_cert),
				   &md->rbody, npp))
			return STF_INTERNAL_ERROR;

		if (npp == ISAKMP_NEXT_CERT) {
			libreswan_log("I am sending a CA cert chain");
			if (!ikev1_ship_chain(auth_chain, chain_len,
							  &md->rbody,
							  mycert.ty,
							  ISAKMP_NEXT_SIG))
				return STF_INTERNAL_ERROR;
		}
	}

	/* IKEv2 NOTIFY payload */
	np = ISAKMP_NEXT_NONE;
	if (st->st_connection->policy & POLICY_IKEV2_ALLOW)
		np = ISAKMP_NEXT_VID;

	/* HASH_R or SIG_R out */
	{
		u_char hash_val[MAX_DIGEST_LEN];
		size_t hash_len =
			main_mode_hash(st, hash_val, FALSE, &r_id_pbs);

		if (auth_payload == ISAKMP_NEXT_HASH) {
			/* HASH_R out */
			if (!ikev1_out_generic_raw(np, &isakmp_hash_desc, &md->rbody,
						hash_val, hash_len, "HASH_R"))
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

			if (!ikev1_out_generic_raw(np, &isakmp_signature_desc,
						&md->rbody, sig_val, sig_len,
						"SIG_R"))
				return STF_INTERNAL_ERROR;
		}
	}

	if (st->st_connection->policy & POLICY_IKEV2_ALLOW) {
		if (!out_vid(ISAKMP_NEXT_NONE, &md->rbody, VID_MISC_IKEv2))
			return STF_INTERNAL_ERROR;
	}

	/* encrypt message, sans fixed part of header */

	if (!encrypt_message(&md->rbody, st))
		return STF_INTERNAL_ERROR; /* ??? we may be partly committed */

	/* Last block of Phase 1 (R3), kept for Phase 2 IV generation */
	DBG_cond_dump(DBG_CRYPT, "last encrypted block of Phase 1:",
		st->st_new_iv, st->st_new_iv_len);

	set_ph1_iv_from_new(st);

	/*
	 * It seems as per Cisco implementation, XAUTH and MODECFG
	 * are not supposed to be performed again during rekey
	 */

	if (st->st_connection->remotepeertype == CISCO &&
		st->st_connection->newest_isakmp_sa != SOS_NOBODY &&
		st->st_connection->spd.this.xauth_client) {
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

	ISAKMP_SA_established(st->st_connection, st->st_serialno);
#ifdef USE_LINUX_AUDIT
	linux_audit_conn(st, LAK_PARENT_START);
#endif


	return STF_OK;
}

/*
 * STATE_MAIN_I3:
 * Handle HDR*;IDir;HASH/SIG_R from responder.
 *
 * Broken into parts to allow asynchronous DNS for KEY records.
 *
 * - main_inR3 to start
 * - main_inR3_tail to finish or suspend for DNS lookup
 * - main_inR3_continue to start main_inR3_tail again
 */

static key_tail_fn main_inR3_tail; /* forward */

stf_status main_inR3(struct msg_digest *md)
{
	return main_inR3_tail(md, NULL);
}

static void main_inR3_continue(struct adns_continuation *cr, err_t ugh)
{
	key_continue(cr, ugh, main_inR3_tail);
}

static stf_status main_inR3_tail(struct msg_digest *md,
				struct key_continuation *kc)
{
	struct state *const st = md->st;

	/*
	 * ID and HASH_R or SIG_R in
	 * Note: this may switch the connection being used!
	 */
	{
		stf_status r = main_id_and_auth(md, TRUE, main_inR3_continue,
						kc);

		if (r != STF_OK)
			return r;
	}

	/* Done input */

	/*
	 * It seems as per Cisco implementation, XAUTH and MODECFG
	 * are not supposed to be performed again during rekey
	 */
	if (st->st_connection->remotepeertype == CISCO &&
		st->st_connection->newest_isakmp_sa != SOS_NOBODY &&
		st->st_connection->spd.this.xauth_client) {
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

	ISAKMP_SA_established(st->st_connection, st->st_serialno);
#ifdef USE_LINUX_AUDIT
	linux_audit_conn(st, LAK_PARENT_START);
#endif

	passert((st->st_policy & POLICY_PFS) == 0 ||
		st->st_pfs_group != NULL);

	/*
	 * save last IV from phase 1 so it can be restored later so anything
	 * between the end of phase 1 and the start of phase 2 i.e. mode config
	 * payloads etc. will not lose our IV
	 */
	set_ph1_iv_from_new(st);

	update_iv(st); /* finalize our Phase 1 IV */

	if (md->ikev2) {
		/*
		 * We cannot use POLICY_IKEV2_ALLOW here, since this will
		 * cause two IKEv2 capable but not ikev2= configured endpoints
		 * to falsely detect a bid down attack.
		 * Also, only the side that proposed IKEv2 can figure out there
		 * was a bid down attack to begin with. The side that did not propose
		 * cannot distinguish attack from regular ikev1 operation.
		 */
		if (st->st_connection->policy & POLICY_IKEV2_PROPOSE) {
			libreswan_log(
				"Bid-down to IKEv1 attack detected, attempting to rekey connection with IKEv2");
			st->st_connection->failed_ikev2 = FALSE;

			/* schedule an event to do this as soon as possible */
			md->event_already_set = TRUE;
			st->st_rekeytov2 = TRUE;
			delete_event(st);
			event_schedule(EVENT_SA_REPLACE, 0, st);
		}
	}

	return STF_OK;
}

stf_status send_isakmp_notification(struct state *st,
				u_int16_t type, const void *data,
				size_t len)
{
	msgid_t msgid;
	pb_stream rbody;
	u_char
		*r_hashval, /* where in reply to jam hash value */
		*r_hash_start; /* start of what is to be hashed */

	msgid = generate_msgid(st);

	init_out_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
		"ISAKMP notify");

	/* HDR* */
	{
		struct isakmp_hdr hdr;
		hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
			ISAKMP_MINOR_VERSION;
		hdr.isa_np = ISAKMP_NEXT_HASH;
		hdr.isa_xchg = ISAKMP_XCHG_INFO;
		hdr.isa_msgid = msgid;
		hdr.isa_flags = ISAKMP_FLAGS_v1_ENCRYPTION;
		memcpy(hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
		memcpy(hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply_stream, &rbody))
			impossible();
	}
	/* HASH -- create and note space to be filled later */
	START_HASH_PAYLOAD(rbody, ISAKMP_NEXT_N);

	/* NOTIFY */
	{
		pb_stream notify_pbs;
		struct isakmp_notification isan;

		isan.isan_np = ISAKMP_NEXT_NONE;
		isan.isan_doi = ISAKMP_DOI_IPSEC;
		isan.isan_protoid = PROTO_ISAKMP;
		isan.isan_spisize = COOKIE_SIZE * 2;
		isan.isan_type = type;
		if (!out_struct(&isan, &isakmp_notification_desc, &rbody,
					&notify_pbs))
			return STF_INTERNAL_ERROR;

		if (!out_raw(st->st_icookie, COOKIE_SIZE, &notify_pbs,
				"notify icookie"))
			return STF_INTERNAL_ERROR;

		if (!out_raw(st->st_rcookie, COOKIE_SIZE, &notify_pbs,
				"notify rcookie"))
			return STF_INTERNAL_ERROR;

		if (data != NULL && len > 0)
			if (!out_raw(data, len, &notify_pbs, "notify data"))
				return STF_INTERNAL_ERROR;

		close_output_pbs(&notify_pbs);
	}


	{
		/* finish computing HASH */
		struct hmac_ctx ctx;

		hmac_init(&ctx, st->st_oakley.prf_hasher,
				st->st_skeyid_a_nss);
		hmac_update(&ctx, (const u_char *) &msgid, sizeof(msgid_t));
		hmac_update(&ctx, r_hash_start, rbody.cur - r_hash_start);
		hmac_final(r_hashval, &ctx);

		DBG(DBG_CRYPT, {
				DBG_log("HASH computed:");
				DBG_dump("", r_hashval, ctx.hmac_digest_len);
			});
	}
	/*
	 * save old IV (this prevents from copying a whole new state object
	 * for NOTIFICATION / DELETE messages we don't need to maintain a state
	 * because there are no retransmissions...
	 */
	{
		u_char old_new_iv[MAX_DIGEST_LEN];
		unsigned int old_new_iv_len;
		u_char old_iv[MAX_DIGEST_LEN];
		unsigned int old_iv_len;

		save_iv(st, old_iv, old_iv_len);
		save_new_iv(st, old_new_iv, old_new_iv_len);

		init_phase2_iv(st, &msgid);
		if (!encrypt_message(&rbody, st))
			return STF_INTERNAL_ERROR;

		send_ike_msg_without_recording(st, &reply_stream, "ISAKMP notify");

		/* get back old IV for this state */
		restore_iv(st, old_iv, old_iv_len);
		restore_new_iv(st, old_new_iv, old_new_iv_len);
	}

	return STF_IGNORE;
}

/*
 * Send a notification to the peer. We could decide
 * whether to send the notification, based on the type and the
 * destination, if we care to.
 * Note: some calls are from send_notification_from_md and
 * those calls pass a fake state as sndst.
 */
static void send_notification(struct state *sndst, notification_t type,
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
	u_char *r_hashval, *r_hash_start;
	static monotime_t last_malformed;
	monotime_t n = mononow();
	struct isakmp_hdr hdr; /* keep it around for TPM */

	struct connection *c = sndst->st_connection;

	r_hashval = NULL;
	r_hash_start = NULL;

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
			/*
			 * Log this if it is for a non-opportunistic connection
			 * or if DBG_OPPO is on.  We don't want a DoS.
			 * Using DBG_OPPO is kind of odd because this is not
			 * controlling DBG_log.
			 */
			if ((c->policy & POLICY_OPPORTUNISTIC) == LEMPTY ||
			    DBGP(DBG_OPPO)) {
				libreswan_log(
					"too many (%d) malformed payloads. Deleting state",
					sndst->hidden_variables.st_malformed_sent);
			}
			delete_state(sndst);
			/* note: no md->st to clear */
			return;
		}

		if (sndst->st_iv_len != 0) {
			libreswan_DBG_dump("payload malformed.  IV:", sndst->st_iv,
					sndst->st_iv_len);
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

	if (encst != NULL && !IS_ISAKMP_ENCRYPTED(encst->st_state))
		encst = NULL;

	/*
	 * Log this if it is for a non-opportunistic connection
	 * or if DBG_OPPO is on.  We don't want a DoS.
	 * Using DBG_OPPO is kind of odd because this is not
	 * controlling DBG_log.
	 */
	if ((c->policy & POLICY_OPPORTUNISTIC) == LEMPTY ||
	    DBGP(DBG_OPPO)) {
		ipstr_buf b;

		libreswan_log("sending %snotification %s to %s:%u",
			encst ? "encrypted " : "",
			enum_name(&ikev1_notify_names, type),
			ipstr(&sndst->st_remoteaddr, &b),
			sndst->st_remoteport);
	}

	init_out_pbs(&pbs, buffer, sizeof(buffer), "notification msg");

	/* HDR* */
	{
		hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
			ISAKMP_MINOR_VERSION;
		hdr.isa_np = encst ? ISAKMP_NEXT_HASH : ISAKMP_NEXT_N;
		hdr.isa_xchg = ISAKMP_XCHG_INFO;
		hdr.isa_msgid = msgid;
		hdr.isa_flags = encst ? ISAKMP_FLAGS_v1_ENCRYPTION : 0;
		if (icookie)
			memcpy(hdr.isa_icookie, icookie, COOKIE_SIZE);
		if (rcookie)
			memcpy(hdr.isa_rcookie, rcookie, COOKIE_SIZE);
		if (!out_struct(&hdr, &isakmp_hdr_desc, &pbs, &r_hdr_pbs))
			impossible();
	}

	/* HASH -- value to be filled later */
	if (encst) {
		pb_stream hash_pbs;
		if (!ikev1_out_generic(ISAKMP_NEXT_N, &isakmp_hash_desc, &r_hdr_pbs,
					&hash_pbs))
			impossible();
		r_hashval = hash_pbs.cur; /* remember where to plant value */
		if (!out_zero(encst->st_oakley.prf_hasher->hash_digest_len,
				&hash_pbs, "HASH(1)"))
			impossible();
		close_output_pbs(&hash_pbs);
		r_hash_start = r_hdr_pbs.cur; /* hash from after HASH(1) */
	}

	/* Notification Payload */
	{
		pb_stream not_pbs;
		struct isakmp_notification isan;

		isan.isan_doi = ISAKMP_DOI_IPSEC;
		isan.isan_np = ISAKMP_NEXT_NONE;
		isan.isan_type = type;
		isan.isan_spisize = 0;
		isan.isan_protoid = protoid;

		if (!out_struct(&isan, &isakmp_notification_desc,
					&r_hdr_pbs, &not_pbs)) {
			libreswan_log(
				"failed to build notification in send_notification");
			return;
		}

		close_output_pbs(&not_pbs);
	}

	/* calculate hash value and patch into Hash Payload */
	if (encst) {
		struct hmac_ctx ctx;

		hmac_init(&ctx, encst->st_oakley.prf_hasher,
				encst->st_skeyid_a_nss);
		hmac_update(&ctx, (u_char *) &msgid, sizeof(msgid_t));
		hmac_update(&ctx, r_hash_start, r_hdr_pbs.cur - r_hash_start);
		hmac_final(r_hashval, &ctx);

		DBG(DBG_CRYPT, {
				DBG_log("HASH(1) computed:");
				DBG_dump("", r_hashval, ctx.hmac_digest_len);
			});
	}

	if (encst != NULL) {
		/* Encrypt message (preserve st_iv) */
		/* ??? why not preserve st_new_iv? */
		u_char old_iv[MAX_DIGEST_LEN];
		u_int old_iv_len;

		save_iv(encst, old_iv, old_iv_len);

		if (!IS_ISAKMP_SA_ESTABLISHED(encst->st_state)) {
			update_iv(encst);
		}
		init_phase2_iv(encst, &msgid);
		if (!encrypt_message(&r_hdr_pbs, encst))
			impossible();

		restore_iv(encst, old_iv, old_iv_len);
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
		from_state = st->st_state;

	if (IS_QUICK(from_state)) {
		p1st = find_phase1_state(st->st_connection,
					ISAKMP_SA_ESTABLISHED_STATES);
		if ((p1st == NULL) ||
			(!IS_ISAKMP_SA_ESTABLISHED(p1st->st_state))) {
			loglog(RC_LOG_SERIOUS,
				"no Phase1 state for Quick mode notification");
			return;
		}
		send_notification(st, type, p1st, generate_msgid(p1st),
				st->st_icookie, st->st_rcookie,
				PROTO_ISAKMP);
	} else if (IS_ISAKMP_ENCRYPTED(from_state)) {
		send_notification(st, type, st, generate_msgid(st),
				st->st_icookie, st->st_rcookie,
				PROTO_ISAKMP);
	} else {
		/* no ISAKMP SA established - don't encrypt notification */
		send_notification(st, type, NULL, v1_MAINMODE_MSGID,
				st->st_icookie, st->st_rcookie,
				PROTO_ISAKMP);
	}
}

void send_notification_from_md(struct msg_digest *md, notification_t type)
{
	/*
	 * Note: send_notification_from_md and send_v2_notification_from_md
	 * share code (and bugs).  Any fix to one should be done to both.
	 *
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
		.addr_family = addrtypeof(&md->sender),	/* for should_fragment_ike_msg() */
		.policy = POLICY_IKE_FRAG_FORCE |	/* for should_fragment_ike_msg() */
			POLICY_OPPORTUNISTIC,	/* for reducing logging various places */
	};

	struct state fake_state = {
		.st_serialno = SOS_NOBODY,
		.st_connection = &fake_connection,	/* for should_fragment_ike_msg() */
	};

	passert(md != NULL);

	update_ike_endpoints(&fake_state, md);
	send_notification(&fake_state, type, NULL, 0,
			md->hdr.isa_icookie, md->hdr.isa_rcookie,
			PROTO_ISAKMP);
}

/*
 * Send a Delete Notification to announce deletion of ISAKMP SA or
 * inbound IPSEC SAs. Does nothing if no such SAs are being deleted.
 * Delete Notifications cannot announce deletion of outbound IPSEC/ISAKMP SAs.
 *
 * @param st State struct (hopefully has some SA's related to it)
 */
bool ikev1_delete_out(struct state *st)
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
	u_char
		*r_hashval, /* where in reply to jam hash value */
		*r_hash_start; /* start of what is to be hashed */
	bool isakmp_sa = FALSE;
	struct isakmp_hdr hdr;

	/* If there are IPsec SA's related to this state struct... */
	if (IS_IPSEC_SA_ESTABLISHED(st->st_state)) {
		/* Find their phase1 state object */
		p1st = find_phase1_state(st->st_connection,
					ISAKMP_SA_ESTABLISHED_STATES);
		if (p1st == NULL) {
			DBG(DBG_CONTROL,
				DBG_log("no Phase 1 state for Delete"));
			return FALSE;
		}

		if (st->st_ah.present) {
			ns->spi = st->st_ah.our_spi;
			ns->dst = st->st_connection->spd.this.host_addr;
			ns->proto = PROTO_IPSEC_AH;
			ns++;
		}
		if (st->st_esp.present) {
			ns->spi = st->st_esp.our_spi;
			ns->dst = st->st_connection->spd.this.host_addr;
			ns->proto = PROTO_IPSEC_ESP;
			ns++;
		}

		passert(ns != said); /* there must be some SAs to delete */
	} else if (IS_ISAKMP_SA_ESTABLISHED(st->st_state)) {
		/* or ISAKMP SA's... */
		p1st = st;
		isakmp_sa = TRUE;
	} else {
		return TRUE; /* nothing to do */
	}

	msgid = generate_msgid(p1st);

	init_out_pbs(&reply_pbs, buffer, sizeof(buffer), "delete msg");

	/* HDR* */
	{
		hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
			ISAKMP_MINOR_VERSION;
		hdr.isa_np = ISAKMP_NEXT_HASH;
		hdr.isa_xchg = ISAKMP_XCHG_INFO;
		hdr.isa_msgid = msgid;
		hdr.isa_flags = ISAKMP_FLAGS_v1_ENCRYPTION;
		memcpy(hdr.isa_icookie, p1st->st_icookie, COOKIE_SIZE);
		memcpy(hdr.isa_rcookie, p1st->st_rcookie, COOKIE_SIZE);
		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply_pbs,
					&r_hdr_pbs))
			impossible();
	}

	/* HASH -- value to be filled later */
	{
		pb_stream hash_pbs;

		if (!ikev1_out_generic(ISAKMP_NEXT_D, &isakmp_hash_desc, &r_hdr_pbs,
					&hash_pbs))
			impossible();
		r_hashval = hash_pbs.cur; /* remember where to plant value */
		if (!out_zero(p1st->st_oakley.prf_hasher->hash_digest_len,
				&hash_pbs, "HASH(1)"))
			impossible();
		close_output_pbs(&hash_pbs);
		r_hash_start = r_hdr_pbs.cur; /* hash from after HASH(1) */
	}

	/* Delete Payloads */
	if (isakmp_sa) {
		pb_stream del_pbs;
		struct isakmp_delete isad;
		u_char isakmp_spi[2 * COOKIE_SIZE];

		isad.isad_doi = ISAKMP_DOI_IPSEC;
		isad.isad_np = ISAKMP_NEXT_NONE;
		isad.isad_spisize = (2 * COOKIE_SIZE);
		isad.isad_protoid = PROTO_ISAKMP;
		isad.isad_nospi = 1;

		memcpy(isakmp_spi, st->st_icookie, COOKIE_SIZE);
		memcpy(isakmp_spi + COOKIE_SIZE, st->st_rcookie, COOKIE_SIZE);

		if (!out_struct(&isad, &isakmp_delete_desc, &r_hdr_pbs,
					&del_pbs) ||
			!out_raw(&isakmp_spi, (2 * COOKIE_SIZE), &del_pbs,
				"delete payload"))
			impossible();
		close_output_pbs(&del_pbs);
	} else {
		while (ns != said) {

			pb_stream del_pbs;
			struct isakmp_delete isad;

			ns--;
			isad.isad_doi = ISAKMP_DOI_IPSEC;
			isad.isad_np = ns ==
				said ? ISAKMP_NEXT_NONE : ISAKMP_NEXT_D;
			isad.isad_spisize = sizeof(ipsec_spi_t);
			isad.isad_protoid = ns->proto;

			isad.isad_nospi = 1;
			if (!out_struct(&isad, &isakmp_delete_desc, &r_hdr_pbs,
						&del_pbs) ||
				!out_raw(&ns->spi, sizeof(ipsec_spi_t),
					&del_pbs,
					"delete payload"))
				impossible();
			close_output_pbs(&del_pbs);
		}
	}

	/* calculate hash value and patch into Hash Payload */
	{
		struct hmac_ctx ctx;

		hmac_init(&ctx, p1st->st_oakley.prf_hasher,
				p1st->st_skeyid_a_nss);
		hmac_update(&ctx, (u_char *) &msgid, sizeof(msgid_t));
		hmac_update(&ctx, r_hash_start, r_hdr_pbs.cur - r_hash_start);
		hmac_final(r_hashval, &ctx);

		DBG(DBG_CRYPT, {
				DBG_log("HASH(1) computed:");
				DBG_dump("", r_hashval, ctx.hmac_digest_len);
			});
	}

	/*
	 * Do a dance to avoid needing a new state object.
	 * We use the Phase 1 State. This is the one with right
	 * IV, for one thing.
	 * The tricky bits are:
	 * - we need to preserve (save/restore) st_iv (but not st_iv_new)
	 * - we need to preserve (save/restore) st_tpacket.
	 */
	{
		u_char old_iv[MAX_DIGEST_LEN];
		unsigned int old_iv_len;

		save_iv(p1st, old_iv, old_iv_len);
		init_phase2_iv(p1st, &msgid);

		if (!encrypt_message(&r_hdr_pbs, p1st))
			impossible();

		send_ike_msg_without_recording(p1st, &reply_pbs, "delete notify");

		/* get back old IV for this state */
		restore_iv(p1st, old_iv, old_iv_len);
	}
	return TRUE;
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
		loglog(RC_LOG_SERIOUS,
			"ignoring Delete SA payload: not encrypted");
		return self_delete;
	}

	/* If there is no SA related to this request, but it was encrypted */
	if (!IS_ISAKMP_SA_ESTABLISHED(st->st_state)) {
		/* can't happen (if msg is encrypt), but just to be sure */
		loglog(RC_LOG_SERIOUS,
			"ignoring Delete SA payload: ISAKMP SA not established");
		return self_delete;
	}

	if (d->isad_nospi == 0) {
		loglog(RC_LOG_SERIOUS, "ignoring Delete SA payload: no SPI");
		return self_delete;
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
		return self_delete;

	default:
		loglog(RC_LOG_SERIOUS,
			"ignoring Delete SA payload: unknown Protocol ID (%s)",
			enum_show(&ikev1_protocol_names, d->isad_protoid));
		return self_delete;
	}

	if (d->isad_spisize != sizespi) {
		loglog(RC_LOG_SERIOUS,
			"ignoring Delete SA payload: bad SPI size (%d) for %s",
			d->isad_spisize,
			enum_show(&ikev1_protocol_names, d->isad_protoid));
		return self_delete;
	}

	if (pbs_left(&p->pbs) != d->isad_nospi * sizespi) {
		loglog(RC_LOG_SERIOUS,
			"ignoring Delete SA payload: invalid payload size");
		return self_delete;
	}

	for (i = 0; i < d->isad_nospi; i++) {
		if (d->isad_protoid == PROTO_ISAKMP) {
			/*
			 * ISAKMP
			 */
			u_int8_t icookie[COOKIE_SIZE];
			u_int8_t rcookie[COOKIE_SIZE];
			struct state *dst;

			if (!in_raw(icookie, COOKIE_SIZE, &p->pbs, "iCookie"))
				return self_delete;

			if (!in_raw(rcookie, COOKIE_SIZE, &p->pbs, "rCookie"))
				return self_delete;

			dst = find_state_ikev1(icookie, rcookie,
					v1_MAINMODE_MSGID);

			if (dst == NULL) {
				loglog(RC_LOG_SERIOUS, "ignoring Delete SA payload: ISAKMP SA not found (maybe expired)");
			} else if (!same_peer_ids(st->st_connection,
							dst->st_connection,
							NULL)) {
				/*
				 * we've not authenticated the relevant
				 * identities
				 */
				loglog(RC_LOG_SERIOUS, "ignoring Delete SA payload: ISAKMP SA used to convey Delete has different IDs from ISAKMP SA it deletes");
			} else if (dst == st) {
				/*
				 * remember this for later:
				 * we need st to do any remaining deletes
				 */
				self_delete = TRUE;
			} else {
				/* note: this code is cloned for handling self_delete */
				loglog(RC_LOG_SERIOUS, "received Delete SA payload: deleting ISAKMP State #%lu",
					dst->st_serialno);
				if (nat_traversal_enabled)
					nat_traversal_change_port_lookup(md,
									dst);
				delete_state(dst);
			}
		} else {
			/*
			 * IPSEC (ESP/AH)
			 */
			ipsec_spi_t spi;	/* network order */

			if (!in_raw(&spi, sizeof(spi), &p->pbs, "SPI"))
				return self_delete;

			bool bogus;
			struct state *dst = find_phase2_state_to_delete(st,
							d->isad_protoid,
							spi,
							&bogus);

			passert(dst != st);	/* st is an IKE SA */
			if (dst == NULL) {
				loglog(RC_LOG_SERIOUS,
					"ignoring Delete SA payload: %s SA(0x%08" PRIx32 ") not found (maybe expired)",
					enum_show(&ikev1_protocol_names,
						d->isad_protoid),
					ntohl(spi));
			} else {
				if (bogus) {
					loglog(RC_LOG_SERIOUS,
						"warning: Delete SA payload: %s SA(0x%08" PRIx32 ") is our own SPI (bogus implementation) - deleting anyway",
						enum_show(&ikev1_protocol_names,
							d->isad_protoid),
						ntohl(spi));
				}

				struct connection *rc = dst->st_connection;
				struct connection *oldc = cur_connection;

				set_cur_connection(rc);

				if (nat_traversal_enabled)
					nat_traversal_change_port_lookup(md,
									dst);

				if (rc->newest_ipsec_sa == dst->st_serialno &&
					(rc->policy & POLICY_UP)) {
					/*
					 * Last IPsec SA for a permanent
					 * connection that we have initiated.
					 * Replace it in a few seconds.
					 *
					 * Useful if the other peer is
					 * rebooting.
					 */
					if (dst->st_event != NULL &&
					    dst->st_event->ev_type ==
						  EVENT_SA_REPLACE &&
					    !monobefore(monotimesum(mononow(),
						  deltatime(DELETE_SA_DELAY)),
						dst->st_event->ev_time)) {
						/*
						 * Patch from Angus Lees to
						 * ignore retransmitted
						 * Delete SA.
						 */
						loglog(RC_LOG_SERIOUS,
							"received Delete SA payload: already replacing IPSEC State #%lu in %ld seconds",
							dst->st_serialno,
							(long)deltasecs(monotimediff(
								dst->st_event->ev_time,
								mononow())));
					} else {
						loglog(RC_LOG_SERIOUS,
							"received Delete SA payload: replace IPSEC State #%lu in %d seconds",
							dst->st_serialno,
							DELETE_SA_DELAY);
						dst->st_margin = deltatime(
							DELETE_SA_DELAY);
						delete_event(dst);
						event_schedule(
							EVENT_SA_REPLACE,
							DELETE_SA_DELAY, dst);
					}
				} else {
					loglog(RC_LOG_SERIOUS,
						"received Delete SA(0x%08" PRIx32 ") payload: deleting IPSEC State #%lu",
						ntohl(spi),
						dst->st_serialno);
					delete_state(dst);
					if (md->st == dst)
						md->st = NULL;
				}

				if (rc->newest_ipsec_sa == SOS_NOBODY) {
					rc->policy &= ~POLICY_UP;
					flush_pending_by_connection(rc);
					delete_states_by_connection(rc, FALSE);
					reset_cur_connection();
				}
				/* reset connection */
				set_cur_connection(oldc);
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
	loglog(RC_LOG_SERIOUS, "received Delete SA payload: self-deleting ISAKMP State #%lu",
		st->st_serialno);
	if (nat_traversal_enabled)
		nat_traversal_change_port_lookup(md, st);
	delete_state(st);
	md->st = st = NULL;
}
