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
 * Modifications to use OCF interface written by
 * Daniel Djamaludin <danield@cyberguard.com>
 * Copyright (C) 2004-2005 Intel Corporation.
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
#include <gmp.h>
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
#include "connections.h" /* needs id.h */
#include "keys.h"
#include "packet.h"
#include "demux.h" /* needs packet.h */
#include "adns.h" /* needs <resolv.h> */
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

#include "lswcrypto.h"

#include "xauth.h"

#include "vendor.h"
#include "nat_traversal.h"
#ifdef VIRTUAL_IP
#include "virtual.h"	/* needs connections.h */
#endif
#include "dpd.h"
#include "x509more.h"

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
		, struct xfrm_user_sec_ctx_ike * uctx
#endif
	)
{
	struct state *st = new_state();
	struct msg_digest md; /* use reply/rbody found inside */

	int numvidtosend = 1; /* we always send DPD VID */

	/* Increase VID counter for VID_IKE_FRAGMENTATION */
	if (c->policy & POLICY_IKE_FRAG_ALLOW)
		numvidtosend++;

	if (nat_traversal_enabled)
		numvidtosend++;

	/* add one for sending CISCO-UNITY */
	if (c->cisco_unity) {
		numvidtosend++;
	}

	if (c->send_vendorid) {
		numvidtosend++;
	}

	if (c->spd.this.xauth_client || c->spd.this.xauth_server)
		numvidtosend++;

	/* set up new state */
	get_cookie(TRUE, st->st_icookie, COOKIE_SIZE, &c->spd.that.host_addr);
	initialize_new_state(st, c, policy, try, whack_sock, importance);
	change_state(st, STATE_MAIN_I1);

	if (HAS_IPSEC_POLICY(policy)) {
		add_pending(dup_any(whack_sock), st, c, policy, 1,
			predecessor ==
			NULL ? SOS_NOBODY : predecessor->st_serialno
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
	zero(reply_buffer);
	init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
		"reply packet");

	/* HDR out */
	{
		struct isakmp_hdr hdr;

		zero(&hdr); /* default to 0 */
		hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
			ISAKMP_MINOR_VERSION;
		hdr.isa_np = ISAKMP_NEXT_SA;
		hdr.isa_xchg = ISAKMP_XCHG_IDPROT;
		memcpy(hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
		/* R-cookie, flags and MessageID are left zero */

		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply_stream,
				&md.rbody)) {
			reset_cur_state();
			return STF_INTERNAL_ERROR;
		}
	}

	/* SA out */
	{
		u_char *sa_start = md.rbody.cur;
		unsigned policy_index = POLICY_ISAKMP(policy, c);
		int np = numvidtosend > 0 ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;

		if (!out_sa(&md.rbody, &oakley_sadb[policy_index], st, TRUE,
				FALSE, np)) {
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
		const char *myvid = ipsec_version_vendorid();
		int np = --numvidtosend >0 ?
			ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;

		if (!out_generic_raw(np, &isakmp_vendor_id_desc, &md.rbody,
					myvid, strlen(myvid), "Vendor ID")) {
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
		if (!nat_traversal_insert_vid(np, &md.rbody)) {
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
			"payload alignment problem please check the code in "
			"main_inR1_outR2 (num=%d)",
			numvidtosend);

	close_message(&md.rbody, st);
	close_output_pbs(&reply_stream);

	clonetochunk(st->st_tpacket, reply_stream.start,
		pbs_offset(&reply_stream),
		"reply packet for main_outI1");

	/* Transmit */
	send_ike_msg(st, "main_outI1");

	delete_event(st);
	event_schedule(EVENT_RETRANSMIT, EVENT_RETRANSMIT_DELAY_0, st);

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

	hmac_init_chunk(&ctx, st->st_oakley.prf_hasher, st->st_skeyid);
	main_mode_hash_body(st, hashi, idpl, &ctx, NULL);
	hmac_final(hash_val, &ctx);
	return ctx.hmac_digest_len;
}

/*
 * Create an RSA signature of a hash.
 * Poorly specified in draft-ietf-ipsec-ike-01.txt 6.1.1.2.
 * Use PKCS#1 version 1.5 encryption of hash (called
 * RSAES-PKCS1-V1_5) in PKCS#2.
 */
size_t RSA_sign_hash(struct connection *c,
		u_char sig_val[RSA_MAX_OCTETS],
		const u_char *hash_val, size_t hash_len)
{
	size_t sz = 0;
	const struct RSA_private_key *k = get_RSA_private_key(c);

	if (k == NULL)
		return 0; /* failure: no key to use */

	sz = k->pub.k;
	passert(RSA_MIN_OCTETS <= sz &&
		4 + hash_len < sz &&
		sz <= RSA_MAX_OCTETS);
	sign_hash(k, hash_val, hash_len, sig_val, sz);
	return sz;
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

        if (len < MINIMUM_NONCE_SIZE || MAXIMUM_NONCE_SIZE < len) {
                loglog(RC_LOG_SERIOUS, "%s length not between %d and %d",
                       name, MINIMUM_NONCE_SIZE, MAXIMUM_NONCE_SIZE);
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

	DBG_cond_dump(DBG_CRYPT | DBG_RAW, "encrypting:\n", enc_start,
		enc_len);
	DBG_cond_dump(DBG_CRYPT | DBG_RAW, "IV:\n",
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
	close_message(pbs, st);
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

#ifdef DMALLOC
static unsigned long dm_mark = 0;
static unsigned long dm_initialized = 0;
#endif

stf_status main_inI1_outR1(struct msg_digest *md)
{
#ifdef DMALLOC
	if (dm_initialized != 0) {
		/*
		 * log unfreed pointers that have been added to the heap
		 * since mark
		 */
		dmalloc_log_changed(dm_mark, 1, 0, 1);
		dmalloc_log_stats();
	}
	dm_mark = dmalloc_mark();
	dm_initialized = 1;
#endif

	struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_SA];
	struct state *st;
	struct connection *c;
	pb_stream r_sa_pbs;

	/* Determine how many Vendor ID payloads we will be sending */
	int numvidtosend = 1; /* we always send DPD VID */

	/* random source ports are handled by find_host_connection */
	c = find_host_connection(&md->iface->ip_addr, pluto_port,
				&md->sender,
				md->sender_port, LEMPTY);

	if (c != NULL && (c->policy & POLICY_IKEV1_DISABLE)) {
		loglog(RC_LOG_SERIOUS, "discard matching conn %s for I1 from "
			"%s:%u. has ikev2=insist", c->name,
			ip_str(&md->iface->ip_addr),
			ntohs(portof(&md->iface->ip_addr)));
		c = NULL;
	}

	if (c == NULL) {
		pb_stream pre_sa_pbs = sa_pd->pbs;
		lset_t policy = preparse_isakmp_sa_body(&pre_sa_pbs);

#if 0
		/*
		 * Other IKE clients, such as strongswan, send the XAUTH
		 * VID even for connections they do not want to run XAUTH on.
		 * We need to depend on the policy negotiation, not the VID.
		 */

		/*
		 * If there is XAUTH VID, copy it to policies.
		 */
		if (md->quirks.xauth_vid)
			policy |= POLICY_XAUTH;

#endif
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
			struct connection *d;
			d = find_host_connection(&md->iface->ip_addr,
						pluto_port,
						(ip_address*)NULL,
						md->sender_port, policy);

			for (; d != NULL; d = d->hp_next) {
				if (d->policy & POLICY_IKEV1_DISABLE) {
					loglog(RC_LOG_SERIOUS,
						"discard matching conn %s for "
						"I1 from %s:%u. %s %s %s has "
						"ikev2=insist ", c->name,
						ip_str(&md->iface->ip_addr),
						ntohs(portof(&md->iface->ip_addr)),
						d->name,
						(policy != LEMPTY) ?
						" with policy=" : "",
						(policy != LEMPTY) ?
						bitnamesof(sa_policy_bit_names,
							policy) : "");
					d=NULL;
					continue;
				}

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
					if (addrinsubnet(&md->sender,
						&d->spd.that.client) &&
						(c == NULL ||
						!subnetinsubnet(&c->spd.that.
						client,
						&d->spd.that.client)))
						c = d;
				}
			}
		}

		if (c == NULL) {
			loglog(RC_LOG_SERIOUS, "initial Main Mode message "
				"received on %s:%u "
				"but no connection has been authorized%s%s",
				ip_str(&md->iface->ip_addr),
				ntohs(portof(&md->iface->ip_addr)),
				(policy != LEMPTY) ? " with policy=" : "",
				(policy != LEMPTY) ?
				bitnamesof(sa_policy_bit_names, policy) : "");
			/* XXX notification is in order! */
			return STF_IGNORE;
		} else if (c->kind != CK_TEMPLATE) {
			loglog(RC_LOG_SERIOUS, "initial Main Mode message "
				"received on %s:%u "
				"but \"%s\" forbids connection",
				ip_str(&md->iface->ip_addr), pluto_port,
				c->name);
			/* XXX notification is in order! */
			return STF_IGNORE;
		} else {
			/*
			 * Create a temporary connection that is a copy
			 * of this one.
			 * His ID isn't declared yet.
			 */
			DBG(DBG_CONTROL,
				DBG_log("instantiating \"%s\" for initial "
					"Main Mode message received on %s:%u",
					c->name,
					ip_str(&md->iface->ip_addr),
					pluto_port));
			c = rw_instantiate(c, &md->sender,
					NULL, NULL);
		}
	} else {
		/*
		 * we found a non-wildcard conn. double check if it needs
		 * instantiation anyway (eg vnet=)
		 */
		if ((c->kind == CK_TEMPLATE) && c->spd.that.virt) {
			DBG(DBG_CONTROL,
				DBG_log("local endpoint has virt (vnet/vhost) "
					"set without wildcards - needs "
					"instantiation"));
			c = rw_instantiate(c, &md->sender, NULL, NULL);
		}
	}

	/* Set up state */
	md->st = st = new_state();

	passert(!st->st_oakley.doing_xauth);

	st->st_connection = c;
	st->st_remoteaddr = md->sender;
	st->st_remoteport = md->sender_port;
	st->st_localaddr = md->iface->ip_addr;
	st->st_localport = md->iface->port;
	st->st_interface = md->iface;

	set_cur_state(st); /* (caller will reset cur_state) */
	st->st_try = 0; /* not our job to try again from start */
	/* only as accurate as connection */
	st->st_policy = c->policy & ~POLICY_IPSEC_MASK;
	change_state(st, STATE_MAIN_R0);

	memcpy(st->st_icookie, md->hdr.isa_icookie, COOKIE_SIZE);
	get_cookie(FALSE, st->st_rcookie, COOKIE_SIZE, &md->sender);

	insert_state(st); /* needs cookies, connection, and msgid (0) */

	st->st_doi = ISAKMP_DOI_IPSEC;
	st->st_situation = SIT_IDENTITY_ONLY; /* We only support this */

	/* copy the quirks we might have accumulated */
	copy_quirks(&st->quirks, &md->quirks);

	if ((c->kind == CK_INSTANCE) && (c->spd.that.host_port_specific)) {
		libreswan_log(
			"responding to Main Mode from unknown peer %s:%u",
			ip_str(&c->spd.that.host_addr),
			c->spd.that.host_port);
	} else if (c->kind == CK_INSTANCE) {
		libreswan_log("responding to Main Mode from unknown peer %s",
			ip_str(&c->spd.that.host_addr));
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
	zero(reply_buffer);
	init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
		"reply packet");
	{
		struct isakmp_hdr r_hdr = md->hdr;

		/* we won't ever turn on this bit */
		r_hdr.isa_flags &= ~ISAKMP_FLAG_COMMIT;
		memcpy(r_hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
		r_hdr.isa_np = ISAKMP_NEXT_SA;
		if (!out_struct(&r_hdr, &isakmp_hdr_desc, &reply_stream,
					&md->rbody))
			return STF_INTERNAL_ERROR;
	}

	/* Increase VID counter for NAT-T VID */
	if (md->quirks.nat_traversal_vid && nat_traversal_enabled) {
		DBG(DBG_NATT, DBG_log("nat-t detected, sending nat-t VID"));
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
		struct isakmp_sa r_sa = sa_pd->payload.sa;

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
		const char *myvid = ipsec_version_vendorid();
		int np = --numvidtosend ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;
		if (!out_generic_raw(np, &isakmp_vendor_id_desc, &md->rbody,
					myvid, strlen(myvid), "Vendor ID"))
			return STF_INTERNAL_ERROR;
	}

	{
		/*
		 * always announce our ability to do RFC 3706
		 * Dead Peer Detection
		 */
		int np = --numvidtosend ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;
		if ( !out_vid(np, &md->rbody, VID_MISC_DPD))
			return STF_INTERNAL_ERROR;
	}

	/* Announce our ability to do (non-RFC) IKE Fragmentation */
	if (c->policy & POLICY_IKE_FRAG_ALLOW) {
		int np = --numvidtosend > 0 ? ISAKMP_NEXT_VID :
			ISAKMP_NEXT_NONE;
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

	DBG(DBG_NATT, DBG_log("sender checking NAT-T: %d and %d",
				nat_traversal_enabled,
				md->quirks.nat_traversal_vid));

	if (md->quirks.nat_traversal_vid && nat_traversal_enabled) {
		int np = --numvidtosend ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;
		/* reply if NAT-Traversal draft is supported */
		st->hidden_variables.st_nat_traversal =
			LELEM(nat_traversal_vid_to_method(
					md->
					quirks.
					nat_traversal_vid));
		if ((st->hidden_variables.st_nat_traversal) &&
			(!out_vid(np, &
				md->rbody, md->quirks.nat_traversal_vid)))
			return STF_INTERNAL_ERROR;
	}

	/* Ensure our 'next payload' types sync'ed up */
	passert(numvidtosend == 0);

	close_message(&md->rbody, st);

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

static stf_status main_inR1_outI2_tail(struct pluto_crypto_req_cont *pcrc,
				struct pluto_crypto_req *r);

static void main_inR1_outI2_continue(struct pluto_crypto_req_cont *pcrc,
				struct pluto_crypto_req *r,
				err_t ugh)
{
	struct ke_continuation *ke = (struct ke_continuation *)pcrc;
	struct msg_digest *md = ke->md;
	struct state *const st = md->st;
	stf_status e;

	DBG(DBG_CONTROLMORE,
		DBG_log("main inR1_outI2: calculated ke+nonce, sending I2"));

	if (st == NULL) {
		loglog(RC_LOG_SERIOUS,
			"%s: Request was disconnected from state",
			__FUNCTION__);
		if (ke->md)
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

	e = main_inR1_outI2_tail(pcrc, r);

	if (ke->md != NULL) {
		complete_v1_state_transition(&ke->md, e);
		if (ke->md)
			release_md(ke->md);
	}

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

	DBG(DBG_NATT, DBG_log("sender checking NAT-T: %d and %d",
				nat_traversal_enabled,
				md->quirks.nat_traversal_vid));

	if (nat_traversal_enabled && md->quirks.nat_traversal_vid) {
		st->hidden_variables.st_nat_traversal =
			LELEM(nat_traversal_vid_to_method(
					md->
					quirks.
					nat_traversal_vid));
		libreswan_log("enabling possible NAT-traversal with method %s",
			enum_name(&natt_method_names,
				nat_traversal_vid_to_method(md->quirks.
							nat_traversal_vid)));
	}

	{
		struct ke_continuation *ke = alloc_thing(
			struct ke_continuation,
			"outI2 KE");
		ke->md = md;

		passert(!st->st_sec_in_use);
		pcrc_init(&ke->ke_pcrc);
		ke->ke_pcrc.pcrc_func = main_inR1_outI2_continue;
		set_suspended(st, md);
		return build_ke(&ke->ke_pcrc, st, st->st_oakley.group,
				st->st_import);
	}
}

/*
 * package up the calculate KE value, and emit it as a KE payload.
 * used by IKEv1: main, aggressive, and quick (in PFS mode).
 */
bool justship_KE(chunk_t *g,
		pb_stream *outs, u_int8_t np)
{
	return out_generic_chunk(np, &isakmp_keyex_desc, outs, *g,
				"keyex value");
}

bool ship_KE(struct state *st,
	struct pluto_crypto_req *r,
	chunk_t *g,
	pb_stream *outs, u_int8_t np)
{
	unpack_KE(st, r, g);
	return justship_KE(g, outs, np);
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
static stf_status main_inR1_outI2_tail(struct pluto_crypto_req_cont *pcrc,
				struct pluto_crypto_req *r)
{
	struct ke_continuation *ke = (struct ke_continuation *)pcrc;
	struct msg_digest *md = ke->md;
	struct state *const st = md->st;

	/* Build output packet HDR;KE;Ni */
	init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
		"reply packet");

	/*
	 * HDR out.
	 * We can't leave this to comm_handle() because the isa_np
	 * depends on the type of Auth (eventually).
	 */
	echo_hdr(md, FALSE, ISAKMP_NEXT_KE);

	/* KE out */
	if (!ship_KE(st, r, &st->st_gi,
			&md->rbody, ISAKMP_NEXT_NONCE))
		return STF_INTERNAL_ERROR;

	/* Ni out */
	if (!ship_nonce(&st->st_ni, r, &md->rbody,
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

		if (!out_generic(ISAKMP_NEXT_NONE, &isakmp_vendor_id_desc,
					&md->rbody,
					&vid_pbs))
			return STF_INTERNAL_ERROR;

		if (!out_zero(1500 /*MTU?*/, &vid_pbs, "Filler VID"))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&vid_pbs);
	}

	DBG(DBG_NATT, DBG_log("NAT-T checking st_nat_traversal"));
	if (st->hidden_variables.st_nat_traversal) {
		DBG(DBG_NATT,
			DBG_log("NAT-T found (implies NAT_T_WITH_NATD)"));
		if (!nat_traversal_add_natd(ISAKMP_NEXT_NONE, &md->rbody, md))
			return STF_INTERNAL_ERROR;
	}

	/* finish message */
	close_message(&md->rbody, st);

	/* Reinsert the state, using the responder cookie we just received */
	unhash_state(st);
	memcpy(st->st_rcookie, md->hdr.isa_rcookie, COOKIE_SIZE);
	insert_state(st); /* needs cookies, connection, and msgid (0) */

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
 * 	    [,<<Cert-I_b>Ke_i]
 *	    --> HDR, <Nr_b>PubKey_i, <KE_b>Ke_r, <IDr1_b>Ke_r
 */
static stf_status main_inI2_outR2_tail(struct pluto_crypto_req_cont *pcrc,
				struct pluto_crypto_req *r);

static void main_inI2_outR2_continue(struct pluto_crypto_req_cont *pcrc,
				struct pluto_crypto_req *r,
				err_t ugh)
{
	struct ke_continuation *ke = (struct ke_continuation *)pcrc;
	struct msg_digest *md = ke->md;
	struct state *const st = md->st;
	stf_status e;

	DBG(DBG_CONTROLMORE,
		DBG_log("main inI2_outR2: calculated ke+nonce, sending R2"));

	if (st == NULL) {
		loglog(RC_LOG_SERIOUS,
			"%s: Request was disconnected from state",
			__FUNCTION__);
		if (ke->md)
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
	e = main_inI2_outR2_tail(pcrc, r);

	if (ke->md != NULL) {
		complete_v1_state_transition(&ke->md, e);
		if (ke->md)
			release_md(ke->md);
	}
	reset_cur_state();
}

stf_status main_inI2_outR2(struct msg_digest *md)
{
	struct state *const st = md->st;
	pb_stream *keyex_pbs = &md->chain[ISAKMP_NEXT_KE]->pbs;

	/* KE in */
	RETURN_STF_FAILURE(accept_KE(&st->st_gi, "Gi", st->st_oakley.group,
						keyex_pbs));

	/* Ni in */
	RETURN_STF_FAILURE(accept_v1_nonce(md, &st->st_ni, "Ni"));

	/* decode certificate requests */
	decode_cr(md, &st->st_connection->requested_ca);

	if (st->st_connection->requested_ca != NULL)
		st->hidden_variables.st_got_certrequest = TRUE;

	DBG(DBG_NATT,
		DBG_log("inI2: checking NAT-T: %d and %d",
			nat_traversal_enabled,
			st->hidden_variables.st_nat_traversal));

	if (st->hidden_variables.st_nat_traversal) {
		DBG(DBG_NATT, DBG_log(" NAT_T_WITH_NATD detected"));
		nat_traversal_natd_lookup(md);
	}
	if (st->hidden_variables.st_nat_traversal) {
		nat_traversal_show_result(
			st->hidden_variables.st_nat_traversal,
			md->sender_port);
	}
	if (st->hidden_variables.st_nat_traversal & NAT_T_WITH_KA) {
		DBG(DBG_NATT, DBG_log(" NAT_T_WITH_KA detected"));
		nat_traversal_new_ka_event();
	}

	{
		struct ke_continuation *ke = alloc_thing(
			struct ke_continuation,
			"inI2_outR2 KE");

		ke->md = md;
		set_suspended(st, md);

		passert(!st->st_sec_in_use);
		pcrc_init(&ke->ke_pcrc);
		ke->ke_pcrc.pcrc_func = main_inI2_outR2_continue;
		return build_ke(&ke->ke_pcrc, st,
				st->st_oakley.group, st->st_import);
	}
}

static void main_inI2_outR2_calcdone(struct pluto_crypto_req_cont *pcrc,
				struct pluto_crypto_req *r,
				err_t ugh)
{
	struct dh_continuation *dh = (struct dh_continuation *)pcrc;
	struct state *st;

	DBG(DBG_CONTROLMORE,
		DBG_log("main inI2_outR2: calculated DH finished"));

	st = state_with_serialno(dh->serialno);
	if (st == NULL) {
		libreswan_log("state %ld disappeared during crypto\n",
			dh->serialno);
		return;
	}

	set_cur_state(st);
	if (ugh) {
		loglog(RC_LOG_SERIOUS, "DH crypto failed: %s\n", ugh);
		return;
	}

	finish_dh_secretiv(st, r);

	st->hidden_variables.st_skeyid_calculated = TRUE;
	update_iv(st);

	/*
	 * if there was a packet received while we were calculating, then
	 * process it now.
	 */
	if (st->st_suspended_md != NULL) {
		struct msg_digest *md = st->st_suspended_md;

		set_suspended(st, NULL);
		process_packet_tail(&md);
		if (md != NULL)
			release_md(md);
	}
	reset_cur_state();
	return;
}

stf_status main_inI2_outR2_tail(struct pluto_crypto_req_cont *pcrc,
				struct pluto_crypto_req *r)
{
	struct ke_continuation *ke = (struct ke_continuation *)pcrc;
	struct msg_digest *md = ke->md;
	struct state *st = md->st;

	/* send CR if auth is RSA and no preloaded RSA public key exists*/
	bool send_cr = FALSE;

	/* Build output packet HDR;KE;Nr */

	send_cr = (st->st_oakley.auth == OAKLEY_RSA_SIG) &&
		!has_preloaded_public_key(st) &&
		st->st_connection->spd.that.ca.ptr != NULL;

	/* HDR out */
	echo_hdr(md, FALSE, ISAKMP_NEXT_KE);

	/* KE out */
	if (!ship_KE(st, r, &st->st_gr,
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
		if (!ship_nonce(&st->st_nr, r,
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

			if (!out_generic((send_cr) ? ISAKMP_NEXT_CR :
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
			if (!build_and_ship_CR(CERT_X509_SIGNATURE,
						st->st_connection->spd.that.ca,
						&md->rbody, ISAKMP_NEXT_NONE))
				return STF_INTERNAL_ERROR;
		} else {
			generalName_t *ca = NULL;

			if (collect_rw_ca_candidates(md, &ca)) {
				generalName_t *gn;

				for (gn = ca; gn != NULL; gn = gn->next) {
					if (!build_and_ship_CR(
							CERT_X509_SIGNATURE,
							gn->name,
							&md->rbody,
							gn->next ==
							NULL ?
							ISAKMP_NEXT_NONE :
							ISAKMP_NEXT_CR))
						return STF_INTERNAL_ERROR;
				}
				free_generalNames(ca, FALSE);
			} else {
				if (!build_and_ship_CR(CERT_X509_SIGNATURE,
							empty_chunk,
							&md->rbody,
							ISAKMP_NEXT_NONE))
					return STF_INTERNAL_ERROR;
			}
		}
	}

	if (st->hidden_variables.st_nat_traversal) {
		if (!nat_traversal_add_natd(ISAKMP_NEXT_NONE, &md->rbody, md))
			return STF_INTERNAL_ERROR;
	}

	/* finish message */
	close_message(&md->rbody, st);

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
	 * actually just doing work in the background.
	 *
	 */
	{
		/*
		 * Looks like we missed perform_dh() declared at
		 * programs/pluto/pluto_crypt.h as external and implemented
		 * nowhere.
		 * Following code regarding dh_continuation allocation seems
		 * useless as it's never used. At least, we should free it.
		 */
		struct dh_continuation *dh = alloc_thing(
			struct dh_continuation,
			"main_inI2_outR2_tail");
		stf_status e;

		dh->md = NULL;
		dh->serialno = st->st_serialno;
		pcrc_init(&dh->dh_pcrc);
		dh->dh_pcrc.pcrc_func = main_inI2_outR2_calcdone;
		passert(st->st_suspended_md == NULL);

		DBG(DBG_CONTROLMORE,
			DBG_log("main inI2_outR2: starting async DH "
				"calculation (group=%d)",
				st->st_oakley.group->group));

		e = start_dh_secretiv(&dh->dh_pcrc, st,
				st->st_import,
				RESPONDER,
				st->st_oakley.group->group);

		DBG(DBG_CONTROLMORE,
			DBG_log("started dh_secretiv, returned: stf=%s\n",
				enum_name(&stfstatus_name, e)));

		if (e == STF_FAIL) {
			loglog(RC_LOG_SERIOUS,
				"failed to start async DH calculation, "
				"stf=%s\n",
				enum_name(&stfstatus_name, e));
			return e;
		}

		/* we are calculating in the background, so it doesn't count */
		if (e == STF_SUSPEND)
			st->st_calculating = FALSE;
	}
	return STF_OK;
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
		if (auth == OAKLEY_PRESHARED_KEY) {
			DBG(DBG_CONTROL,
				DBG_log("I did not send a certificate "
					"because digital signatures are not "
					"being used. (PSK)"));
		} else if (certtype == CERT_NONE) {
			DBG(DBG_CONTROL,
				DBG_log("I did not send a certificate because "
					"I do not have one."));
		} else if (policy == cert_sendifasked) {
			DBG(DBG_CONTROL,
				DBG_log("I did not send my certificate "
					"because I was not asked to."));
		}
	}
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
	bool initial_contact = FALSE;
	generalName_t *requested_ca = NULL;
	cert_t mycert = st->st_connection->spd.this.cert;

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
			st->st_connection->spd.this.sendcert ==
			cert_alwayssend ||
			st->st_connection->spd.this.sendcert ==
			cert_forcedtype);

	doi_log_cert_thinking(md,
			st->st_oakley.auth,
			mycert.type,
			st->st_connection->spd.this.sendcert,
			st->hidden_variables.st_got_certrequest,
			send_cert);

	/*
	 * send certificate request, if we don't have a preloaded RSA
	 * public key
	 */
	send_cr = send_cert && !has_preloaded_public_key(st);

	DBG(DBG_CONTROL,
		DBG_log(" I am %ssending a certificate request",
			send_cr ? "" : "not "));

	/*
	 * free collected certificate requests since as initiator
	 * we don't heed them anyway
	 */
	free_generalNames(requested_ca, TRUE);

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

	if (st->hidden_variables.st_nat_traversal)
		nat_traversal_natd_lookup(md);
	if (st->hidden_variables.st_nat_traversal) {
		nat_traversal_show_result(
			st->hidden_variables.st_nat_traversal,
			md->sender_port);
	}
	if (st->hidden_variables.st_nat_traversal & NAT_T_WITH_KA)
		nat_traversal_new_ka_event();

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

	/* HASH_I or SIG_I out */
	{
		u_char hash_val[MAX_DIGEST_LEN];
		size_t hash_len = main_mode_hash(st, hash_val, TRUE, &id_pbs);

		if (auth_payload == ISAKMP_NEXT_HASH) {
			/* HASH_I out */
			if (!out_generic_raw(initial_contact ? ISAKMP_NEXT_N :
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
					"unable to locate my private key "
					"for RSA Signature");
				return STF_FAIL + AUTHENTICATION_FAILED;
			}

			if (!out_generic_raw(initial_contact ? ISAKMP_NEXT_N :
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

		libreswan_log("I am sending INITIAL_CONTACT");

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
		libreswan_log("Not sending INITIAL_CONTACT");
	}

	/* encrypt message, except for fixed part of header */

	/* st_new_iv was computed by generate_skeyids_iv (??? DOESN'T EXIST) */
	if (!encrypt_message(&md->rbody, st))
		return STF_INTERNAL_ERROR; /* ??? we may be partly committed */

	return STF_OK;
}

static void main_inR2_outI3_cryptotail(struct pluto_crypto_req_cont *pcrc,
				struct pluto_crypto_req *r,
				err_t ugh)
{
	struct dh_continuation *dh = (struct dh_continuation *)pcrc;
	struct msg_digest *md = dh->md;
	struct state *const st = md->st;
	stf_status e;

	DBG(DBG_CONTROLMORE,
		DBG_log("main inR2_outI3: calculated DH, sending R1"));

	if (st == NULL) {
		loglog(RC_LOG_SERIOUS,
			"%s: Request was disconnected from state",
			__FUNCTION__);
		if (dh->md)
			release_md(dh->md);
		return;
	}

	passert(cur_state == NULL);
	passert(st != NULL);

	passert(st->st_suspended_md == dh->md);
	set_suspended(st, NULL); /* no longer connected or suspended */

	set_cur_state(st);
	st->st_calculating = FALSE;

	if (ugh) {
		loglog(RC_LOG_SERIOUS, "failed in DH exponentiation: %s", ugh);
		e = STF_FATAL;
	} else {
		e = main_inR2_outI3_continue(md, r);
	}

	if (dh->md != NULL) {
		complete_v1_state_transition(&dh->md, e);
		if (dh->md)
			release_md(dh->md);
	}
	reset_cur_state();
}

stf_status main_inR2_outI3(struct msg_digest *md)
{
	struct dh_continuation *dh;
	pb_stream *const keyex_pbs = &md->chain[ISAKMP_NEXT_KE]->pbs;
	struct state *const st = md->st;

	/* KE in */
	RETURN_STF_FAILURE(accept_KE(&st->st_gr, "Gr",
						st->st_oakley.group,
						keyex_pbs));

	/* Nr in */
	RETURN_STF_FAILURE(accept_v1_nonce(md, &st->st_nr, "Nr"));

	dh = alloc_thing(struct dh_continuation, "aggr outR1 DH");
	if (!dh)
		return STF_FATAL;

	dh->md = md;
	set_suspended(st, md);
	pcrc_init(&dh->dh_pcrc);
	dh->dh_pcrc.pcrc_func = main_inR2_outI3_cryptotail;
	return start_dh_secretiv(&dh->dh_pcrc, st,
				st->st_import,
				INITIATOR,
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
	loglog(RC_LOG_SERIOUS, "no RSA public key known for '%s'"
		"; DNS search for KEY failed (%s)", id_buf, ugh);
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
			cont_fn_t cont_fn, /* continuation function */
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
	if (!aggrmode && !decode_peer_id(md, initiator, FALSE))
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
				"received Hash Payload does not match "
				"computed value");
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
			enum key_oppo_step step_done = kc ==
				NULL ? kos_null : kc->
				step;
			err_t ugh;

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
				ugh = start_adns_query(
					&st->st_connection->spd.that.id,
					/* SG itself */
					&st->st_connection->spd.that.id,
					ns_t_txt,
					cont_fn,
					&nkc->ac);
				break;

#ifdef USE_KEYRR
			case kos_his_txt:
				/* second try: look for the KEY records */
				nkc->step = kos_his_key;
				ugh = start_adns_query(
					&st->st_connection->spd.that.id,
					NULL, /* no sgw for KEY */
					ns_t_key,
					cont_fn,
					&nkc->ac);
				break;
#endif /* USE_KEYRR */

			default:
				bad_case(step_done);
			}

			if (ugh != NULL) {
				report_key_dns_failure(
					&st->st_connection->spd.that.id, ugh);
				set_suspended(st, NULL);
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
		set_suspended(st, NULL); /* no longer connected or suspended */
		cur_state = st;

		/* cancel any DNS event, since we got an anwer */
		delete_event(st);

		if (!kc->failure_ok && ugh != NULL) {
			report_key_dns_failure(&st->st_connection->spd.that.id,
					ugh);
			r = STF_FAIL + INVALID_KEY_INFORMATION;
		} else {

#ifdef USE_KEYRR
			passert(kc->step == kos_his_txt || kc->step ==
				kos_his_key);
#else
			passert(kc->step == kos_his_txt);
#endif
			/* record previous error in case we need it */
			kc->last_ugh = ugh;
			r = (*tail)(kc->md, kc);
		}
		complete_v1_state_transition(&kc->md, r);
	}
	if (kc->md != NULL)
		release_md(kc->md);
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
	return main_inI3_outR3_tail(md, NULL);
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
	bool send_cert;
	unsigned int np;

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
		mycert.type != CERT_NONE &&
		((st->st_connection->spd.this.sendcert ==
			cert_sendifasked &&
			st->hidden_variables.st_got_certrequest) ||
			st->st_connection->spd.this.sendcert ==
			cert_alwayssend);

	doi_log_cert_thinking(md,
			st->st_oakley.auth,
			mycert.type,
			st->st_connection->spd.this.sendcert,
			st->hidden_variables.st_got_certrequest,
			send_cert);

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
	echo_hdr(md, TRUE, ISAKMP_NEXT_ID);

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
		pb_stream cert_pbs;

		struct isakmp_cert cert_hd;
		cert_hd.isacert_np = ISAKMP_NEXT_SIG;
		cert_hd.isacert_type = mycert.type;

		libreswan_log("I am sending my cert");

		if (!out_struct(&cert_hd, &isakmp_ipsec_certificate_desc,
					&md->rbody, &cert_pbs))
			return STF_INTERNAL_ERROR;

		if (!out_chunk(get_mycert(mycert), &cert_pbs, "CERT"))
			return STF_INTERNAL_ERROR;

		close_output_pbs(&cert_pbs);
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
			if (!out_generic_raw(np, &isakmp_hash_desc, &md->rbody,
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
					"unable to locate my private key "
					"for RSA Signature");
				return STF_FAIL + AUTHENTICATION_FAILED;
			}

			if (!out_generic_raw(np, &isakmp_signature_desc,
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

	st->st_ph1_iv_len = st->st_new_iv_len;
	set_ph1_iv(st, st->st_new_iv);

	/*
	 * It seems as per Cisco implementation, XAUTH and MODECFG
	 * are not supposed to be performed again during rekey
	 */

	if ( st->st_connection->remotepeertype == CISCO &&
		st->st_connection->newest_isakmp_sa != SOS_NOBODY &&
		st->st_connection->spd.this.xauth_client) {
		DBG(DBG_CONTROL,
			DBG_log("Skipping XAUTH for rekey for Cisco Peer "
				"compatibility."));
		st->hidden_variables.st_xauth_client_done = TRUE;
		st->st_oakley.doing_xauth = FALSE;

		if (st->st_connection->spd.this.modecfg_client) {
			DBG(DBG_CONTROL,
				DBG_log("Skipping ModeCFG for rekey for "
					"Cisco Peer compatibility."));
			st->hidden_variables.st_modecfg_vars_set = TRUE;
			st->hidden_variables.st_modecfg_started = TRUE;
		}
	}

	ISAKMP_SA_established(st->st_connection, st->st_serialno);

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

	/*
	 * Done input
	 *
	 * save last IV from phase 1 so it can be restored later so anything
	 * between the end of phase 1 and the start of phase 2 ie mode config
	 * payloads etc will not loose our IV
	 */
	memcpy(st->st_ph1_iv, st->st_new_iv, st->st_new_iv_len);
	st->st_ph1_iv_len = st->st_new_iv_len;

	/*
	 * It seems as per Cisco implementation, XAUTH and MODECFG
	 * are not supposed to be performed again during rekey
	 */
	if ( st->st_connection->remotepeertype == CISCO &&
		st->st_connection->newest_isakmp_sa != SOS_NOBODY &&
		st->st_connection->spd.this.xauth_client) {
		DBG(DBG_CONTROL,
			DBG_log("Skipping XAUTH for rekey for Cisco Peer "
				"compatibility."));
		st->hidden_variables.st_xauth_client_done = TRUE;
		st->st_oakley.doing_xauth = FALSE;

		if (st->st_connection->spd.this.modecfg_client) {
			DBG(DBG_CONTROL,
				DBG_log("Skipping ModeCFG for rekey for Cisco "
					"Peer compatibility."));
			st->hidden_variables.st_modecfg_vars_set = TRUE;
			st->hidden_variables.st_modecfg_started = TRUE;
		}
	}

	ISAKMP_SA_established(st->st_connection, st->st_serialno);

	passert((st->st_policy & POLICY_PFS) == 0 || st->st_pfs_group !=
		NULL );

	st->st_ph1_iv_len = st->st_new_iv_len;
	set_ph1_iv(st, st->st_new_iv);

	/*
	 * save last IV from phase 1 so it can be restored later so anything
	 * between the end of phase 1 and the start of phase 2 ie mode config
	 * payloads etc will not loose our IV
	 */
	memcpy(st->st_ph1_iv, st->st_new_iv, st->st_new_iv_len);
	st->st_ph1_iv_len = st->st_new_iv_len;

	update_iv(st); /* finalize our Phase 1 IV */

	if (md->ikev2) {
		/*
		 * We cannot use POLICY_IKEV2_ALLOW here, since this will
		 * cause two IKEv2 capable but not ikev2= configured endpoints
		 * to falsely detect a bid down attack.
		 * Also, only the side that proposed IKEv2 can figure out there
		 * was a bid down attack to begin with. The side that did not propose
		 * cannot distinguish attack from regular ikev1 operation.
		 * if(st->st_connection->policy & POLICY_IKEV2_ALLOW) {
		 */
		if (st->st_connection->policy & POLICY_IKEV2_PROPOSE) {
			libreswan_log(
				"Bid-down to IKEv1 attack detected, "
				"attempting to rekey connection with IKEv2");
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
	u_char old_new_iv[MAX_DIGEST_LEN];
	u_char old_iv[MAX_DIGEST_LEN];
	u_char
	*r_hashval, /* where in reply to jam hash value */
	*r_hash_start; /* start of what is to be hashed */

	msgid = generate_msgid(st);

	zero(reply_buffer);
	init_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
		"ISAKMP notify");

	/* HDR* */
	{
		struct isakmp_hdr hdr;
		hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
			ISAKMP_MINOR_VERSION;
		hdr.isa_np = ISAKMP_NEXT_HASH;
		hdr.isa_xchg = ISAKMP_XCHG_INFO;
		hdr.isa_msgid = msgid;
		hdr.isa_flags = ISAKMP_FLAG_ENCRYPTION;
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
		hmac_init_chunk(&ctx, st->st_oakley.prf_hasher,
				st->st_skeyid_a);
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

	save_iv(st, old_iv);
	save_new_iv(st, old_new_iv);

	init_phase2_iv(st, &msgid);
	if (!encrypt_message(&rbody, st))
		return STF_INTERNAL_ERROR;

	{
		chunk_t saved_tpacket = st->st_tpacket;

		setchunk(st->st_tpacket, reply_stream.start,
			pbs_offset(&reply_stream));
		send_ike_msg(st, "ISAKMP notify");
		st->st_tpacket = saved_tpacket;
	}
	/* get back old IV for this state */
	set_iv(st, old_iv);
	set_new_iv(st, old_new_iv);

	return STF_IGNORE;
}

/*
 * Send a notification to the peer. We could decide
 * whether to send the notification, based on the type and the
 * destination, if we care to.
 */
static void send_notification(struct state *sndst, notification_t type,
			struct state *encst,
			msgid_t msgid, u_char *icookie, u_char *rcookie,
			u_char protoid)
{
	u_char buffer[1024];
	pb_stream pbs, r_hdr_pbs;
	u_char *r_hashval, *r_hash_start;
	static time_t last_malformed;
	time_t n = time(NULL);
	struct isakmp_hdr hdr; /* keep it around for TPM */

	r_hashval = NULL;
	r_hash_start = NULL;

	passert((sndst) && (sndst->st_connection));

	switch (type) {
	case PAYLOAD_MALFORMED:
		/* only send one per second. */
		if (n == last_malformed)
			return;

		last_malformed = n;
		sndst->hidden_variables.st_malformed_sent++;
		if (sndst->hidden_variables.st_malformed_sent >
			MAXIMUM_MALFORMED_NOTIFY) {
			libreswan_log(
				"too many (%d) malformed payloads. Deleting "
				"state",
				sndst->hidden_variables.st_malformed_sent);
			delete_state(sndst);
			return;
		}

		libreswan_DBG_dump("payload malformed after possible IV", sndst->st_iv,
				sndst->st_iv_len);

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

	libreswan_log("sending %snotification %s to %s:%u",
		encst ? "encrypted " : "",
		enum_name(&ikev1_notify_names, type),
		ip_str(&sndst->st_remoteaddr),
		sndst->st_remoteport);

	zero(buffer);
	init_pbs(&pbs, buffer, sizeof(buffer), "notification msg");

	/* HDR* */
	{
		hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
			ISAKMP_MINOR_VERSION;
		hdr.isa_np = encst ? ISAKMP_NEXT_HASH : ISAKMP_NEXT_N;
		hdr.isa_xchg = ISAKMP_XCHG_INFO;
		hdr.isa_msgid = msgid;
		hdr.isa_flags = encst ? ISAKMP_FLAG_ENCRYPTION : 0;
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
		if (!out_generic(ISAKMP_NEXT_N, &isakmp_hash_desc, &r_hdr_pbs,
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
				"failed to build notification in send_"
				"notification\n");
			return;
		}

		close_output_pbs(&not_pbs);
	}

	/* calculate hash value and patch into Hash Payload */
	if (encst) {
		struct hmac_ctx ctx;
		hmac_init_chunk(&ctx, encst->st_oakley.prf_hasher,
				encst->st_skeyid_a);
		hmac_update(&ctx, (u_char *) &msgid, sizeof(msgid_t));
		hmac_update(&ctx, r_hash_start, r_hdr_pbs.cur - r_hash_start);
		hmac_final(r_hashval, &ctx);

		DBG(DBG_CRYPT, {
				DBG_log("HASH(1) computed:");
				DBG_dump("", r_hashval, ctx.hmac_digest_len);
			});
	}

	/* Encrypt message (preserve st_iv) */
	if (encst) {
		u_char old_iv[MAX_DIGEST_LEN];
		u_int old_iv_len = encst->st_iv_len;

		if (old_iv_len > MAX_DIGEST_LEN)
			impossible();
		memcpy(old_iv, encst->st_iv, old_iv_len);

		if (!IS_ISAKMP_SA_ESTABLISHED(encst->st_state)) {
			if (encst->st_new_iv_len > MAX_DIGEST_LEN)
				impossible();
			memcpy(encst->st_iv, encst->st_new_iv,
				encst->st_new_iv_len);
			encst->st_iv_len = encst->st_new_iv_len;
		}
		init_phase2_iv(encst, &msgid);
		if (!encrypt_message(&r_hdr_pbs, encst))
			impossible();

		/* restore preserved st_iv*/
		memcpy(encst->st_iv, old_iv, old_iv_len);
		encst->st_iv_len = old_iv_len;
	} else {
		close_output_pbs(&r_hdr_pbs);
	}

	/* Send packet (preserve st_tpacket) */
	{
		chunk_t saved_tpacket = sndst->st_tpacket;

		setchunk(sndst->st_tpacket, pbs.start, pbs_offset(&pbs));
		send_ike_msg(sndst, "notification packet");
		sndst->st_tpacket = saved_tpacket;
	}
}

void send_notification_from_state(struct state *st, enum state_kind from_state,
				notification_t type)
{
	struct state *p1st;

	passert(st);

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
		send_notification(st, type, NULL, MAINMODE_MSGID,
				st->st_icookie, st->st_rcookie,
				PROTO_ISAKMP);
	}
}

void send_notification_from_md(struct msg_digest *md, notification_t type)
{
	/*
	 * Create a dummy state to be able to use send_ike_msg in
	 * send_notification
	 *
	 * we need to set:
	 *   st_connection->that.host_addr
	 *   st_connection->that.host_port
	 *   st_connection->interface
	 */
	struct state st;
	struct connection cnx;

	passert(md);

	zero(&st);
	zero(&cnx);
	st.st_connection = &cnx;
	st.st_remoteaddr = md->sender;
	st.st_remoteport = md->sender_port;
	st.st_localaddr = md->iface->ip_addr;
	st.st_localport = md->iface->port;
	cnx.interface = md->iface;
	st.st_interface = md->iface;

	send_notification(&st, type, NULL, 0,
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
void ikev1_delete_out(struct state *st)
{
	pb_stream reply_pbs;
	pb_stream r_hdr_pbs;
	msgid_t msgid;
	u_char buffer[8192];
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
			return;
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
	}
	/* or ISAKMP SA's... */
	else if (IS_ISAKMP_SA_ESTABLISHED(st->st_state)) {
		p1st = st;
		isakmp_sa = TRUE;
	} else {
		return; /* nothing to do */
	}

	msgid = generate_msgid(p1st);

	zero(buffer);
	init_pbs(&reply_pbs, buffer, sizeof(buffer), "delete msg");

	/* HDR* */
	{
		hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
			ISAKMP_MINOR_VERSION;
		hdr.isa_np = ISAKMP_NEXT_HASH;
		hdr.isa_xchg = ISAKMP_XCHG_INFO;
		hdr.isa_msgid = msgid;
		hdr.isa_flags = ISAKMP_FLAG_ENCRYPTION;
		memcpy(hdr.isa_icookie, p1st->st_icookie, COOKIE_SIZE);
		memcpy(hdr.isa_rcookie, p1st->st_rcookie, COOKIE_SIZE);
		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply_pbs,
					&r_hdr_pbs))
			impossible();
	}

	/* HASH -- value to be filled later */
	{
		pb_stream hash_pbs;

		if (!out_generic(ISAKMP_NEXT_D, &isakmp_hash_desc, &r_hdr_pbs,
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
		hmac_init_chunk(&ctx, p1st->st_oakley.prf_hasher,
				p1st->st_skeyid_a);
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
		chunk_t saved_tpacket = p1st->st_tpacket;

		save_iv(p1st, old_iv);
		init_phase2_iv(p1st, &msgid);

		if (!encrypt_message(&r_hdr_pbs, p1st))
			impossible();

		setchunk(p1st->st_tpacket, reply_pbs.start,
			 pbs_offset(&reply_pbs));
		send_ike_msg(p1st, "delete notify");
		p1st->st_tpacket = saved_tpacket;

		/* get back old IV for this state */
		set_iv(p1st, old_iv);
	}
}

/*
 * Accept a Delete SA notification, and process it if valid.
 *
 * @param st State structure
 * @param md Message Digest
 * @param p Payload digest
 */
void accept_delete(struct state *st, struct msg_digest *md,
		struct payload_digest *p)
{
	struct isakmp_delete *d = &(p->payload.delete);
	size_t sizespi;
	int i;

	/* We only listen to encrypted notifications */
	if (!md->encrypted) {
		loglog(RC_LOG_SERIOUS,
			"ignoring Delete SA payload: not encrypted");
		return;
	}

	/* If there is no SA related to this request, but it was encrypted */
	if (!IS_ISAKMP_SA_ESTABLISHED(st->st_state)) {
		/* can't happen (if msg is encrypt), but just to be sure */
		loglog(RC_LOG_SERIOUS, "ignoring Delete SA payload: "
			"ISAKMP SA not established");
		return;
	}

	if (d->isad_nospi == 0) {
		loglog(RC_LOG_SERIOUS, "ignoring Delete SA payload: no SPI");
		return;
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
		return;

	default:
		loglog(RC_LOG_SERIOUS,
			"ignoring Delete SA payload: unknown Protocol ID (%s)",
			enum_show(&protocol_names, d->isad_protoid));
		return;
	}

	if (d->isad_spisize != sizespi) {
		loglog(RC_LOG_SERIOUS,
			"ignoring Delete SA payload: bad SPI size (%d) for %s",
			d->isad_spisize,
			enum_show(&protocol_names, d->isad_protoid));
		return;
	}

	if (pbs_left(&p->pbs) != d->isad_nospi * sizespi) {
		loglog(RC_LOG_SERIOUS,
			"ignoring Delete SA payload: invalid payload size");
		return;
	}

	for (i = 0; i < d->isad_nospi; i++) {
		u_char *spi = p->pbs.cur + (i * sizespi);

		if (d->isad_protoid == PROTO_ISAKMP) {
			/*
			 * ISAKMP
			 */
			struct state *dst = find_state_ikev1(spi, /* iCookie */
							/* rCookie */
							spi + COOKIE_SIZE,
							MAINMODE_MSGID);

			if (dst == NULL) {
				loglog(RC_LOG_SERIOUS, "ignoring Delete SA "
					"payload: ISAKMP SA not found (maybe "
					"expired)");
			} else if (!same_peer_ids(st->st_connection,
							dst->st_connection,
							NULL)) {
				/*
				 * we've not authenticated the relevant
				 * identities
				 */
				loglog(RC_LOG_SERIOUS, "ignoring Delete SA "
					"payload: ISAKMP SA used to convey "
					"Delete has different IDs from ISAKMP "
					"SA it deletes");
			} else {
				struct connection *oldc;

				oldc = cur_connection;
				set_cur_connection(dst->st_connection);

				if (nat_traversal_enabled)
					nat_traversal_change_port_lookup(md,
									dst);

				loglog(RC_LOG_SERIOUS, "received Delete SA "
					"payload: deleting ISAKMP State #%lu",
					dst->st_serialno);
				delete_state(dst);
				set_cur_connection(oldc);
			}
		} else {
			/*
			 * IPSEC (ESP/AH)
			 */
			bool bogus;
			struct state *dst = find_phase2_state_to_delete(st,
							d->isad_protoid,
							*(ipsec_spi_t*)
							spi, /* network order */
							&bogus);

			if (dst == NULL) {
				loglog(RC_LOG_SERIOUS,
					"ignoring Delete SA payload: %s "
					"SA(0x%08lx) not found (%s)",
					enum_show(&protocol_names,
						d->isad_protoid),
					(unsigned long)ntohl((unsigned long)
						*(ipsec_spi_t *)spi),
					bogus ? "our SPI - bogus implementation" : "maybe expired");
			} else {
				struct connection *rc = dst->st_connection;
				struct connection *oldc;

				oldc = cur_connection;
				set_cur_connection(rc);

				if (nat_traversal_enabled)
					nat_traversal_change_port_lookup(md,
									dst);

				if (rc->newest_ipsec_sa == dst->st_serialno &&
					(rc->policy & POLICY_UP)) {
					/*
					 * Last IPSec SA for a permanent
					 * connection that we have initiated.
					 * Replace it in a few seconds.
					 *
					 * Useful if the other peer is
					 * rebooting.
					 */
#define DELETE_SA_DELAY EVENT_RETRANSMIT_DELAY_0
					if (dst->st_event != NULL &&
						dst->st_event->ev_type ==
						EVENT_SA_REPLACE &&
						dst->st_event->ev_time <=
						DELETE_SA_DELAY + now()) {
						/*
						 * Patch from Angus Lees to
						 * ignore retransmited
						 * Delete SA.
						 */
						loglog(RC_LOG_SERIOUS,
							"received Delete SA "
							"payload: already "
							"replacing IPSEC "
							"State #%lu in %d "
							"seconds",
							dst->st_serialno,
							(int)(dst->st_event->
								ev_time -
								now()));
					} else {
						loglog(RC_LOG_SERIOUS,
							"received Delete SA "
							"payload: replace "
							"IPSEC State #%lu "
							"in %d seconds",
							dst->st_serialno,
							DELETE_SA_DELAY);
						dst->st_margin =
							DELETE_SA_DELAY;
						delete_event(dst);
						event_schedule(
							EVENT_SA_REPLACE,
							DELETE_SA_DELAY, dst);
					}
				} else {
					loglog(RC_LOG_SERIOUS,
						"received Delete SA(0x%08lx) "
						"payload: deleting IPSEC "
						"State #%lu",
						(unsigned long)ntohl(
							(unsigned long)*(
								ipsec_spi_t *)
							spi),
						dst->st_serialno);
					delete_state(dst);
				}

				/* reset connection */
				set_cur_connection(oldc);
			}
		}
	}
}
