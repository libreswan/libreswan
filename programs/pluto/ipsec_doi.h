/* IPsec DOI and Oakley resolution routines
 * Copyright (C) 1998-2002,2010-2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2007,2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Wes Hardaker <opensource@hardakers.net>
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
 */

struct xfrm_user_sec_ctx_ike *uctx; /* forward declaration */

extern void ipsecdoi_initiate(int whack_sock, struct connection *c,
			      lset_t policy, unsigned long try,
			      so_serial_t replacing,
			      enum crypto_importance importance
#ifdef HAVE_LABELED_IPSEC
			      , struct xfrm_user_sec_ctx_ike *uctx
#endif
			      );

extern void ipsecdoi_replace(struct state *st,
			     lset_t policy_add, lset_t policy_del,
			     unsigned long try);

extern void init_phase2_iv(struct state *st, const msgid_t *msgid);

extern state_transition_fn
	main_inI1_outR1,
	main_inR1_outI2,
	main_inI2_outR2,
	main_inR2_outI3,
	main_inI3_outR3,
	main_inR3,
	aggr_inI1_outR1,
	aggr_inR1_outI2,
	aggr_inI2;
/*
 * forward
 */
struct oakley_group_desc;
extern bool send_delete(struct state *st);
extern bool accept_delete(struct msg_digest *md,
			  struct payload_digest *p);
extern void accept_self_delete(struct msg_digest *md);

extern void send_notification_from_state(struct state *st,
					 enum state_kind from_state,
					 notification_t type);
extern void send_notification_from_md(struct msg_digest *md, notification_t type);

extern notification_t accept_KE(chunk_t *dest, const char *val_name,
				const struct oakley_group_desc *gr,
				pb_stream *pbs);

/*
 * some additional functions are exported for xauth.c
 */
extern bool close_message(pb_stream *pbs, struct state *st) MUST_USE_RESULT;
extern bool encrypt_message(pb_stream *pbs, struct state *st) MUST_USE_RESULT;

/* START_HASH_PAYLOAD_NO_HASH_START
 *
 * Emit a to-be-filled-in hash payload, noting the field start (r_hashval)
 * and the start of the part of the message to be hashed (r_hash_start).
 * This macro is magic.
 * - it can cause the caller to return
 * - it references variables local to the caller (r_hashval, st)
 */
#define START_HASH_PAYLOAD_NO_R_HASH_START(rbody, np) { \
		pb_stream hash_pbs; \
		if (!ikev1_out_generic(np, &isakmp_hash_desc, &(rbody), &hash_pbs)) \
			return STF_INTERNAL_ERROR; \
		r_hashval = hash_pbs.cur; /* remember where to plant value */ \
		if (!out_zero(st->st_oakley.prf_hasher->hash_digest_len, \
			      &hash_pbs, "HASH")) \
			return STF_INTERNAL_ERROR; \
		close_output_pbs(&hash_pbs); \
}

/* START_HASH_PAYLOAD
 *
 * Emit a to-be-filled-in hash payload, noting the field start (r_hashval)
 * and the start of the part of the message to be hashed (r_hash_start).
 * This macro is magic.
 * - it can cause the caller to return
 * - it references variables local to the caller (r_hashval, r_hash_start, st)
 */
#define START_HASH_PAYLOAD(rbody, np) { \
		START_HASH_PAYLOAD_NO_R_HASH_START(rbody, np); \
		r_hash_start = (rbody).cur; /* hash from after HASH payload */ \
}

/* CHECK_QUICK_HASH
 *
 * This macro is magic -- it cannot be expressed as a function.
 * - it causes the caller to return!
 * - it declares local variables and expects the "do_hash" argument
 *   expression to reference them (hash_val, hash_pbs)
 */
#define CHECK_QUICK_HASH(md, do_hash, hash_name, msg_name) { \
		pb_stream *const hash_pbs = &md->chain[ISAKMP_NEXT_HASH]->pbs; \
		u_char hash_val[MAX_DIGEST_LEN]; \
		size_t hash_len = do_hash; \
		if (pbs_left(hash_pbs) != hash_len \
		    || !memeq(hash_pbs->cur, hash_val, hash_len)) \
		{ \
			DBG_cond_dump(DBG_CRYPT, "received " hash_name ":", \
				      hash_pbs->cur, pbs_left(hash_pbs)); \
			loglog(RC_LOG_SERIOUS, \
			       "received " hash_name " does not match computed value in " msg_name); \
			/* XXX Could send notification back */ \
			return STF_FAIL + INVALID_HASH_INFORMATION; \
		} \
}

extern stf_status send_isakmp_notification(struct state *st,
					   u_int16_t type, const void *data,
					   size_t len);

extern bool has_preloaded_public_key(struct state *st);

extern bool extract_peer_id(struct id *peer, const pb_stream *id_pbs);

struct pluto_crypto_req;	/* prevent struct type being local to function protocol */
extern void unpack_nonce(chunk_t *n, const struct pluto_crypto_req *r);
