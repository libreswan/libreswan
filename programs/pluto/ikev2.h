/*
 * IKEv2 functions: that ikev2_parent.c/ikev2_child.c needs.
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2018 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2017-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2018 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2020 Yulia Kuzovkova <ukuzovkova@gmail.com>
 */

#ifndef IKEV2_H
#define IKEV2_H

#include "fd.h"

struct pending;
struct pluto_crypto_req;
struct spd_route;
struct crypt_mac;
struct hash_desc;
struct payload_digest;
struct ikev2_ipseckey_dns;
struct hash_signature;
enum payload_security;

typedef stf_status crypto_transition_fn(struct state *st, struct msg_digest *md,
					struct pluto_crypto_req *r);

void ikev2_process_packet(struct msg_digest *mdp);

void process_protected_v2_message(struct ike_sa *ike, struct msg_digest *md);

typedef stf_status ikev2_state_transition_fn(struct ike_sa *ike,
					     struct child_sa *child, /* could be NULL */
					     struct msg_digest *md /* could be NULL */);

extern void complete_v2_state_transition(struct ike_sa *ike,
					 struct msg_digest *mdp,
					 stf_status result);

void schedule_reinitiate_v2_ike_sa_init(struct ike_sa *ike,
					stf_status (*resume)(struct ike_sa *ike));

struct crypt_mac ikev2_rsa_sha1_hash(const struct crypt_mac *hash);

extern bool ikev2_emit_psk_auth(enum keyword_auth authby,
				const struct ike_sa *ike,
				const struct crypt_mac *idhash,
				pb_stream *a_pbs,
				const struct hash_signature *auth_sig);

extern bool ikev2_create_psk_auth(enum keyword_auth authby,
				  const struct ike_sa *ike,
				  const struct crypt_mac *idhash,
				  chunk_t *additional_auth /* output */);

extern void ikev2_derive_child_keys(struct ike_sa *ike, struct child_sa *child);

void schedule_v2_replace_event(struct state *st);

bool ikev2_parse_cp_r_body(struct payload_digest *cp_pd, struct child_sa *child);

struct ikev2_expected_payloads {
	/* required payloads: one of each type must be present */
	lset_t required;
	/* optional payloads: up to one of each type can be present */
	lset_t optional;
	/* required notification, if not v2N_NOTHING_WRONG */
	v2_notification_t notification;
};

struct v2_state_transition {
	const char *const story;	/* state transition story (not state_story[]) */
	const enum state_kind state;
	const enum state_kind next_state;
	const lset_t flags;

	/*
	 * The message type being exchanged.
	 *
	 * Incomming message must match RECV_ROLE.
	 *
	 * If the transition succeeds, outgoing message must match
	 * SEND_ROLE.
	 *
	 * Old code had a simple flag (SMF2_SEND) and then tried to
	 * reverse engineer this value from the incoming message.
	 * While in theory possible, it didn't seem to go well.  For
	 * instance, because the code didn't clearly differentiate
	 * between a FAKE_MD (created because old code insisted on
	 * there always being an incoming message) and a real request
	 * or response it ended up trying to use STATE_KIND to figure
	 * things out.  While perhaps it is possible to make all this
	 * work, spelling it out seems clearer.
	 */
	const enum isakmp_xchg_type exchange;
	enum message_role recv_role;
	enum message_role send_role;

	/*
	 * The message contents.
	 *
	 * These field names, what ever they are, should exactly match
	 * equivalent struct payload_summary fields found in struct
	 * msg_digest.
	 */
	struct ikev2_expected_payloads message_payloads;
	struct ikev2_expected_payloads encrypted_payloads; /* contents of SK payload */

	const enum event_type timeout_event;
	ikev2_state_transition_fn *const processor;

	/*
	 * When non-NULL, use this to log the IKE SA's successful
	 * state transition.
	 */
	void (*llog_success)(struct ike_sa *ike);
};

void v2_ike_sa_established(struct ike_sa *ike);
void llog_v2_ike_sa_established(struct ike_sa *ike, struct child_sa *larval);

extern bool emit_v2KE(chunk_t g, const struct dh_desc *group, pb_stream *outs);

extern void init_ikev2(void);

void v2_event_sa_rekey(struct state *st, bool detach_whack);
void v2_event_sa_replace(struct state *st);

struct payload_summary ikev2_decode_payloads(struct logger *log,
					     struct msg_digest *md,
					     pb_stream *in_pbs,
					     enum next_payload_types_ikev2 np);

void v2_dispatch(struct ike_sa *ike, struct msg_digest *md,
		 const struct v2_state_transition *transition);

bool accept_v2_nonce(struct logger *logger, struct msg_digest *md,
		     chunk_t *dest, const char *name);

bool v2_accept_ke_for_proposal(struct ike_sa *ike,
			       struct state *st,
			       struct msg_digest *md,
			       const struct dh_desc *accepted_dh,
			       enum payload_security security);
void ikev2_rekey_expire_predecessor(const struct child_sa *larval_sa, so_serial_t pred);

struct crypt_mac v2_id_hash(struct ike_sa *ike, const char *why,
			    const char *id_name, shunk_t id_payload,
			    const char *key_name, PK11SymKey *key);
bool id_ipseckey_allowed(struct ike_sa *ike, enum ikev2_auth_method atype);
struct crypt_mac v2_hash_id_payload(const char *id_name, struct ike_sa *ike,
				    const char *key_name, PK11SymKey *key);

bool negotiate_hash_algo_from_notification(const struct pbs_in *payload_pbs,
					   struct ike_sa *ike);


/*
 * See 2.21. Error Handling.  In particular the IKE_AUTH discussion.
 */

bool v2_notification_fatal(v2_notification_t n);

bool already_has_larval_v2_child(struct ike_sa *ike, const struct connection *c);

void llog_v2_success_exchange_sent(struct ike_sa *ike);
void llog_v2_success_exchange_processed(struct ike_sa *ike);
void llog_v2_success_state_story(struct ike_sa *ike);
void llog_v2_success_state_story_details(struct ike_sa *ike);
void llog_v2_success_state_story_to_details(struct ike_sa *ike);
void ldbg_v2_success(struct ike_sa *ike);

bool v2_state_is_expired(struct state *st, const char *verb);

bool accept_v2_notification(v2_notification_t n,
			    struct logger *logger,
			    struct msg_digest *md,
			    bool enabled);


#endif
