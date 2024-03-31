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
struct spd;
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

extern void ikev2_derive_child_keys(struct ike_sa *ike, struct child_sa *child);

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
	const struct finite_state *from[2];	/* grow as needed */
	const struct finite_state *to;
	struct {
		bool release_whack;
	} flags;

	/*
	 * The message type being exchanged.
	 *
	 * Incoming message must match RECV_ROLE.
	 *
	 * When RECV_ROLE is NO_MESSAGE, the transition is for a new
	 * exchange.
	 */
	const enum isakmp_xchg_type exchange;
	enum message_role recv_role;

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

extern void init_ikev2(void);

void event_v2_rekey(struct state *st, bool detach_whack);

struct payload_summary ikev2_decode_payloads(struct logger *log,
					     struct msg_digest *md,
					     struct pbs_in *in_pbs,
					     enum next_payload_types_ikev2 np);

void v2_dispatch(struct ike_sa *ike, struct msg_digest *md,
		 const struct v2_state_transition *transition);

bool v2_accept_ke_for_proposal(struct ike_sa *ike,
			       struct state *st,
			       struct msg_digest *md,
			       const struct dh_desc *accepted_dh,
			       enum payload_security security);
/*
 * See 2.21. Error Handling.  In particular the IKE_AUTH discussion.
 */

bool v2_notification_fatal(v2_notification_t n);

bool already_has_larval_v2_child(struct ike_sa *ike, const struct connection *c);

void llog_v2_success_exchange_sent_to(struct ike_sa *ike);
void llog_v2_success_exchange_processed(struct ike_sa *ike);
void llog_v2_success_state_story(struct ike_sa *ike);
void ldbg_v2_success(struct ike_sa *ike);
void llog_v2_success_state_story_to(struct ike_sa *ike);

bool accept_v2_notification(v2_notification_t n,
			    struct logger *logger,
			    struct msg_digest *md,
			    bool enabled);

void start_v2_transition(struct ike_sa *ike,
			 const struct v2_state_transition *transition,
			 struct msg_digest *md, where_t where);

stf_status next_v2_transition(struct ike_sa *ike, struct msg_digest *md,
			      const struct v2_state_transition *transition,
			      where_t where);

extern void jam_v2_transition(struct jambuf *buf, const struct v2_state_transition *transition);
extern bool v2_transition_from(const struct v2_state_transition *transition, const struct finite_state *state);

#endif
