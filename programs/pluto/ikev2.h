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

#include "message_role.h"

struct pending;
struct pluto_crypto_req;
struct spd;
struct crypt_mac;
struct hash_desc;
struct payload_digest;
struct ikev2_ipseckey_dns;
struct hash_signature;
enum payload_security;
struct msg_digest;
struct state;
struct ike_sa;
struct child_sa;
struct pbs_in;
struct kem_desc;
struct connection;

typedef stf_status crypto_transition_fn(struct state *st, struct msg_digest *md,
					struct pluto_crypto_req *r);
typedef void ikev2_llog_success_fn(struct ike_sa *ike,
				   const struct msg_digest *md);

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
	/* For liveness, so that no payloads means no payloads */
	bool exact_match;
	/* required payloads: one of each type must be present */
	lset_t required;
	/* optional payloads: up to one of each type can be present */
	lset_t optional;
	/* required notification, if not v2N_NOTHING_WRONG */
	v2_notification_t notification;
};

/* Short forms for building payload type sets */

#define v2P(N) LELEM(ISAKMP_NEXT_v2##N)

struct v2_transition {
	const char *const story;	/* state transition story (not state_story[]) */
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
	const enum ikev2_exchange exchange;
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
	 *
	 * Caution! MD is NULL for initiator; then non-NULL for the
	 * responder, and the response.
	 */
	ikev2_llog_success_fn *llog_success;
};

struct v2_transitions {
	const struct v2_transition *list;
	size_t len;
};

struct v2_exchange {
	const enum ikev2_exchange type;
	const char *subplot;
	bool secured;
	struct {
		const struct v2_transition *transition;
		const struct finite_state *from[3];	/* grow as needed */
	} initiate;
	const struct v2_transitions *responder;
	const struct v2_transitions *response;
};

struct v2_exchanges {
	const struct v2_exchange *const *list;
	size_t len;
};

#define V2_EXCHANGE(KIND,						\
		    SUBPLOT,						\
		    NEXT_STORY,						\
		    I_CAT, IR_CAT, SECURED,				\
		    ...)						\
									\
	static const struct v2_transitions v2_##KIND##_response_transitions = { \
		ARRAY_REF(v2_##KIND##_response_transition),		\
	};								\
									\
	static const struct v2_transitions v2_##KIND##_responder_transitions = { \
		ARRAY_REF(v2_##KIND##_responder_transition),		\
	};								\
									\
	const struct finite_state state_v2_##KIND##_I = {		\
		.kind = STATE_V2_##KIND##_I,				\
		.name = #KIND"_I",					\
		.short_name = #KIND"_I",				\
		.story = "sent "#KIND" request",			\
		.category = I_CAT,					\
		.ike_version = IKEv2,					\
		.v2.secured = SECURED,					\
	};								\
									\
	const struct finite_state state_v2_##KIND##_IR = {		\
		.kind = STATE_V2_##KIND##_IR,				\
		.name = #KIND"_IR",					\
		.short_name = #KIND"_IR",				\
		.story = "processed "#KIND" response"NEXT_STORY,	\
		.category = IR_CAT,					\
		.ike_version = IKEv2,					\
		.v2.secured = SECURED,					\
	};								\
									\
	const struct v2_exchange v2_##KIND##_exchange = {		\
		.type = ISAKMP_v2_##KIND,				\
		.subplot = SUBPLOT,					\
		.secured = SECURED,					\
		.initiate.transition = &v2_##KIND##_initiate_transition, \
		.initiate.from = { __VA_ARGS__ },			\
		.responder = &v2_##KIND##_responder_transitions,	\
		.response = &v2_##KIND##_response_transitions,		\
	}

#define V2_STATE(KIND,							\
		 STORY,							\
		 CATEGORY, SECURED,					\
		 ...)							\
									\
	static const struct v2_exchange *v2_##KIND##_responder_exchange[] = { \
		__VA_ARGS__						\
	};								\
									\
	static const struct v2_exchanges v2_##KIND##_responder_exchanges = { \
		ARRAY_REF(v2_##KIND##_responder_exchange),		\
	};								\
									\
	const struct finite_state state_v2_##KIND = {			\
		.kind = STATE_V2_##KIND,				\
		.name = #KIND,						\
		.short_name = #KIND,					\
		.story = STORY,						\
		.category = CATEGORY,					\
		.ike_version = IKEv2,					\
		.v2.ike_exchanges = &v2_##KIND##_responder_exchanges,	\
		.v2.secured = SECURED,					\
	}

extern void init_ikev2(void);

struct payload_summary ikev2_decode_payloads(struct logger *log,
					     struct msg_digest *md,
					     struct pbs_in *in_pbs,
					     enum next_payload_types_ikev2 np);

void v2_dispatch(struct ike_sa *ike, struct msg_digest *md,
		 const struct v2_transition *transition);

bool v2_accept_ke_for_proposal(struct ike_sa *ike,
			       struct state *st,
			       struct msg_digest *md,
			       const struct kem_desc *accepted_dh,
			       enum payload_security security);
/*
 * See 2.21. Error Handling.  In particular the IKE_AUTH discussion.
 */

bool v2_notification_fatal(v2_notification_t n);

bool already_has_larval_v2_child(struct ike_sa *ike, const struct connection *c);

ikev2_llog_success_fn llog_success_ikev2_exchange_initiator;
ikev2_llog_success_fn llog_success_ikev2_exchange_responder;
ikev2_llog_success_fn llog_success_ikev2_exchange_response;

ikev2_llog_success_fn ldbg_success_ikev2;

bool accept_v2_notification(v2_notification_t n,
			    struct logger *logger,
			    struct msg_digest *md,
			    bool enabled);

void start_v2_exchange(struct ike_sa *ike, const struct v2_exchange *exchange, where_t where);
void start_v2_transition(struct ike_sa *ike,
			 const struct v2_transition *transition,
			 struct msg_digest *md, where_t where);

stf_status next_v2_exchange(struct ike_sa *ike, struct msg_digest *md,
			    const struct v2_exchange *exchange,
			    where_t where);

extern void jam_v2_transition(struct jambuf *buf, const struct v2_transition *transition);

bool v2_ike_sa_can_initiate_exchange(const struct ike_sa *ike, const struct v2_exchange *exchange);

#endif
