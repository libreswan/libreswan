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
enum payload_security;

typedef stf_status crypto_transition_fn(struct state *st, struct msg_digest *md,
					struct pluto_crypto_req *r);

void ikev2_process_packet(struct msg_digest *mdp);
void ikev2_process_state_packet(struct ike_sa *ike, struct state *st,
				struct msg_digest *mdp);

typedef stf_status ikev2_state_transition_fn(struct ike_sa *ike,
					     struct child_sa *child, /* could be NULL */
					     struct msg_digest *md /* could be NULL */);

extern void log_ipsec_sa_established(const char *m, const struct state *st);

extern void complete_v2_state_transition(struct state *st,
					 struct msg_digest *mdp,
					 stf_status result);

void schedule_reinitiate_v2_ike_sa_init(struct ike_sa *ike,
					stf_status (*resume)(struct ike_sa *ike));

struct ikev2_proposal;
struct ikev2_proposals;

void DBG_log_ikev2_proposal(const char *prefix, const struct ikev2_proposal *proposal);

void free_ikev2_proposal(struct ikev2_proposal **proposal);
void free_ikev2_proposals(struct ikev2_proposals **proposals);

/*
 * On-demand, generate proposals for either the IKE SA or the CHILD
 * SA.
 *
 * For CHILD SAs, two different proposal suites are used: during the
 * IKE_AUTH exchange a stripped down proposal that excludes DH; and
 * during the CREATE_CHILD_SA exchange DH a mashed up proposal that
 * can include the IKE SA's latest DH.
 *
 * This is done on-demand as, only at the point where the IKE or CHILD
 * SA is being instantiated, is it clear what proposals are needed.
 * For instance, when a CHILD SA shares an existing IKE SA, the CHILD
 * won't need IKE proposals but will need the IKE SA's DH.
 *
 * XXX: Should the CREATE CHILD SA proposals be stored in the state?
 */

struct ikev2_proposals *get_v2_ike_proposals(struct connection *c, const char *why,
					     struct logger *logger);
struct ikev2_proposals *get_v2_ike_auth_child_proposals(struct connection *c, const char *why,
							struct logger *logger);
struct ikev2_proposals *get_v2_create_child_proposals(struct connection *c, const char *why,
						      const struct dh_desc *default_dh,
						      struct logger *logger);

bool ikev2_emit_sa_proposal(struct pbs_out *pbs,
			    const struct ikev2_proposal *proposal,
			    const chunk_t *local_spi);

bool ikev2_emit_sa_proposals(struct pbs_out *outs,
			     const struct ikev2_proposals *proposals,
			     const chunk_t *local_spi);

const struct dh_desc *ikev2_proposals_first_dh(const struct ikev2_proposals *proposals,
					       struct logger *logger);

bool ikev2_proposals_include_modp(const struct ikev2_proposals *proposals,
				  oakley_group_t modp);

stf_status ikev2_process_sa_payload(const char *what,
				    pb_stream *sa_payload,
				    bool expect_ike,  /* IKE vs ESP or AH */
				    bool expect_spi,
				    bool expect_accepted,
				    bool opportunistic,
				    struct ikev2_proposal **chosen,
				    const struct ikev2_proposals *local_proposals,
				    struct logger *logger);

bool ikev2_proposal_to_proto_info(const struct ikev2_proposal *proposal,
				  struct ipsec_proto_info *proto_info,
				  struct logger *logger);

bool ikev2_proposal_to_trans_attrs(const struct ikev2_proposal *chosen,
				   struct trans_attrs *ta_out, struct logger *logger);

ipsec_spi_t ikev2_child_sa_spi(const struct spd_route *spd_route, lset_t policy,
			       struct logger *logger);

extern void ikev2_log_parentSA(const struct state *st);

extern bool ikev2_calculate_rsa_hash(struct ike_sa *ike,
				     const struct crypt_mac *idhash,
				     pb_stream *a_pbs,
				     chunk_t *no_ppk_auth /* optional output */,
				     const struct hash_desc *hash_algo);

extern bool ikev2_emit_psk_auth(enum keyword_authby authby,
				const struct ike_sa *ike,
				const struct crypt_mac *idhash,
				pb_stream *a_pbs);

extern bool ikev2_create_psk_auth(enum keyword_authby authby,
				  const struct ike_sa *ike,
				  const struct crypt_mac *idhash,
				  chunk_t *additional_auth /* output */);

diag_t v2_authsig_and_log_using_RSA_pubkey(struct ike_sa *ike,
					   const struct crypt_mac *idhash,
					   shunk_t signature,
					   const struct hash_desc *hash_algo);

diag_t v2_authsig_and_log_using_ECDSA_pubkey(struct ike_sa *ike,
					     const struct crypt_mac *idhash,
					     shunk_t signature,
					     const struct hash_desc *hash_algo);

extern void ikev2_derive_child_keys(struct ike_sa *ike, struct child_sa *child);

void v2_schedule_replace_event(struct state *st);

bool ikev2_parse_cp_r_body(struct payload_digest *cp_pd, struct child_sa *child);

struct ikev2_payload_errors {
	bool bad;
	lset_t excessive;
	lset_t missing;
	lset_t unexpected;
	v2_notification_t notification;
};

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
	const enum isakmp_xchg_type recv_type;
	enum message_role recv_role;
	const lset_t flags;

	/*
	 * During a successful state transition is an out going
	 * message expected and, if so, is it a request or response.
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
	enum message_role send;

	/*
	 * These field names, what ever they are, should exactly match
	 * equivalent struct payload_summary fields found in struct
	 * msg_digest.
	 */
	struct ikev2_expected_payloads message_payloads;
	struct ikev2_expected_payloads encrypted_payloads; /* contents of SK payload */

	const enum event_type timeout_event;
	ikev2_state_transition_fn *const processor;
};

void ikev2_copy_cookie_from_sa(const struct ikev2_proposal *accepted_ike_proposal,
				ike_spi_t *cookie);

void ikev2_ike_sa_established(struct ike_sa *ike,
			      const struct v2_state_transition *svm,
			      enum state_kind new_state);

extern bool emit_v2KE(chunk_t g, const struct dh_desc *group, pb_stream *outs);

extern void init_ikev2(void);

void jam_v2_stf_status(struct jambuf *buf, unsigned ret);

void v2_event_sa_rekey(struct state *st);
void v2_event_sa_replace(struct state *st);

struct payload_summary ikev2_decode_payloads(struct logger *log,
					     struct msg_digest *md,
					     pb_stream *in_pbs,
					     enum next_payload_types_ikev2 np);

void v2_dispatch(struct ike_sa *ike, struct state *st,
		 struct msg_digest *md,
		 const struct v2_state_transition *transition);

bool accept_v2_nonce(struct logger *logger, struct msg_digest *md,
		     chunk_t *dest, const char *name);

bool v2_accept_ke_for_proposal(struct ike_sa *ike,
			       struct state *st,
			       struct msg_digest *md,
			       const struct dh_desc *accepted_dh,
			       enum payload_security security);
bool need_v2_configuration_payload(const struct connection *const pc,
				   const lset_t st_nat_traversal);
void ikev2_rekey_expire_predecessor(const struct child_sa *larval_sa, so_serial_t pred);

struct crypt_mac v2_id_hash(struct ike_sa *ike, const char *why,
			    const char *id_name, shunk_t id_payload,
			    const char *key_name, PK11SymKey *key);
bool id_ipseckey_allowed(struct ike_sa *ike, enum ikev2_auth_method atype);
struct crypt_mac v2_hash_id_payload(const char *id_name, struct ike_sa *ike,
				    const char *key_name, PK11SymKey *key);

void IKE_SA_established(const struct ike_sa *ike);

bool negotiate_hash_algo_from_notification(const struct pbs_in *payload_pbs,
					   struct ike_sa *ike);


/*
 * See 2.21. Error Handling.  In particular the IKE_AUTH discussion.
 */

bool v2_notification_fatal(v2_notification_t n);
stf_status stf_status_from_v2_notification(v2_notification_t n);

bool already_has_larval_v2_child(struct ike_sa *ike, const struct connection *c);

#endif
