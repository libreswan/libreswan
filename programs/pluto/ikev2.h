/*
 * IKEv2 functions: that ikev2_parent.c/ikev2_child.c needs.
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2017 Andrew Cagney
 */

typedef stf_status crypto_transition_fn(struct state *st, struct msg_digest *md,
					struct pluto_crypto_req *r);

void ikev2_process_packet(struct msg_digest **mdp);
void ikev2_process_state_packet(struct ike_sa *ike, struct state *st,
				struct msg_digest **mdp);

/* extern initiator_function ikev2_parent_outI1; */
extern void ikev2_parent_outI1(int whack_sock,
			      struct connection *c,
			      struct state *predecessor,
			      lset_t policy,
			      unsigned long try,
			      enum crypto_importance importance
#ifdef HAVE_LABELED_IPSEC
			      , struct xfrm_user_sec_ctx_ike *uctx
#endif
			      );

extern void log_ipsec_sa_established(const char *m, const struct state *st);

extern void complete_v2_state_transition(struct msg_digest **mdp,
					 stf_status result);

extern stf_status ikev2_send_livenss_probe(struct state *st);

extern state_transition_fn process_encrypted_informational_ikev2;

extern state_transition_fn ikev2_child_ike_inIoutR;
extern state_transition_fn ikev2_child_ike_inR;
extern state_transition_fn ikev2_child_inR;
extern state_transition_fn ikev2_child_inIoutR;

extern state_transition_fn ikev2_parent_inI1outR1;
extern state_transition_fn ikev2_IKE_SA_process_SA_INIT_response_notification;
extern state_transition_fn ikev2_auth_initiator_process_failure_notification;
extern state_transition_fn ikev2_auth_initiator_process_unknown_notification;
extern state_transition_fn ikev2_ike_sa_process_auth_request_no_skeyid;
extern state_transition_fn ikev2_ike_sa_process_auth_request;
extern state_transition_fn ikev2_parent_inR1outI2;
extern state_transition_fn ikev2_parent_inR2;
extern crypto_transition_fn ikev2_child_out_cont;
extern crypto_transition_fn ikev2_child_inR_tail;
extern crypto_transition_fn ikev2_child_ike_rekey_tail;
extern void ikev2_initiate_child_sa(struct pending *p);

void ikev2_rekey_ike_start(struct state *st);

extern void ikev2_child_outI(struct state *st);
extern void ikev2_child_send_next(struct state *st);

extern v2_notification_t accept_v2_nonce(struct msg_digest *md, chunk_t *dest,
		const char *name);

extern stf_status ikev2_parent_inI2outR2_id_tail(struct msg_digest * md);

/* MAGIC: perform f, a function that returns notification_t
 * and return from the ENCLOSING stf_status returning function if it fails.
 */
/* ??? why are there so many copies of this routine (ikev2.h, ikev1_continuations.h, ipsec_doi.c).
 * Sometimes more than one copy is defined!
 */
#define RETURN_STF_FAILURE(f) { \
	notification_t res = (f); \
	if (res != NOTHING_WRONG) { \
		  return STF_FAIL + res; \
	} \
}

/* macro that returns STF_STATUS on failure */
#define RETURN_STF_FAILURE_STATUS(f) { \
	stf_status res = (f); \
	if (res != STF_OK) { \
		return res; \
	} \
}

struct ikev2_proposal;
struct ikev2_proposals;

void DBG_log_ikev2_proposal(const char *prefix, struct ikev2_proposal *proposal);

void free_ikev2_proposal(struct ikev2_proposal **proposal);
void free_ikev2_proposals(struct ikev2_proposals **proposals);

void ikev2_proposals_from_alg_info_ike(const char *connection_name,
				       const char *why,
				       struct alg_info_ike *alg_info_ike,
				       struct ikev2_proposals **proposals);

void ikev2_proposals_from_alg_info_esp(const char *connection_name,
				       const char *why,
				       struct alg_info_esp *alg_info_esp,
				       lset_t policy,
				       const struct oakley_group_desc *default_dh,
				       struct ikev2_proposals **proposals);

bool ikev2_emit_sa_proposal(pb_stream *pbs,
			    struct ikev2_proposal *proposal,
			    chunk_t *local_spi,
			    enum next_payload_types_ikev2 next_payload_type);

bool ikev2_emit_sa_proposals(pb_stream *outs, struct ikev2_proposals *proposals,
			     chunk_t *local_spi,
			     enum next_payload_types_ikev2 next_payload_type);

const struct oakley_group_desc *ikev2_proposals_first_dh(struct ikev2_proposals *proposals);

bool ikev2_proposals_include_modp(struct ikev2_proposals *proposals,
				  oakley_group_t modp);

stf_status ikev2_process_sa_payload(const char *what,
				    pb_stream *sa_payload,
				    bool expect_ike,  /* IKE vs ESP or AH */
				    bool expect_spi,
				    bool expect_accepted,
				    bool opportunistic,
				    struct ikev2_proposal **chosen,
				    struct ikev2_proposals *local_proposals);

bool ikev2_proposal_to_proto_info(struct ikev2_proposal *proposal,
				  struct ipsec_proto_info *proto_info);

bool ikev2_proposal_to_trans_attrs(struct ikev2_proposal *chosen,
				   struct trans_attrs  *);

struct ipsec_proto_info *ikev2_child_sa_proto_info(struct state *st, lset_t policy);

ipsec_spi_t ikev2_child_sa_spi(const struct spd_route *spd_route, lset_t policy);

extern bool ikev2_decode_peer_id_and_certs(struct msg_digest *md);

extern void ikev2_log_parentSA(struct state *st);

extern bool ikev2_calculate_rsa_sha1(struct state *st,
				     enum original_role role,
				     unsigned char *idhash,
				     pb_stream *a_pbs,
				     bool calc_no_ppk_auth,
				     chunk_t *no_ppk_auth);

extern bool ikev2_create_psk_auth(enum keyword_authby authby,
				     struct state *st,
				     unsigned char *idhash,
				     pb_stream *a_pbs,
				     bool calc_additional_auth,
				     chunk_t *additional_auth);

extern stf_status ikev2_verify_rsa_sha1(struct state *st,
					enum original_role role,
					unsigned char *idhash,
					pb_stream *sig_pbs);

extern stf_status ikev2_verify_psk_auth(enum keyword_authby authby,
					struct state *st,
					unsigned char *idhash,
					pb_stream *sig_pbs);

extern void ikev2_derive_child_keys(struct child_sa *child);

extern struct traffic_selector ikev2_end_to_ts(const struct end *e);

extern int ikev2_evaluate_connection_fit(const struct connection *d,
					 const struct spd_route *sr,
					 enum original_role role,
					 const struct traffic_selector *tsi,
					 const struct traffic_selector *tsr,
					 int tsi_n,
					 int tsr_n);

extern int ikev2_evaluate_connection_port_fit(const struct connection *d,
					      const struct spd_route *sr,
					      enum original_role role,
					      const struct traffic_selector *tsi,
					      const struct traffic_selector *tsr,
					      int tsi_n,
					      int tsr_n,
					      int *best_tsi_i,
					      int *best_tsr_i);

extern stf_status ikev2_emit_ts_payloads(struct child_sa *cst,
					 pb_stream *outpbs,
					 enum sa_role role,
					 const struct connection *c0,
					 const enum next_payload_types_ikev2 np);

extern int ikev2_parse_ts(struct payload_digest *ts_pd,
			  struct traffic_selector *array,
			  unsigned int array_roof);

extern int ikev2_evaluate_connection_protocol_fit(const struct connection *d,
						  const struct spd_route *sr,
						  enum original_role role,
						  const struct traffic_selector *tsi,
						  const struct traffic_selector *tsr,
						  int tsi_n,
						  int tsr_n,
						  int *best_tsi_i,
						  int *best_tsr_i);

extern stf_status ikev2_child_sa_respond(struct msg_digest *md,
					 pb_stream *outpbs,
					 enum isakmp_xchg_types isa_xchg);

extern stf_status ikev2_resp_accept_child_ts(const struct msg_digest *md,
					     struct state **ret_cst,
					     enum original_role role, enum
					     isakmp_xchg_types isa_xchg);

extern void ikev2_update_msgid_counters(struct msg_digest *md);
extern void ikev2_print_ts(struct traffic_selector *ts);

extern deltatime_t ikev2_replace_delay(struct state *st,
				       enum event_type *pkind);

stf_status ikev2_send_cp(struct state *st, enum next_payload_types_ikev2 np,
		pb_stream *outpbs);

bool ikev2_parse_cp_r_body(struct payload_digest *cp_pd, struct state *st);

bool ikev2_decrypt_msg(struct state *st, struct msg_digest *md);

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

struct state_v2_microcode {
	const char *const story;	/* state transition story (not state_story[]) */
	enum state_kind state;
	enum state_kind next_state;
	enum isakmp_xchg_types recv_type;
	lset_t flags;

	lset_t req_clear_payloads;  /* required unencrypted payloads (allows just one) for received packet */
	lset_t opt_clear_payloads;  /* optional unencrypted payloads (none or one) for received packet */
	lset_t req_enc_payloads;  /* required encrypted payloads (allows just one) for received packet */
	lset_t opt_enc_payloads;  /* optional encrypted payloads (none or one) for received packet */

	/*
	 * Packed form of above for passing into payload processing
	 * functions.  If above are specified, they are re-packed into
	 * the below.
	 *
	 * These field names, what ever they are, should exactly match
	 * equivalent struct payload_summary fields found in struct
	 * msg_digest.
	 */
	struct ikev2_expected_payloads message_payloads;
	struct ikev2_expected_payloads encrypted_payloads;

	enum event_type timeout_event;
	state_transition_fn *processor;
	crypto_transition_fn *crypto_end;
};

void ikev2_copy_cookie_from_sa(struct ikev2_proposal *accepted_ike_proposal,
				u_int8_t *cookie);

void ikev2_ike_sa_established(struct ike_sa *ike,
			      const struct state_v2_microcode *svm,
			      enum state_kind new_state);

struct ikev2_ipseckey_dns;

extern stf_status ikev2_process_child_sa_pl(struct msg_digest *md,
					    bool expect_accepted);

extern bool justship_v2KE(chunk_t *g, const struct oakley_group_desc *group,
		pb_stream *outs, u_int8_t np);

extern bool is_msg_response(const struct msg_digest *md);
extern bool is_msg_request(const struct msg_digest *md);

extern bool need_this_intiator(struct state *st);

extern void init_ikev2(void);

extern void ikev2_record_newaddr(struct state *st, void *arg_ip);
extern void ikev2_record_deladdr(struct state *st, void *arg_ip);
extern void ikev2_addr_change(struct state *st);

