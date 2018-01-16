/*
 * IKEv2 functions: that ikev2_parent.c/ikev2_child.c needs.
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2017 Andrew Cagney
 */

typedef stf_status crypto_transition_fn(struct state *st, struct msg_digest *md,
					struct pluto_crypto_req *r);

extern void process_v2_packet(struct msg_digest **mdp);

extern void ikev2parent_outI1(int whack_sock,
			      struct connection *c,
			      struct state *predecessor,
			      lset_t policy,
			      unsigned long try,
			      enum crypto_importance importance
#ifdef HAVE_LABELED_IPSEC
			      , struct xfrm_user_sec_ctx_ike *uctx
#endif
			      );

extern bool ikev2_delete_out(struct state *st);

extern void log_ipsec_sa_established(const char *m, const struct state *st);

extern void complete_v2_state_transition(struct msg_digest **mdp,
					 stf_status result);

extern stf_status ikev2_send_livenss_probe(struct state *st);

extern stf_status ikev2_send_informational(struct state *st, struct state *pst,
					   v2_notification_t v2N);

extern state_transition_fn process_encrypted_informational_ikev2;

extern crypto_transition_fn ikev2_parent_outI1_tail;
extern state_transition_fn ikev2_child_ike_inIoutR;
extern state_transition_fn ikev2_child_inR;
extern state_transition_fn ikev2_child_inIoutR;

extern state_transition_fn ikev2parent_inI1outR1;
extern state_transition_fn ikev2parent_inR1;
extern state_transition_fn ikev2parent_inR1BoutI1B;
extern state_transition_fn ikev2parent_inR1outI2;
extern state_transition_fn ikev2parent_inI2outR2;
extern state_transition_fn ikev2parent_inR2;
extern crypto_transition_fn ikev2_child_out_cont;
extern crypto_transition_fn ikev2_child_inR_tail;
extern void ikev2_add_ipsec_child(int whack_sock, struct state *isakmp_sa,
		struct connection *c, lset_t policy, unsigned long try,
		so_serial_t replacing
#ifdef HAVE_LABELED_IPSEC
		, struct xfrm_user_sec_ctx_ike *uctx
#endif
		);

extern void ikev2_child_outI(struct state *st);
extern void ikev2_child_send_next(struct state *st);

extern const struct state_v2_microcode ikev2_parent_firststate_microcode;
extern const struct state_v2_microcode ikev2_rekey_ike_firststate_microcode;
extern const struct state_v2_microcode ikev2_create_child_initiate_microcode;
extern const struct state_v2_microcode ikev2_create_child_initiator_final_microcode;


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
void DBG_log_ikev2_proposals(const char *prefix, struct ikev2_proposals *proposals);

void free_ikev2_proposal(struct ikev2_proposal **proposal);
void free_ikev2_proposals(struct ikev2_proposals **proposals);

void ikev2_proposals_from_alg_info_ike(const char *name, const char *what,
				       struct alg_info_ike *alg_info_ike,
				       struct ikev2_proposals **proposals);

void ikev2_proposals_from_alg_info_esp(const char *name, const char *what,
				       struct alg_info_esp *alg_info_esp,
				       lset_t policy,
				       const struct oakley_group_desc
						*pfs_group,
				       struct ikev2_proposals **proposals);

bool ikev2_emit_sa_proposal(pb_stream *pbs,
			    struct ikev2_proposal *proposal,
			    chunk_t *local_spi,
			    enum next_payload_types_ikev2 next_payload_type);

bool ikev2_emit_sa_proposals(pb_stream *outs, struct ikev2_proposals *proposals,
			     chunk_t *local_spi,
			     enum next_payload_types_ikev2 next_payload_type);

const struct oakley_group_desc *ikev2_proposals_first_modp(struct ikev2_proposals *proposals);

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

struct ipsec_proto_info *ikev2_esp_or_ah_proto_info(struct state *st, lset_t policy);

ipsec_spi_t ikev2_esp_or_ah_spi(const struct spd_route *spd_route, lset_t policy);

extern void send_v2_notification_from_state(struct state *st,
					    v2_notification_t type,
					    chunk_t *data);

extern void send_v2_notification_from_md(struct msg_digest *md,
					 v2_notification_t type,
					 chunk_t *data);

extern stf_status ikev2_process_decrypted_payloads(struct msg_digest *md);

extern bool ikev2_decode_peer_id_and_certs(struct msg_digest *md);

extern void ikev2_log_parentSA(struct state *st);

extern bool ikev2_calculate_rsa_sha1(struct state *st,
				     enum original_role role,
				     unsigned char *idhash,
				     pb_stream *a_pbs);

extern bool ikev2_create_psk_auth(enum keyword_authby authby,
				     struct state *st,
				     unsigned char *idhash,
				     pb_stream *a_pbs,
				     bool calc_no_ppk_auth,
				     chunk_t *no_ppk_auth);

extern stf_status ikev2_verify_rsa_sha1(struct state *st,
					enum original_role role,
					unsigned char *idhash,
					pb_stream *sig_pbs);

extern stf_status ikev2_verify_psk_auth(enum keyword_authby authby,
					struct state *st,
					unsigned char *idhash,
					pb_stream *sig_pbs);

extern void ikev2_derive_child_keys(struct state *st,
				    enum original_role role);

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

extern stf_status ikev2_calc_emit_ts(struct msg_digest *md,
				     pb_stream *outpbs,
				     const enum original_role role,
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
					 enum original_role role,
					 pb_stream *outpbs,
					 enum isakmp_xchg_types isa_xchg);

extern stf_status ikev2_resp_accept_child_ts(const struct msg_digest *md,
					     struct state **ret_cst,
					     enum original_role role, enum
					     isakmp_xchg_types isa_xchg);

extern void ikev2_update_msgid_counters(struct msg_digest *md);
extern void ikev2_print_ts(struct traffic_selector *ts);

extern void send_v2_notification(struct state *pst,
				 v2_notification_t type,
				 u_char *icookie,
				 u_char *rcookie,
				 chunk_t *data);

extern bool ship_v2N(enum next_payload_types_ikev2 np,
		     u_int8_t critical,
		     u_int8_t protoid,
		     const chunk_t *spi,
		     v2_notification_t type,
		     const chunk_t *n_data, pb_stream *rbody);

extern deltatime_t ikev2_replace_delay(struct state *st, enum event_type *pkind,
				       enum original_role role);

stf_status ikev2_send_cp(struct state *st, enum next_payload_types_ikev2 np,
		pb_stream *outpbs);

bool ikev2_parse_cp_r_body(struct payload_digest *cp_pd, struct state *st);

void send_v2_notification_invalid_ke(struct msg_digest *md,
				     const struct oakley_group_desc *group);

struct ikev2_payloads_summary {
	stf_status status;
	lset_t seen;
	lset_t repeated;
};

struct ikev2_payloads_summary ikev2_decode_payloads(struct msg_digest *md,
						    pb_stream *in_pbs,
						    enum next_payload_types_ikev2 np);

struct ikev2_payloads_summary ikev2_decrypt_msg(struct msg_digest *md);

struct ikev2_payload_errors {
	stf_status status;
	lset_t bad_repeat;
	lset_t missing;
	lset_t unexpected;
};

struct ikev2_expected_payloads {
	/*
	 * required payloads: one of each type must be present
	 */
	lset_t required;
	/*
	 * optional payloads: up to one of each type can be present
	 */
	lset_t optional;
};

struct state_v2_microcode {
	const char *const story;
	enum state_kind state, next_state;
	enum isakmp_xchg_types recv_type;
	lset_t flags;
#ifdef NOT_YET
	/* or struct ... clear_payloads ; struct ... encrypted_payloads; */
	struct {
		struct ikev2_expected_payloads clear;
		struct ikev2_expected_payloads encrypted;
	} expected_payloads;
#else
	lset_t req_clear_payloads;  /* required unencrypted payloads (allows just one) for received packet */
	lset_t opt_clear_payloads;  /* optional unencrypted payloads (none or one) for received packet */
	lset_t req_enc_payloads;  /* required encrypted payloads (allows just one) for received packet */
	lset_t opt_enc_payloads;  /* optional encrypted payloads (none or one) for received packet */
#endif
	enum event_type timeout_event;
	state_transition_fn *processor;
	crypto_transition_fn *crypto_end;
};

void ikev2_copy_cookie_from_sa(struct state *st,
		                struct ikev2_proposal *accepted_ike_proposal);

struct ikev2_payload_errors ikev2_verify_payloads(struct ikev2_payloads_summary summary,
						  const struct ikev2_expected_payloads *expected);

void ikev2_log_payload_errors(struct ikev2_payload_errors errors,
			      struct state *st);

void ikev2_isakamp_established(struct state *st,
				const struct state_v2_microcode
				*svm, enum state_kind new_state,
				enum original_role role);
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

