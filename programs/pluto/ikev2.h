/*
 * IKEv2 functions: that ikev2_parent.c/ikev2_child.c needs.
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 *
 *
 */

extern void process_v2_packet(struct msg_digest **mdp);

extern stf_status ikev2parent_outI1(int whack_sock,
				    struct connection *c,
				    struct state *predecessor,
				    lset_t policy,
				    unsigned long try,
				    enum crypto_importance importance
#ifdef HAVE_LABELED_IPSEC
				    , struct xfrm_user_sec_ctx_ike * uctx
#endif
				    );

extern void ikev2_delete_out(struct state *st);
extern void v2_delete_my_family(struct state *pst, enum phase1_role role);

extern bool ikev2_out_sa(pb_stream *outs,
			 enum ikev2_sec_proto_id protoid,
			 struct db_sa *sadb,
			 struct state *st,
			 bool parentSA,
			 enum next_payload_types_ikev2 np);

extern void complete_v2_state_transition(struct msg_digest **mdp,
					 stf_status result);

extern stf_status ikev2_send_informational(struct state *st);

extern stf_status process_encrypted_informational_ikev2(struct msg_digest *md);
extern stf_status ikev2_in_create_child_sa(struct msg_digest *md);

extern stf_status ikev2parent_inI1outR1(struct msg_digest *md);
extern stf_status ikev2parent_inR1(struct msg_digest *md);
extern stf_status ikev2parent_inR1BoutI1B(struct msg_digest *md);
extern stf_status ikev2parent_inR1outI2(struct msg_digest *md);
extern stf_status ikev2parent_inI2outR2(struct msg_digest *md);
extern stf_status ikev2parent_inR2(struct msg_digest *md);

extern const struct state_v2_microcode ikev2_parent_firststate_microcode;

extern v2_notification_t accept_v2_nonce(struct msg_digest *md, chunk_t *dest,
		const char *name);

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

extern stf_status ikev2_parse_parent_sa_body(pb_stream *sa_pbs,				/* body of input SA Payload */
					     const struct ikev2_sa *sa_prop UNUSED,	/* header of input SA Payload */
					     pb_stream *r_sa_pbs,			/* if non-NULL, where to emit winning SA */
					     struct state *st,				/* current state object */
					     bool selection				/* if this SA is a selection, only one
											 * tranform can appear. */
					     );

extern stf_status ikev2_parse_child_sa_body(pb_stream *sa_pbs,				/* body of input SA Payload */
					    const struct ikev2_sa *sa_prop UNUSED,	/* header of input SA Payload */
					    pb_stream *r_sa_pbs,				/* if non-NULL, where to emit winning SA */
					    struct state *st,				/* current state object */
					    bool selection				/* if this SA is a selection, only one
											 * tranform can appear. */
					    );


extern void send_v2_notification_from_state(struct state *st,
					    enum state_kind state,
					    v2_notification_t type,
					    chunk_t *data);

extern void send_v2_notification_from_md(struct msg_digest *md,
					 v2_notification_t type,
					 chunk_t *data);

extern stf_status ikev2_process_payloads(struct msg_digest *md,
					 pb_stream   *in_pbs,
					 enum next_payload_types_ikev2 np,
					 bool enc);

extern bool ikev2_decode_peer_id(struct msg_digest *md,
				 enum phase1_role initiator);

extern void ikev2_log_parentSA(struct state *st);

extern bool ikev2_calculate_rsa_sha1(struct state *st,
				     enum phase1_role role,
				     unsigned char *idhash,
				     pb_stream *a_pbs);

extern bool ikev2_calculate_psk_auth(struct state *st,
				     enum phase1_role role,
				     unsigned char *idhash,
				     pb_stream *a_pbs);

extern stf_status ikev2_verify_rsa_sha1(struct state *st,
					enum phase1_role role,
					unsigned char *idhash,
					const struct pubkey_list *keys_from_dns,
					const struct gw_info *gateways_from_dns,
					pb_stream *sig_pbs);

extern stf_status ikev2_verify_psk_auth(struct state *st,
					enum phase1_role role,
					unsigned char *idhash,
					pb_stream *sig_pbs);

extern stf_status ikev2_emit_ipsec_sa(struct msg_digest *md,
				      pb_stream *outpbs,
				      enum next_payload_types_ikev2 np,
				      struct connection *c,
				      lset_t policy);

extern void ikev2_derive_child_keys(struct state *st,
				    enum phase1_role role);

extern struct traffic_selector ikev2_end_to_ts(struct end *e);

extern int ikev2_evaluate_connection_fit(struct connection *d,
					 struct spd_route *sr,
					 enum phase1_role role,
					 struct traffic_selector *tsi,
					 struct traffic_selector *tsr,
					 unsigned int tsi_n,
					 unsigned int tsr_n);

extern int ikev2_evaluate_connection_port_fit(struct connection *d,
					      struct spd_route *sr,
					      enum phase1_role role,
					      struct traffic_selector *tsi,
					      struct traffic_selector *tsr,
					      unsigned int tsi_n,
					      unsigned int tsr_n,
					      unsigned int *best_tsi_i,
					      unsigned int *best_tsr_i);

extern stf_status ikev2_calc_emit_ts(struct msg_digest *md,
				     pb_stream *outpbs,
				     enum phase1_role role,
				     struct connection *c0,
				     lset_t policy);

extern int ikev2_parse_ts(struct payload_digest *ts_pd,
			  struct traffic_selector *array,
			  unsigned int array_max);

extern int ikev2_evaluate_connection_protocol_fit(struct connection *d,
						  struct spd_route *sr,
						  enum phase1_role role,
						  struct traffic_selector *tsi,
						  struct traffic_selector *tsr,
						  unsigned int tsi_n,
						  unsigned int tsr_n,
						  unsigned int *best_tsi_i,
						  unsigned int *best_tsr_i);

extern stf_status ikev2_child_sa_respond(struct msg_digest *md,
					 enum phase1_role role,
					 pb_stream *outpbs);

extern void ikev2_update_counters(struct msg_digest *md);
extern void ikev2_print_ts(struct traffic_selector *ts);

extern void send_v2_notification(struct state *p1st,
				 v2_notification_t type,
				 struct state *encst,
				 u_char *icookie,
				 u_char *rcookie,
				 chunk_t *data);

extern bool doi_send_ikev2_cert_thinking(struct state *st);

extern stf_status ikev2_send_cert(struct state *st,
				  struct msg_digest *md,
				  enum phase1_role role,
				  enum next_payload_types_ikev2 np,
				  pb_stream *outpbs);

extern bool ship_v2N(enum next_payload_types_ikev2 np,
		     u_int8_t critical,
		     u_int8_t protoid,
		     const chunk_t *spi,
		     v2_notification_t type,
		     const chunk_t *n_data, pb_stream *rbody);

extern bool force_busy;	/* config option to emulate responder under DOS */

extern time_t ikev2_replace_delay(struct state *st, enum event_type *pkind,
				  enum phase1_role role);
