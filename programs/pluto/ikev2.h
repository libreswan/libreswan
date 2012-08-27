/*
 * IKEv2 functions: that ikev2_parent.c/ikev2_child.c needs.
 *
 */
extern stf_status ikev2parent_outI1(int whack_sock
				    , struct connection *c
				    , struct state *predecessor
				    , lset_t policy
				    , unsigned long try
				    , enum crypto_importance importance
#ifdef HAVE_LABELED_IPSEC
				    , struct xfrm_user_sec_ctx_ike * uctx
#endif
				    );



extern void ikev2_delete_out(struct state *st);

bool ikev2_out_attr(int type
        , unsigned long val
        , struct_desc *attr_desc
        , enum_names **attr_val_descs USED_BY_DEBUG
        , pb_stream *pbs);

extern bool ikev2_out_sa(pb_stream *outs
			 , unsigned int protoid
			 , struct db_sa *sadb
			 , struct state *st
			 , bool parentSA
			 , u_int8_t np);

extern void complete_v2_state_transition(struct msg_digest **mdp
					 , stf_status result);

extern stf_status process_informational_ikev2(struct msg_digest *md);
extern stf_status ikev2parent_inI1outR1(struct msg_digest *md);
extern stf_status ikev2parent_inR1(struct msg_digest *md);
extern stf_status ikev2parent_inR1outI2(struct msg_digest *md);
extern stf_status ikev2parent_inI2outR2(struct msg_digest *md);
extern stf_status ikev2parent_inR2(struct msg_digest *md);

extern const struct state_v2_microcode *ikev2_parent_firststate(void);

extern v2_notification_t accept_v2_nonce(struct msg_digest *md, chunk_t *dest
				      , const char *name);

/* MAGIC: perform f, a function that returns v2_notification_t
 * and return from the ENCLOSING stf_status returning function if it fails.
 */
#define RETURN_STF_FAILURE2(f, xf)					\
    { int r = (f); if (r != NOTHING_WRONG) { \
	  if((xf)!=NULL) pfree(xf);	     \
	  return STF_FAIL + r; }}

#define RETURN_STF_FAILURE(f) RETURN_STF_FAILURE2(f, NULL)

extern v2_notification_t ikev2_parse_parent_sa_body(
	pb_stream *sa_pbs,              /* body of input SA Payload */
	const struct ikev2_sa *sa_prop UNUSED, /* header of input SA Payload */
	pb_stream *r_sa_pbs,	    /* if non-NULL, where to emit winning SA */
	struct state *st,  	            /* current state object */
	bool selection                 /* if this SA is a selection, only one 
					* tranform can appear. */
	);

extern v2_notification_t ikev2_parse_child_sa_body(
	pb_stream *sa_pbs,              /* body of input SA Payload */
	const struct ikev2_sa *sa_prop UNUSED, /* header of input SA Payload */
	pb_stream *r_sa_pbs,	    /* if non-NULL, where to emit winning SA */
	struct state *st,  	            /* current state object */
	bool selection                 /* if this SA is a selection, only one 
					* tranform can appear. */
	);

#if 0
extern v2_notification_t parse_ikev2_sa_body(pb_stream *sa_pbs
					  , const struct ikev2_sa *sa
					  , pb_stream *r_sa_pbs
					  , struct state *st
					  , bool selection
					  , bool parentSA);
#endif

extern void send_v2_notification_from_state(struct state *st
					    , enum state_kind state
					    , u_int16_t type, chunk_t *data);

extern void send_v2_notification_from_md(struct msg_digest *md,u_int16_t type
   					 , chunk_t *data);
extern stf_status ikev2_process_payloads(struct msg_digest *md,
					 pb_stream   *in_pbs,
					 unsigned int from_state,
					 unsigned int np);

extern bool ikev2_decode_peer_id(struct msg_digest *md
				 , enum phase1_role initiator);
extern void ikev2_log_parentSA(struct state *st);

extern bool ikev2_calculate_rsa_sha1(struct state *st
				     , enum phase1_role role
				     , unsigned char *idhash
				     , pb_stream *a_pbs);

extern bool ikev2_calculate_psk_auth(struct state *st
				     , enum phase1_role role
				     , unsigned char *idhash
				     , pb_stream *a_pbs);

extern stf_status ikev2_verify_rsa_sha1(struct state *st
					, enum phase1_role role
				   , unsigned char *idhash
				   , const struct pubkey_list *keys_from_dns
				   , const struct gw_info *gateways_from_dns
				   , pb_stream *sig_pbs);

extern stf_status ikev2_verify_psk_auth(struct state *st
					, enum phase1_role role
				   , unsigned char *idhash
				   , pb_stream *sig_pbs);

extern stf_status ikev2_emit_ipsec_sa(struct msg_digest *md
				      , pb_stream *outpbs
				      , unsigned int np
				      , struct connection *c
				      , lset_t policy);

extern void ikev2_derive_child_keys(struct state *st
				    , enum phase1_role role);

extern struct traffic_selector ikev2_end_to_ts(struct end *e);
extern int ikev2_evaluate_connection_fit(struct connection *d
				, struct spd_route *sr
				, enum phase1_role role
				, struct traffic_selector *tsi
				, struct traffic_selector *tsr
				, unsigned int tsi_n
				, unsigned int tsr_n);

extern int ikev2_evaluate_connection_port_fit(struct connection *d
				, struct spd_route *sr
				, enum phase1_role role
				, struct traffic_selector *tsi
				, struct traffic_selector *tsr
				, unsigned int tsi_n
				, unsigned int tsr_n
				, unsigned int *best_tsi_i
				, unsigned int *best_tsr_i);

extern stf_status ikev2_emit_ts(struct msg_digest *md 
				, pb_stream *outpbs   
				, unsigned int np
				, struct traffic_selector *ts
				, enum phase1_role role);

extern stf_status ikev2_calc_emit_ts(struct msg_digest *md
				, pb_stream *outpbs
				, enum phase1_role role
				, struct connection *c0
				, lset_t policy);

extern int ikev2_parse_ts(struct payload_digest *ts_pd
				, struct traffic_selector *array
				, unsigned int array_max);

extern int ikev2_evaluate_connection_protocol_fit(struct connection *d
				, struct spd_route *sr
				, enum phase1_role role
				, struct traffic_selector *tsi
				, struct traffic_selector *tsr
				, unsigned int tsi_n
				, unsigned int tsr_n
				, unsigned int *best_tsi_i
				, unsigned int *best_tsr_i);

extern stf_status ikev2_child_sa_respond(struct msg_digest *md
					 , enum phase1_role role
					 , pb_stream *outpbs);

extern struct traffic_selector ikev2_end_to_ts(struct end *e);
extern void ikev2_update_counters(struct msg_digest *md);
extern void ikev2_print_ts(struct traffic_selector *ts);


extern void send_v2_notification(struct state *p1st, u_int16_t type
				 , struct state *encst 
				 , u_char *icookie
				 , u_char *rcookie
				 , chunk_t *data);

extern bool doi_send_ikev2_cert_thinking( struct state *st);

extern stf_status ikev2_send_cert( struct state *st
				   , struct msg_digest *md
				   , enum phase1_role role
				   , unsigned int np
				   , pb_stream *outpbs);
extern bool ship_v2N (unsigned int np, u_int8_t  critical,
				    u_int8_t protoid, chunk_t *spi, 
					u_int16_t type, chunk_t *n_data, pb_stream *rbody);

extern bool force_busy;  /* config option to emulate responder under DOS */

