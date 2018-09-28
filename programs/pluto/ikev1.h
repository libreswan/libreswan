#ifndef _IKEV1_H
#define _IKEV1_H

#include "pluto_crypt.h"
#include "ikev1_continuations.h"
#include "packet.h"		/* for pb_stream */
#include "fd.h"

/* ikev1.c */

extern void init_ikev1(void);

const struct oakley_group_desc *ikev1_quick_pfs(struct alg_info_esp *aie);

void ikev1_init_out_pbs_echo_hdr(struct msg_digest *md, bool enc, uint8_t np,
				 pb_stream *output_stream, uint8_t *output_buffer,
				 size_t sizeof_output_buffer,
				 pb_stream *rbody);

extern void complete_v1_state_transition(struct msg_digest **mdp,
					 stf_status result);

extern void process_v1_packet(struct msg_digest **mdp);

/*
 * IKEv1 functions: that ikev1_main.c provides and ikev1_aggr.c
 * needs.
 */

/* continue with encrypted packet */
extern void process_packet_tail(struct msg_digest **mdp);

extern bool ikev1_justship_nonce(chunk_t *n,
			   pb_stream *outs, uint8_t np,
			   const char *name);

/* calls previous two routines */
extern bool ikev1_ship_nonce(chunk_t *n, struct pluto_crypto_req *r,
		       pb_stream *outs, uint8_t np,
		       const char *name);

extern notification_t accept_v1_nonce(struct msg_digest *md, chunk_t *dest,
				      const char *name);

extern bool ikev1_justship_KE(chunk_t *g,
			pb_stream *outs, uint8_t np);

/* just calls previous two routines now */
extern bool ikev1_ship_KE(struct state *st,
		    struct pluto_crypto_req *r,
		    chunk_t *g,
		    pb_stream *outs, uint8_t np);

/* **MAIN MODE FUNCTIONS** in ikev1_main.c */

/* extern initiator_function main_outI1; */
extern void main_outI1(fd_t whack_sock,
		       struct connection *c,
		       struct state *predecessor,
		       lset_t policy,
		       unsigned long try
#ifdef HAVE_LABELED_IPSEC
		       , struct xfrm_user_sec_ctx_ike *uctx
#endif
		       );

/* extern initiator_function aggr_outI1; */
extern void aggr_outI1(fd_t whack_sock,
		       struct connection *c,
		       struct state *predecessor,
		       lset_t policy,
		       unsigned long try
#ifdef HAVE_LABELED_IPSEC
		       , struct xfrm_user_sec_ctx_ike *uctx
#endif
		       );

extern void send_v1_delete(struct state *st);

/*
 * note: ikev1_decode_peer_id may change which connection is referenced by
 * md->st->st_connection.
 * But only if we are a Main Mode Responder.
 */
extern bool ikev1_decode_peer_id(struct msg_digest *md, bool initiator,
			   bool aggrmode);

extern size_t RSA_sign_hash(const struct connection *c,
			    u_char sig_val[RSA_MAX_OCTETS],
			    const u_char *hash_val, size_t hash_len,
			    enum notify_payload_hash_algorithms hash_algo);

extern size_t                           /* length of hash */
main_mode_hash(struct state *st,
	       u_char *hash_val,        /* resulting bytes */
	       bool hashi,              /* Initiator? */
	       const pb_stream *idpl);  /* ID payload, as PBS; cur must be at end */

/*
 * Note: oakley_id_and_auth may switch the connection being used!
 * But only if we are a Main Mode Responder.
 */
extern stf_status oakley_id_and_auth(struct msg_digest *md,
				     bool initiator,                    /* are we the Initiator? */
				     bool aggrmode);                     /* aggressive mode? */

extern bool ikev1_ship_chain(chunk_t *chain, int n, pb_stream *outs,
					     uint8_t type,
					     uint8_t setnp);

void doi_log_cert_thinking(uint16_t auth,
			   enum ike_cert_type certtype,
			   enum certpolicy policy,
			   bool gotcertrequest,
			   bool send_cert,
			   bool send_chain);

#if 0	/* not yet disentangled from spdb.h */
extern bool ikev1_out_sa(pb_stream *outs,
		const struct db_sa *sadb,
		struct state *st,
		bool oakley_mode,
		bool aggressive_mode,
		enum next_payload_types_ikev1 np);
#endif

bool ikev1_encrypt_message(pb_stream *pbs, struct state *st);
bool ikev1_close_message(pb_stream *pbs, const struct state *st);

typedef stf_status ikev1_state_transition_fn(struct state *st, struct msg_digest *md);

extern ikev1_state_transition_fn main_inI1_outR1;
extern ikev1_state_transition_fn main_inR1_outI2;
extern ikev1_state_transition_fn main_inI2_outR2;
extern ikev1_state_transition_fn main_inR2_outI3;
extern ikev1_state_transition_fn main_inI3_outR3;
extern ikev1_state_transition_fn main_inR3;
extern ikev1_state_transition_fn aggr_inI1_outR1;
extern ikev1_state_transition_fn aggr_inR1_outI2;
extern ikev1_state_transition_fn aggr_inI2;
extern ikev1_state_transition_fn quick_inI1_outR1;
extern ikev1_state_transition_fn quick_inR1_outI2;
extern ikev1_state_transition_fn quick_inI2;

#endif
