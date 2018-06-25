#ifndef _IKEV1_H
#define _IKEV1_H

#include "pluto_crypt.h"
#include "ikev1_continuations.h"

/* ikev1.c */

extern void init_ikev1(void);

const struct oakley_group_desc *ikev1_quick_pfs(struct alg_info_esp *aie);

void ikev1_init_out_pbs_echo_hdr(struct msg_digest *md, bool enc, u_int8_t np,
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
			   pb_stream *outs, u_int8_t np,
			   const char *name);

/* calls previous two routines */
extern bool ikev1_ship_nonce(chunk_t *n, struct pluto_crypto_req *r,
		       pb_stream *outs, u_int8_t np,
		       const char *name);

extern notification_t accept_v1_nonce(struct msg_digest *md, chunk_t *dest,
				      const char *name);

extern bool ikev1_justship_KE(chunk_t *g,
			pb_stream *outs, u_int8_t np);

/* just calls previous two routines now */
extern bool ikev1_ship_KE(struct state *st,
		    struct pluto_crypto_req *r,
		    chunk_t *g,
		    pb_stream *outs, u_int8_t np);

/* **MAIN MODE FUNCTIONS** in ikev1_main.c */

/* extern initiator_function main_outI1; */
extern void main_outI1(int whack_sock,
		       struct connection *c,
		       struct state *predecessor,
		       lset_t policy,
		       unsigned long try,
		       enum crypto_importance importance
#ifdef HAVE_LABELED_IPSEC
		       , struct xfrm_user_sec_ctx_ike *uctx
#endif
		       );

/* extern initiator_function aggr_outI1; */
extern void aggr_outI1(int whack_sock,
		       struct connection *c,
		       struct state *predecessor,
		       lset_t policy,
		       unsigned long try,
		       enum crypto_importance importance
#ifdef HAVE_LABELED_IPSEC
		       , struct xfrm_user_sec_ctx_ike *uctx
#endif
		       );

extern void send_v1_delete(struct state *st);

extern bool ikev1_decode_peer_id(struct msg_digest *md, bool initiator,
			   bool aggrmode);

extern size_t RSA_sign_hash(struct connection *c,
			    u_char sig_val[RSA_MAX_OCTETS],
			    const u_char *hash_val, size_t hash_len);

extern size_t                           /* length of hash */
main_mode_hash(struct state *st,
	       u_char *hash_val,        /* resulting bytes */
	       bool hashi,              /* Initiator? */
	       const pb_stream *idpl);  /* ID payload, as PBS; cur must be at end */

extern stf_status oakley_id_and_auth(struct msg_digest *md,
				     bool initiator,                    /* are we the Initiator? */
				     bool aggrmode);                     /* aggressive mode? */

static inline stf_status aggr_id_and_auth(struct msg_digest *md,
					  bool initiator)               /* are we the Initiator? */
{
	return oakley_id_and_auth(md, initiator, TRUE);
}

extern bool ikev1_ship_chain(chunk_t *chain, int n, pb_stream *outs,
					     u_int8_t type,
					     u_int8_t setnp);

void doi_log_cert_thinking(u_int16_t auth,
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
bool ikev1_close_message(pb_stream *pbs, struct state *st);

#endif
