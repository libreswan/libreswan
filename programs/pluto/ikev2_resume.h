#ifndef IKEV2_RESUME_H
#define IKEV2_RESUME_H

#include <stdbool.h>

#include "state.h"
#include "packet.h"
#include "deltatime.h"
#include "connections.h"

/* made up - fixup to actual known max later */
#define MAX_SK_d_LEN  256

struct ticket_by_val {

	unsigned long sr_serialco;
	id_buf peer_id;

	/* Reference to sk_d_old */
	char sk_d_old[MAX_SK_d_LEN];
	int sk_d_old_len;

	/* All the chosen Algorithm Description */
	int sr_encr;
	int sr_prf;
	int sr_integ;
	int sr_dh;
	int sr_enc_keylen;

	enum keyword_authby sr_auth_method;

};

/* 
 * forms a ticket chunk.
 * assign state's member varibles to ticket's
 */
chunk_t st_to_ticket(const struct state *st);

/*
 * Emit IKEv2 Notify TICKET_LT_OPAQUE payload.
 *
 * @param *st struct state
 * @param pbs output stream
 */
extern bool emit_ticket_lt_opaque_notification(struct state *st, pb_stream *pbs);

/*
 * Emit IKEv2 Notify TICKET_OPAQUE payload.
 *
 * @param *ticket chunk_t stored encrypted ticket chunk at the client side
 * @param pbs output stream
 */
extern bool emit_ticket_opaque_notification(chunk_t ticket, pb_stream *pbs);

void suspend_connection(struct connection *c);
bool set_ikev2_accepted_proposal(struct ike_sa *ike, int enc_keylen,
								  int encr, int prf, int integ, int dh);
bool decrypt_ticket(pb_stream *pbs, size_t len, struct ike_sa *ike);

extern void ikev2_session_resume_outI1(struct fd *whack_sock,
				       struct connection *c,
				       struct state *predecessor UNUSED,
				       lset_t policy,
				       unsigned long try,
				       const threadtime_t *inception UNUSED,
				       struct xfrm_user_sec_ctx_ike *uctx UNUSED);

#endif
