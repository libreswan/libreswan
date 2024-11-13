#ifndef _IKEV1_H
#define _IKEV1_H

#include "ikev1_continuations.h"
#include "fd.h"
#include "crypt_mac.h"

struct child_proposals;
struct ike_proposals;

/* ikev1.c */

const struct dh_desc *ikev1_quick_pfs(const struct child_proposals proposals);

void ikev1_init_pbs_out_from_md_hdr(struct msg_digest *md, bool enc,
				    struct pbs_out *output_stream,
				    uint8_t *output_buffer, size_t sizeof_output_buffer,
				    struct pbs_out *rbody, struct logger *logger);

extern void complete_v1_state_transition(struct state *st,
					 struct msg_digest *md,
					 stf_status result);

extern void process_v1_packet(struct msg_digest *md);

/*
 * IKEv1 functions: that ikev1_main.c provides and ikev1_aggr.c
 * needs.
 */

/* continue with encrypted packet */
extern void process_packet_tail(struct msg_digest *md);

/* **MAIN MODE FUNCTIONS** in ikev1_main.c */

extern struct ike_sa *main_outI1(struct connection *c,
				 struct ike_sa *predecessor,
				 const struct child_policy *policy,
				 const threadtime_t *inception,
				 bool background);

extern struct ike_sa *aggr_outI1(struct connection *c,
				 struct ike_sa *predecessor,
				 const struct child_policy *policy,
				 const threadtime_t *inception,
				 bool background);

struct hash_signature v1_sign_hash_RSA(const struct connection *c,
				       const struct crypt_mac *hash,
				       struct logger *logger);

struct crypt_mac main_mode_hash(struct ike_sa *ike,
				enum sa_role role,
				shunk_t id_payload);  /* ID payload, including header */

void doi_log_cert_thinking(uint16_t auth,
			   enum ike_cert_type certtype,
			   enum certpolicy policy,
			   bool gotcertrequest,
			   bool send_cert,
			   bool send_chain);

/* Parent capable of sending messages.  */
struct ike_sa *established_isakmp_sa_for_state(struct state *st, bool viable_parent);

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
extern ikev1_state_transition_fn unexpected;
extern ikev1_state_transition_fn informational;

void ISAKMP_SA_established(struct ike_sa *ike);

struct ike_sa *find_v1_isakmp_sa(const ike_spis_t *ipe_spis);

extern struct pbs_out reply_stream;

#endif
