/* Process IKE_SA_INIT payload, for libreswan
 *
 * Copyright (C) 2017-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2018 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2020 Yulia Kuzovkova <ukuzovkova@gmail.com>
 */

#ifndef IKEV2_IKE_SA_INIT_H
#define IKEV2_IKE_SA_INIT_H

#include "ikev2.h"		/* for ikev2_state_transition_fn */

struct msg_digest;
struct ike_sa;

void process_v2_IKE_SA_INIT(struct msg_digest *md);

struct ike_sa *initiate_v2_IKE_SA_INIT_request(struct connection *c,
					       struct state *predecessor,
					       lset_t policy,
					       const threadtime_t *inception,
					       shunk_t sec_label,
					       bool background);

extern ikev2_state_transition_fn process_v2_IKE_SA_INIT_request;
extern ikev2_state_transition_fn process_v2_IKE_SA_INIT_response_v2N_INVALID_KE_PAYLOAD;

bool record_v2_IKE_SA_INIT_request(struct ike_sa *ike);

void llog_v2_IKE_SA_INIT_success(struct ike_sa *ike);

#endif
