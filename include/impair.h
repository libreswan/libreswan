/* impair operation, for libreswan
 *
 * Copyright (C) 2018-2020 Andrew Cagney
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#ifndef IMPAIR_H
#define IMPAIR_H

#include <stdbool.h>

#include "lswcdefs.h"

struct fd;
struct logger;
struct jambuf;
struct whack_impair;

/*
 * Meddle with the contents of a payload.
 */

enum impair_emit {
	IMPAIR_EMIT_NO = 0,
	IMPAIR_EMIT_OMIT,
	IMPAIR_EMIT_EMPTY,
	IMPAIR_EMIT_DUPLICATE,
#define IMPAIR_EMIT_ROOF (IMPAIR_EMIT_DUPLICATE+1) /* >= ROOF -> <number> */
};

/*
 * Meddle with a specific exchange.
 */

enum impair_v1_exchange {
	IMPAIR_v1_EXCHANGE_NO = 0,
	IMPAIR_v1_NOTIFICATION_EXCHANGE,
	IMPAIR_v1_QUICK_EXCHANGE,
	IMPAIR_v1_XAUTH_EXCHANGE,
	IMPAIR_v1_DELETE_EXCHANGE,
};

/*
 * Meddle with an (IKEv2) transform.
 */

enum impair_v2_transform {
	IMPAIR_v2_TRANSFORM_NO = 0,
	IMPAIR_v2_TRANSFORM_ALLOW_NONE,
	IMPAIR_v2_TRANSFORM_DROP_NONE,
	IMPAIR_v2_TRANSFORM_OMIT,
};

struct impair_unsigned {
	bool enabled;
	unsigned value;
};

/*
 * What can be impaired.
 *
 * See impair.c for documentation.
 *
 * XXX: make this a structure so it can be copied?
 */

struct impair {

	bool revival;
	bool emitting;

	/*
	 * IKEv1: the key-length attribute is at the same level as
	 * other attributes such as encryption.  Just need to know if
	 * the IKE, or CHILD proposal set should be manipulated.
	 *
	 * IKEv2: the key-length attribute is nested within an
	 * encryption transform.  Hence, also need to know which
	 * transform to screw with.
	 */

	enum impair_emit ke_payload;
	enum impair_emit ike_key_length_attribute;
	enum impair_emit child_key_length_attribute;

	struct impair_unsigned log_rate_limit;

	enum impair_emit v1_hash_payload;
	enum impair_v1_exchange v1_hash_exchange;
	bool v1_hash_check;

	struct impair_unsigned ike_initiator_spi;
	struct impair_unsigned ike_responder_spi;

	bool bust_mi2;
	bool bust_mr2;
	bool drop_i2;
	bool jacob_two_two;
	bool allow_null_none;
	bool major_version_bump;
	bool minor_version_bump;
	bool timeout_on_retransmit;
	bool suppress_retransmits;
	bool send_bogus_payload_flag;
	bool send_bogus_isakmp_flag;
	bool send_no_delete;
	bool send_no_ikev2_auth;
	bool send_no_xauth_r0;
	bool send_no_idr;
	bool drop_xauth_r0;
	bool send_no_main_r2;
	bool force_fips;
	bool send_key_size_check;
	bool send_bogus_dcookie;

	bool childless_ikev2_supported;

	enum impair_v2_transform v2_proposal_integ;
	enum impair_v2_transform v2_proposal_dh;

	struct impair_unsigned ikev2_add_ike_transform;
	struct impair_unsigned ikev2_add_child_transform;

	bool replay_encrypted;
	bool corrupt_encrypted;
	bool proposal_parser;

	bool allow_dns_insecure;
	bool send_pkcs7_thingie;
	bool send_nonzero_reserved;
	bool send_nonzero_reserved_id;
	bool ikev1_del_with_notify;
	bool bad_ike_auth_xchg;
	bool rekey_initiate_supernet;
	bool rekey_initiate_subnet;
	bool rekey_respond_supernet;
	bool rekey_respond_subnet;

	bool tcp_use_blocking_write;
	bool tcp_skip_setsockopt_espintcp;

	struct impair_unsigned add_unknown_v2_payload_to;
	struct impair_unsigned add_unknown_v2_payload_to_sk;
	bool unknown_v2_payload_critical;

	struct impair_unsigned force_v2_auth_method;

	struct impair_unsigned add_v2_notification;
	struct impair_unsigned ignore_v2_notification;
	struct impair_unsigned omit_v2_notification;

	bool omit_v2_ike_auth_child;
	bool ignore_v2_ike_auth_child;

	bool event_check_crls;
	bool ignore_soft_expire;
	bool ignore_hard_expire;

	bool cannot_ondemand;

	struct impair_unsigned number_of_TSi_selectors;
	struct impair_unsigned number_of_TSr_selectors;

	bool lifetime;

	bool copy_v1_notify_response_SPIs_to_retransmission;

	struct impair_unsigned v1_remote_quick_id;
	struct impair_unsigned v1_emit_quick_id;

	enum impair_emit v1_isakmp_delete_payload;
	enum impair_emit v1_ipsec_delete_payload;

	struct impair_unsigned v2_delete_protoid;
	struct impair_unsigned v2n_rekey_sa_protoid;
	struct impair_unsigned v2_proposal_protoid;

	struct impair_unsigned helper_thread_delay;

	bool install_ipsec_sa_inbound_state;
	bool install_ipsec_sa_inbound_policy;
	bool install_ipsec_sa_outbound_state;
	bool install_ipsec_sa_outbound_policy;

	bool record_inbound;
	bool record_outbound;

	/*
	 * add more here
	 */

};

extern struct impair impair;

enum impair_status {
	IMPAIR_OK = 1,
	IMPAIR_HELP,
	IMPAIR_ERROR,
};

enum impair_status parse_impair(const char *optarg,
				struct whack_impair *whack_impair,
				bool enable, struct logger *logger);

enum impair_message_direction {
	IMPAIR_INBOUND_MESSAGE,
	IMPAIR_OUTBOUND_MESSAGE,
};

enum impair_action {
	CALL_IMPAIR_UPDATE,

	CALL_INITIATE_v2_LIVENESS,
	CALL_SEND_KEEPALIVE,

	CALL_GLOBAL_EVENT_HANDLER,
	CALL_STATE_EVENT_HANDLER,
	CALL_CONNECTION_EVENT_HANDLER,

	CALL_IMPAIR_MESSAGE_DROP,
	CALL_IMPAIR_MESSAGE_BLOCK,
	CALL_IMPAIR_MESSAGE_DRIP,
	CALL_IMPAIR_MESSAGE_DUPLICATE,
	CALL_IMPAIR_MESSAGE_REPLAY,

#if 0
	CALL_IMPAIR_CORRUPT_INBOUND,
	CALL_IMPAIR_CORRUPT_OUTBOUND,
#endif
};

bool process_impair(const struct whack_impair *whack_impair,
		    void (*action)(enum impair_action impairment_action,
				   unsigned impairment_param,
				   bool whack_enable,
				   unsigned whack_value,
				   bool background,
				   struct logger *logger),
		    bool background, struct logger *logger);

bool have_impairments(void);
void jam_impairments(struct jambuf *buf, const char *sep);

#endif
