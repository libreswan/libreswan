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

/*
 * Meddle with the contents of a payload.
 */

enum send_impairment {
	SEND_NORMAL = 0,
	SEND_OMIT,
	SEND_EMPTY,
	SEND_DUPLICATE,
	SEND_ROOF, /* >= ROOF -> <number> */
};

/*
 * Meddle with a specific exchange.
 */

enum exchange_impairment {
	NO_EXCHANGE = 0,
	NOTIFICATION_EXCHANGE,
	QUICK_EXCHANGE,
	XAUTH_EXCHANGE,
	DELETE_EXCHANGE,
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

	enum send_impairment ke_payload;
	enum send_impairment ike_key_length_attribute;
	enum send_impairment child_key_length_attribute;

	unsigned log_rate_limit;

	enum send_impairment v1_hash_payload;
	enum exchange_impairment v1_hash_exchange;
	bool v1_hash_check;

	unsigned ike_initiator_spi;
	unsigned ike_responder_spi;

	/*
	 * add more here
	 */

	/*
	 * HACK to keep code using IMPAIR() compiling without a
	 * massive rename.
	 */

#define IMPAIR(BEHAVIOUR) (impair.BEHAVIOUR)
	bool BUST_MI2;
	bool BUST_MR2;
	bool DROP_I2;
	bool SA_CREATION;
	bool JACOB_TWO_TWO;
	bool ALLOW_NULL_NONE;
	bool MAJOR_VERSION_BUMP;
	bool MINOR_VERSION_BUMP;
	bool TIMEOUT_ON_RETRANSMIT;
	bool DELETE_ON_RETRANSMIT;
	bool SUPPRESS_RETRANSMITS;
	bool SEND_BOGUS_PAYLOAD_FLAG;
	bool SEND_BOGUS_ISAKMP_FLAG;
	bool SEND_NO_DELETE;
	bool SEND_NO_IKEV2_AUTH;
	bool SEND_NO_XAUTH_R0;
	bool DROP_XAUTH_R0;
	bool SEND_NO_MAIN_R2;
	bool FORCE_FIPS;
	bool SEND_KEY_SIZE_CHECK;
	bool SEND_BOGUS_DCOOKIE;
	bool OMIT_HASH_NOTIFY_REQUEST;
	bool IGNORE_HASH_NOTIFY_REQUEST;
	bool IGNORE_HASH_NOTIFY_RESPONSE;
	bool IKEv2_EXCLUDE_INTEG_NONE;
	bool IKEv2_INCLUDE_INTEG_NONE;
	bool REPLAY_DUPLICATES;
	bool REPLAY_FORWARD;
	bool REPLAY_BACKWARD;
	bool REPLAY_ENCRYPTED;
	bool CORRUPT_ENCRYPTED;
	bool PROPOSAL_PARSER;
	bool ADD_UNKNOWN_PAYLOAD_TO_SA_INIT;
	bool ADD_UNKNOWN_PAYLOAD_TO_AUTH;
	bool ADD_UNKNOWN_PAYLOAD_TO_AUTH_SK;
	bool UNKNOWN_PAYLOAD_CRITICAL;
	bool ALLOW_DNS_INSECURE;
	bool SEND_PKCS7_THINGIE;
	bool IKEv1_DEL_WITH_NOTIFY;
	bool BAD_IKE_AUTH_XCHG;
};

extern struct impair impair;

/*
 * What whack sends across the wire for a impair.
 */

struct whack_impair {
	unsigned what;
	unsigned how;
};

bool parse_impair(const char *optarg, struct whack_impair *whack_impair, bool enable);

void process_impair(const struct whack_impair *whack_impair);

void help_impair(const char *prefix);

bool have_impairments(void);
void jam_impairments(jambuf_t *buf, const char *sep);

#endif
