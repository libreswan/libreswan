/* IKEv2 message routines, for Libreswan
 *
 * Copyright (C) 2018 Andrew Cagney
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
 */

#ifndef IKEV2_MESSAGE_H
#define IKEV2_MESSAGE_H

#include "chunk.h"

#include "message_role.h"
#include "packet.h"		/* for struct pbs_out; */

struct msg_digest;
struct dh_desc;
struct ike_sa;
struct state;
struct spd_end;
struct host_end;
struct v2_incoming_fragments;

/*
 * Outgoing messages.
 */

struct v2SK_payload {
	/* public */
	struct logger *logger;
	struct ike_sa *ike;
	struct pbs_out pbs; /* within SK */
	/* private */
	/* pointers into SK header+contents */
	chunk_t payload; /* aad+wire_iv+cleartext+padding+integrity */
	chunk_t aad;
	chunk_t wire_iv;
	chunk_t cleartext;
	chunk_t padding;
	chunk_t integrity;
};

bool encrypt_v2SK_payload(struct v2SK_payload *sk);

uint8_t build_ikev2_critical(bool impair, struct logger *logger);

enum payload_security {
	ENCRYPTED_PAYLOAD = 1,
	UNENCRYPTED_PAYLOAD,
};

struct v2_message {
	/* CONTAINS POINTERS to SELF; pass by ref */
	struct logger *logger;
	struct pbs_out *pbs; /* where to put message (POINTER!); either .BODY or .SK */
	/* internal fields */
	enum payload_security security;
	struct pbs_out message;
	struct pbs_out body;
	const char *story;
	struct v2_outgoing_fragment **outgoing_fragments;
	struct v2SK_payload sk; /* optional */
};

bool open_v2_message(const char *story,
		     struct ike_sa *ike, struct logger *logger,
		     struct msg_digest *request_md,
		     enum ikev2_exchange exchange_type,
		     uint8_t *buffer, size_t sizeof_buffer,
		     struct v2_message *message,
		     enum payload_security security);

bool close_v2_message(struct v2_message *message);

bool close_and_record_v2_message(struct v2_message *message);

/*
 * Incoming Message fragments.
 */

enum  collected_fragment {
	FRAGMENT_IGNORED,
	FRAGMENTS_MISSING,
	FRAGMENTS_COMPLETE,
};

enum collected_fragment collect_v2_incoming_fragment(struct ike_sa *ike,
						     struct msg_digest *md,
						     struct v2_incoming_fragments **frags);
bool decrypt_v2_incoming_fragments(struct ike_sa *ike,
				   struct v2_incoming_fragments **frags);
struct msg_digest *reassemble_v2_incoming_fragments(struct v2_incoming_fragments **frags);

bool ikev2_decrypt_msg(struct ike_sa *ike, struct msg_digest *md);

struct ikev2_id build_v2_id_payload(const struct host_end *end, shunk_t *body,
				    const char *what, struct logger *logger);

#endif
