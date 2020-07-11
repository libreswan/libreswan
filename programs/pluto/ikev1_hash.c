/* IKEv1 HASH payload weirdness, for Libreswan
 *
 * Copyright (C) 2019  Andrew Cagney
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

#include "ikev1_hash.h"

#include "state.h"
#include "crypt_prf.h"
#include "ike_alg.h"
#include "lswlog.h"
#include "demux.h"
#include "impair.h"

bool emit_v1_HASH(enum v1_hash_type hash_type, const char *what,
		  enum impair_v1_exchange exchange,
		  struct state *st, struct v1_hash_fixup *fixup,
		  pb_stream *rbody)
{
	zero(fixup);
	fixup->what = what;
	fixup->hash_type = hash_type;
	fixup->impair = (impair.v1_hash_exchange == exchange
			 ? impair.v1_hash_payload : IMPAIR_EMIT_NO);
	if (fixup->impair == IMPAIR_EMIT_OMIT) {
		libreswan_log("IMPAIR: omitting HASH payload for %s", what);
		return true;
	}
	pb_stream hash_pbs;
	if (!ikev1_out_generic(&isakmp_hash_desc, rbody, &hash_pbs)) {
		return false;
	}
	if (fixup->impair == IMPAIR_EMIT_EMPTY) {
		libreswan_log("IMPAIR: sending HASH payload with no data for %s", what);
	} else {
		/* reserve space for HASH data */
		fixup->hash_data = chunk2(hash_pbs.cur, st->st_oakley.ta_prf->prf_output_size);
		if (!out_zero(fixup->hash_data.len, &hash_pbs, "HASH DATA"))
			return false;
	}
	close_output_pbs(&hash_pbs);
	/* save start of rest of message for later */
	fixup->body = rbody->cur;
	return true;
}

void fixup_v1_HASH(struct state *st, const struct v1_hash_fixup *fixup,
		   msgid_t msgid, const uint8_t *roof)
{
	if (fixup->impair >= IMPAIR_EMIT_ROOF) {
		libreswan_log("IMPAIR: setting HASH payload bytes to %02x",
			      fixup->impair - IMPAIR_EMIT_ROOF);
		/* chunk_fill()? */
		memset(fixup->hash_data.ptr, fixup->impair - IMPAIR_EMIT_ROOF,
		       fixup->hash_data.len);
		return;
	} else if (fixup->impair != IMPAIR_EMIT_NO) {
		/* already logged above? */
		return;
	}
	struct crypt_prf *hash =
		crypt_prf_init_symkey("HASH(1)", st->st_oakley.ta_prf,
				      "SKEYID_a", st->st_skeyid_a_nss);
	/* msgid */
	passert(sizeof(msgid_t) == sizeof(uint32_t));
	msgid_t raw_msgid = htonl(msgid);
	switch (fixup->hash_type) {
	case V1_HASH_1:
		/* HASH(1) = prf(SKEYID_a, M-ID | payload ) */
		crypt_prf_update_thing(hash, "M-ID", raw_msgid);
		crypt_prf_update_bytes(hash, "payload",
				       fixup->body, roof - fixup->body);
		break;
	case V1_HASH_2:
		/* HASH(2) = prf(SKEYID_a, M-ID | Ni_b | payload ) */
		crypt_prf_update_thing(hash, "M-ID", raw_msgid);
		crypt_prf_update_hunk(hash, "Ni_b", st->st_ni);
		crypt_prf_update_bytes(hash, "payload",
				       fixup->body, roof - fixup->body);
		break;
	case V1_HASH_3:
		/* HASH(3) = prf(SKEYID_a, 0 | M-ID | Ni_b | Nr_b) */
		crypt_prf_update_byte(hash, "0", 0);
		crypt_prf_update_thing(hash, "M-ID", raw_msgid);
		crypt_prf_update_hunk(hash, "Ni_b", st->st_ni);
		crypt_prf_update_hunk(hash, "Nr_b", st->st_nr);
		break;
	default:
		bad_case(fixup->hash_type);
	}
	/* stuff result into hash_data */
	passert(fixup->hash_data.len == st->st_oakley.ta_prf->prf_output_size);
	crypt_prf_final_bytes(&hash, fixup->hash_data.ptr, fixup->hash_data.len);
	if (DBGP(DBG_BASE)) {
		DBG_log("%s HASH(%u):", fixup->what, fixup->hash_type);
		DBG_dump_hunk(NULL, fixup->hash_data);
	}
}

bool check_v1_HASH(enum v1_hash_type type, const char *what,
		   struct state *st, struct msg_digest *md)
{
	if (type == V1_HASH_NONE) {
		dbg("message '%s' HASH payload not checked early", what);
		return true;
	}
	if (impair.v1_hash_check) {
		libreswan_log("IMPAIR: skipping check of '%s' HASH payload", what);
		return true;
	}
	if (md->hdr.isa_np != ISAKMP_NEXT_HASH) {
		loglog(RC_LOG_SERIOUS, "received '%s' message is missing a HASH(%u) payload",
		       what, type);
		return false;
	}
	pb_stream *hash_pbs = &md->chain[ISAKMP_NEXT_HASH]->pbs;
	shunk_t received_hash = pbs_in_left_as_shunk(hash_pbs);
	if (received_hash.len != st->st_oakley.ta_prf->prf_output_size) {
		loglog(RC_LOG_SERIOUS,
		       "received '%s' message HASH(%u) data is the wrong length (received %zd bytes but expected %zd)",
		       what, type, received_hash.len, st->st_oakley.ta_prf->prf_output_size);
		return false;
	}
	/*
	 * Create a fixup pointing at COMPUTED_HASH so that
	 * fixup_v1_HASH() will fill it in.
	 */
	struct crypt_mac computed_hash = {
		.len = st->st_oakley.ta_prf->prf_output_size,
	};
	struct v1_hash_fixup expected = {
		.hash_data = chunk2(computed_hash.ptr, computed_hash.len),
		.body = received_hash.ptr + received_hash.len,
		.what = what,
		.hash_type = type,
	};
	fixup_v1_HASH(st, &expected, md->hdr.isa_msgid, md->message_pbs.roof);
	/* does it match? */
	if (!hunk_eq(received_hash, computed_hash)) {
		if (DBGP(DBG_BASE)) {
			DBG_log("received %s HASH_DATA:", what);
			DBG_dump_hunk(NULL, received_hash);
		}
		loglog(RC_LOG_SERIOUS,
		       "received '%s' message HASH(%u) data does not match computed value",
		       what, type);
		return false;
	}
	dbg("received '%s' message HASH(%u) data ok", what, type);
	return true;
}
