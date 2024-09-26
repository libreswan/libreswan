/* Interface to the PF_KEY v2 IPsec mechanism, for Libreswan
 *
 * Copyright (C)  2022  Andrew Cagney
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

#include "kernel_sadb.h"

#include "lswlog.h"
#include "ip_protocol.h"
#include "ip_sockaddr.h"
#include "ip_info.h"
#include "verbose.h"

bool get_sadb_sockaddr_address_port(shunk_t *cursor,
				    ip_address *address,
				    ip_port *port,
				    struct verbose verbose)
{
	err_t err = sockaddr_to_address_port(cursor->ptr, cursor->len,
					     address, port);
	if (err != NULL) {
		llog_pexpect(verbose.logger, HERE, "invalid sockaddr: %s", err);
		return false;
	}
	const struct ip_info *afi = address_type(address);
	cursor->ptr += afi->sockaddr_size;
	cursor->len -= afi->sockaddr_size;
	return true;
}

const struct sadb_ext *get_sadb_ext(shunk_t *msgbase,
				    shunk_t *msgext,
				    struct verbose verbose)
{
	shunk_t tmp = *msgbase;
	const struct sadb_ext *ext =
		hunk_get_thing(&tmp, const struct sadb_ext);
	vassert(ext != NULL);

	size_t len = ext->sadb_ext_len * sizeof(uint64_t);
	if (len == 0) {
		llog_passert(verbose.logger, HERE,
			     "have zero bytes");
	}
	if (msgbase->len < len) {
		llog_passert(verbose.logger, HERE,
			     "have %zu bytes but should be %zu",
			     msgbase->len, len);
	}

	/* note: include EXT read above; will re-read */
	*msgext = shunk2(msgbase->ptr, len);

	/* then advance */
	msgbase->ptr += len;
	msgbase->len -= len;

	return ext;
}

/*
 * XXX: the x_ipsecrequest extension messed up the convention by
 * storing the nr-bytes in len.  Hence LEN_MULTIPLIER.
 */

#define GET_SADB(TYPE, LEN_MULTIPLIER) X_GET_SADB(TYPE, LEN_MULTIPLIER)
#define X_GET_SADB(TYPE, LEN_MULTIPLIER)				\
	const struct TYPE *get_##TYPE(shunk_t *cursor,			\
				      shunk_t *type_cursor,		\
				      struct verbose verbose)		\
	{								\
		*type_cursor = null_shunk;				\
		if (sizeof(struct TYPE) > cursor->len) {		\
			llog_pexpect(verbose.logger, HERE,		\
				     "%zu-byte buffer too small for %zu-byte "#TYPE, \
				     cursor->len, sizeof(struct TYPE));	\
			return NULL;					\
		}							\
		/* SADB stream is aligned */				\
		const struct TYPE *type = cursor->ptr;			\
		size_t type_len = type->TYPE##_len * LEN_MULTIPLIER;	\
		if (type_len < sizeof(struct TYPE)) {			\
			llog_pexpect(verbose.logger, HERE,		\
				     "%zu-byte "#TYPE" bigger than "#TYPE"_len=%u(%zu-bytes)", \
				     sizeof(struct TYPE), type->TYPE##_len, type_len); \
			return NULL;					\
		}							\
		if (type_len > (cursor)->len) {				\
			llog_pexpect(verbose.logger, HERE,		\
				     "%zu-byte buffer too small for "#TYPE"_len=%u(%zu-bytes)", \
				     cursor->len, type->TYPE##_len, type_len); \
			return NULL;					\
		}							\
		/* type_cursor */					\
		(type_cursor)->ptr = (cursor)->ptr + sizeof(struct TYPE); \
		(type_cursor)->len = type_len - sizeof(struct TYPE);	\
		/* now skip to next field */				\
		(cursor)->ptr += type_len;				\
		(cursor)->len -= type_len;				\
		return type;						\
	}

GET_SADB(sadb_address, sizeof(uint64_t));
GET_SADB(sadb_key, sizeof(uint64_t));
GET_SADB(sadb_lifetime, sizeof(uint64_t));
GET_SADB(sadb_msg, sizeof(uint64_t));
GET_SADB(sadb_prop, sizeof(uint64_t));
GET_SADB(sadb_sa, sizeof(uint64_t));
GET_SADB(sadb_spirange, sizeof(uint64_t));
GET_SADB(sadb_supported, sizeof(uint64_t));
#ifdef SADB_X_EXT_POLICY
GET_SADB(sadb_x_ipsecrequest, sizeof(uint8_t)); /* XXX: see rfc, screwup */
#endif
#ifdef SADB_X_EXT_NAT_T_TYPE
GET_SADB(sadb_x_nat_t_type, sizeof(uint64_t));
#endif
#ifdef SADB_X_EXT_POLICY
GET_SADB(sadb_x_policy, sizeof(uint64_t));
#endif
#ifdef SADB_X_EXT_SA2
GET_SADB(sadb_x_sa2, sizeof(uint64_t));
#endif
#ifdef SADB_X_EXT_SA_REPLAY
GET_SADB(sadb_x_sa_replay, sizeof(uint64_t));
#endif
#ifdef SADB_X_EXT_COUNTER
GET_SADB(sadb_x_counter, sizeof(uint64_t));
#endif
#ifdef SADB_X_EXT_PROTOCOL
GET_SADB(sadb_protocol, sizeof(uint64_t));
#endif
#ifdef SADB_X_EXT_REPLAY /* OpenBSD */
GET_SADB(sadb_x_replay, sizeof(uint64_t));
#endif
#ifdef SADB_X_EXT_UDPENCAP
GET_SADB(sadb_x_udpencap, sizeof(uint64_t));
#endif
