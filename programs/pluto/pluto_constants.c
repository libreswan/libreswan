/* tables of names for values defined in constants.h
 *
 * Copyright (C) 1998-2002,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2020 Yulia Kuzovkova <ukuzovkova@gmail.com>
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

/*
 * Note that the array sizes are all specified; this is to enable range
 * checking by code that only includes constants.h.
 */

#include "passert.h"

#include "jambuf.h"
#include "constants.h"
#include "enum_names.h"
#include "defs.h"
#include "kernel.h"

/*
 * To obsolete or convert to runtime options:
 * NOTYET
 * NOT_YET
 * PFKEY
 * PLUTO_GROUP_CTL
 * SOFTREMOTE_CLIENT_WORKAROUND
 * USE_3DES USE_AES USE_MD5 USE_SHA1 USE_SHA2
 */

/* enum kernel_policy_op_names */

static const char *kernel_policy_op_name[] = {
#define S(E) [E] = #E
	S(KERNEL_POLICY_OP_ADD),
	S(KERNEL_POLICY_OP_REPLACE),
#undef S
};

enum_names kernel_policy_op_names = {
	0, elemsof(kernel_policy_op_name)-1,
	ARRAY_REF(kernel_policy_op_name),
	.en_prefix = "KERNEL_POLICY_OP_",
};

/* enum direction_names */

static const char *direction_name[] = {
#define S(E) [E-DIRECTION_INBOUND] = #E
	S(DIRECTION_OUTBOUND),
	S(DIRECTION_INBOUND),
#undef S
};

enum_names direction_names = {
	DIRECTION_INBOUND,
	DIRECTION_OUTBOUND,
	ARRAY_REF(direction_name),
	.en_prefix = "DIRECTION_",
};

/* */

/* print a policy: like bitnamesof, but it also does the non-bitfields.
 * Suppress the shunt and fail fields if 0.
 */

size_t jam_policy(struct jambuf *buf, lset_t policy)
{
	size_t s = 0;

	if (policy != LEMPTY) {
		s += jam_lset_short(buf, &sa_policy_bit_names, "+", policy);
	}
	return s;
}

const char *str_policy(lset_t policy, policy_buf *dst)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(dst->buf);
	jam_policy(&buf, policy);
	return dst->buf;
}

static const enum_names *pluto_enum_names_checklist[] = {
	&sd_action_names,
	&natt_method_names,
	&routing_tails,
	&routing_names,
	&stf_status_names,
	&perspective_names,
	&sa_policy_bit_names,
	&kernel_policy_op_names,
	&direction_names,
	&shunt_kind_names,
	&shunt_policy_names,
	&keyword_auth_names,
	&keyword_host_names,
	NULL,
};

void init_pluto_constants(void) {
	check_enum_names(pluto_enum_names_checklist);
}
