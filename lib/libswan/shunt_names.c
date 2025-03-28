/*
 * tables of names for values defined in constants.h
 * Copyright (C) 2012-2017 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 1998-2002,2015  D. Hugh Redelmeier.
 * Copyright (C) 2016-2017 Andrew Cagney
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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
 */

#include "shunt.h"
#include "lswcdefs.h"		/* for ARRAY_REF() */
#include "enum_names.h"
#include "sparse_names.h"

static const char *const shunt_policy_name[] = {
#define S(E) [E - SHUNT_UNSET] = #E
	S(SHUNT_UNSET),
	S(SHUNT_IPSEC),
	S(SHUNT_HOLD),
	S(SHUNT_NONE),
	S(SHUNT_PASS),
	S(SHUNT_DROP),
	S(SHUNT_REJECT),
	S(SHUNT_TRAP),
#undef S
};

const struct enum_names shunt_policy_names = {
	SHUNT_UNSET, SHUNT_POLICY_ROOF-1,
	ARRAY_REF(shunt_policy_name),
	"SHUNT_", /* prefix */
	NULL,
};

static const char *const shunt_kind_name[] = {
#define S(E) [E - SHUNT_KIND_NONE] = #E
	S(SHUNT_KIND_NONE),
	S(SHUNT_KIND_NEVER_NEGOTIATE),
	S(SHUNT_KIND_ONDEMAND),
	S(SHUNT_KIND_NEGOTIATION),
	S(SHUNT_KIND_IPSEC),
	S(SHUNT_KIND_FAILURE),
	S(SHUNT_KIND_BLOCK),
#undef S
};

const struct enum_names shunt_kind_names = {
	0, SHUNT_KIND_ROOF-1,
	ARRAY_REF(shunt_kind_name),
	"SHUNT_KIND_", /*PREFIX*/
	NULL,
};

static const char *const shunt_policy_percent_name[] = {
	[SHUNT_UNSET] = "<shunt-unset>",
	[SHUNT_HOLD] = "%hold",
	[SHUNT_NONE] = "%none",
	[SHUNT_PASS] = "%pass",
	[SHUNT_DROP] = "%drop",
	[SHUNT_REJECT] = "%reject",
	[SHUNT_TRAP] = "%trap",
};

const struct enum_names shunt_policy_percent_names = {
	SHUNT_UNSET, SHUNT_POLICY_ROOF-1,
	ARRAY_REF(shunt_policy_percent_name),
	"%"/*prefix*/,
	NULL,
};

/*
 * Values for failureshunt={passthrough, drop, reject, none}
 */

const struct sparse_names failure_shunt_names = {
	.list = {
		SPARSE("none",        SHUNT_NONE),
		SPARSE("passthrough", SHUNT_PASS),
		SPARSE("drop",        SHUNT_DROP),
		SPARSE("hold",        SHUNT_DROP), /* alias */
		SPARSE("reject",      SHUNT_REJECT),
		SPARSE_NULL
	},
};

/*
 * Values for negotiationshunt={passthrough, hold}
 */

const struct sparse_names negotiation_shunt_names = {
	.list = {
		SPARSE("passthrough", SHUNT_PASS),
		SPARSE("drop",        SHUNT_HOLD), /* alias */
		SPARSE("hold",        SHUNT_HOLD),
		SPARSE_NULL
	},
};
