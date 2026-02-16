/* table of keyword-type names, for libreswan
 *
 * Copyright (C) 2026 Andrew Cagney
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

#include "ipsecconf/keywords.h"

#include "enum_names.h"
#include "lswcdefs.h"		/* for ARRAY_REF */

static const char *const keyword_type_name[] = {
#define S(E) [E - kt_string] = #E
	S(kt_string),
	S(kt_appendstrings),
	S(kt_sparse_name),
	S(kt_unsigned),
	S(kt_seconds),
	S(kt_also),
	S(kt_obsolete),
#undef S
};

const struct enum_names keyword_type_names = {
	kt_string, kt_obsolete,
	ARRAY_REF(keyword_type_name),
	"kt_",
	NULL,
};
