/* parser transform names, for libreswan
 *
 * Copyright (C) 2025 Andrew Cagney
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

#include "proposals.h"

#include "lswcdefs.h"		/* for ARRAY_REF */
#include "enum_names.h"

static const char *proposal_transform_name[] = {
#define S(E) [E-PROPOSAL_TRANSFORM_FLOOR] = #E
	S(PROPOSAL_TRANSFORM_encrypt),
	S(PROPOSAL_TRANSFORM_prf),
	S(PROPOSAL_TRANSFORM_integ),
	S(PROPOSAL_TRANSFORM_kem),
	S(PROPOSAL_TRANSFORM_addke1),
	S(PROPOSAL_TRANSFORM_addke2),
	S(PROPOSAL_TRANSFORM_addke3),
	S(PROPOSAL_TRANSFORM_addke4),
	S(PROPOSAL_TRANSFORM_addke5),
	S(PROPOSAL_TRANSFORM_addke6),
	S(PROPOSAL_TRANSFORM_addke7),
#undef S
};

const struct enum_names proposal_transform_names = {
	PROPOSAL_TRANSFORM_FLOOR, PROPOSAL_TRANSFORM_ROOF-1,
	ARRAY_REF(proposal_transform_name),
	.en_prefix = "PROPOSAL_TRANSFORM_",
};
