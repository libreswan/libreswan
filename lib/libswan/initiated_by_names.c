/* tables of names for values defined in constants.h
 *
 * Copyright (C) 2023 Andrew Cagney
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

#include "lswcdefs.h"		/* for ARRAY_REF() */
#include "initiated_by.h"
#include "enum_names.h"

static const char *initiated_by_name[] = {
#define S(E) [E] = #E
	S(INITIATED_BY_ACQUIRE),
	S(INITIATED_BY_PEER),
	S(INITIATED_BY_REPLACE),
	S(INITIATED_BY_REVIVE),
	S(INITIATED_BY_UNKNOWN),
	S(INITIATED_BY_IKE),
	S(INITIATED_BY_PENDING),
	S(INITIATED_BY_WHACK),
#undef S
};

const struct enum_names initiated_by_names = {
	0, INITIATED_BY_ROOF-1,
	ARRAY_REF(initiated_by_name),
	"INITIATED_BY_", NULL,
};
