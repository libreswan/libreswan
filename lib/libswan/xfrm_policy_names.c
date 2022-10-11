
/* tables of names for values defined in constants.h
 *
 * Copyright (C) 2022 Andrew Cagney
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

#include "linux/xfrm.h"		/* either local copy or system header */

#include "lswcdefs.h"		/* for ARRAY_REF() */
#include "enum_names.h"

/* XFRM POLICY direction names */

static const char *const xfrm_policy_name[] = {
#define S(E) [E] = #E
	S(XFRM_POLICY_IN),
	S(XFRM_POLICY_OUT),
	S(XFRM_POLICY_FWD),
#undef S
};

const struct enum_names xfrm_policy_names = {
	XFRM_POLICY_IN, XFRM_POLICY_FWD,
	ARRAY_REF(xfrm_policy_name),
	"XFRM_POLICY_", /* prefix */
	NULL
};
