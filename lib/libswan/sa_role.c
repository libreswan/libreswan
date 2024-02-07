/* sa_role names, for libreswan
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

#include "lswcdefs.h"		/* for ARRAY_REF() */
#include "enum_names.h"
#include "sa_role.h"

const char *sa_role_name[] = {
#define S(E) [E - SA_ROLE_FLOOR] = #E
	S(SA_INITIATOR),
	S(SA_RESPONDER),
#undef S
};

const struct enum_names sa_role_names = {
	SA_ROLE_FLOOR, SA_ROLE_ROOF-1,
	ARRAY_REF(sa_role_name),
	"SA_ROLE_",
	NULL,
};
