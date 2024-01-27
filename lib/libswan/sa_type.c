/* SA type, for libreswan
 *
 * Copyright (C) 2024 Andrew Cagney
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

#include "sa_type.h"

#include "lswcdefs.h"		/* for ARRAY_REF */
#include "enum_names.h"

static const char *sa_type_name[] = {
#define S(E) [E - SA_TYPE_FLOOR] = #E
	S(IKE_SA),
	S(CHILD_SA),
#undef S
};

const struct enum_names sa_type_names = {
	SA_TYPE_FLOOR,
	SA_TYPE_ROOF,
	ARRAY_REF(sa_type_name),
	.en_prefix = NULL,
};
