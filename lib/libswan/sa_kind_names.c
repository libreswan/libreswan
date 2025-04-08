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

#include "sa_kind.h"

#include "lswcdefs.h"		/* for ARRAY_REF */
#include "enum_names.h"

static const char *sa_kind_name[] = {
#define S(E) [E - SA_KIND_FLOOR] = #E
	S(IKE_SA),
	S(CHILD_SA),
#undef S
};

const struct enum_names sa_kind_names = {
	SA_KIND_FLOOR,
	SA_KIND_ROOF-1,
	ARRAY_REF(sa_kind_name),
	.en_prefix = NULL,
};
