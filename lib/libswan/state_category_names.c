/* state categories, for libreswan
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

#include "state_category.h"
#include "enum_names.h"
#include "lswcdefs.h"

/* state categories */

static const char *const cat_name[CAT_ROOF] = {
	[CAT_UNKNOWN] = "unknown",
	[CAT_HALF_OPEN_IKE_SA] = "half-open IKE SA",
	[CAT_OPEN_IKE_SA] = "open IKE SA",
	[CAT_ESTABLISHED_IKE_SA] = "established IKE SA",
	[CAT_OPEN_CHILD_SA] = "open Child SA",
	[CAT_ESTABLISHED_CHILD_SA] = "established Child SA",
	[CAT_INFORMATIONAL] = "informational",
	[CAT_IGNORE] = "ignore",
};

const struct enum_names state_category_names = {
	0, CAT_ROOF - 1,
	ARRAY_REF(cat_name),
	"",
	NULL
};
