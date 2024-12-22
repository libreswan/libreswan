/* end, for libreswan
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

#include "end.h"

#include "enum_names.h"
#include "lswcdefs.h"	/* for ARRAY_REF() */

static const char *end_name[] = {
#define S(E) [E-LEFT_END] = #E
	S(LEFT_END),
	S(RIGHT_END),
#undef S
};

const struct enum_names end_names = {
	LEFT_END,
	RIGHT_END,
	ARRAY_REF(end_name),
	.en_prefix = NULL,
};

static const char *end_story[] = {
	[LEFT_END] = "left",
	[RIGHT_END] = "right",
};

const struct enum_names end_stories = {
	LEFT_END,
	RIGHT_END,
	ARRAY_REF(end_story),
	.en_prefix = NULL,
};
