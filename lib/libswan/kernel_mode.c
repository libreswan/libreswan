/* kernel mode, for libreswan
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

#include "kernel_mode.h"

#include "lswcdefs.h"		/* for ARRAY_REF */
#include "enum_names.h"

static const char *kernel_mode_name[] = {
#define S(E) [E-KERNEL_MODE_TRANSPORT] = #E
	S(KERNEL_MODE_TRANSPORT),
	S(KERNEL_MODE_IPTFS),
#undef S
};

const struct enum_names kernel_mode_names = {
	KERNEL_MODE_FLOOR, KERNEL_MODE_ROOF-1,
	ARRAY_REF(kernel_mode_name),
	.en_prefix = "KERNEL_MODE_",
};

static const char *kernel_mode_story[] = {
#define S(E,T) [E-KERNEL_MODE_TRANSPORT] = T
	S(KERNEL_MODE_TRANSPORT, "Transport Mode"),
	S(KERNEL_MODE_IPTFS, "Tunnel Mode"),
#undef S
};

const struct enum_names kernel_mode_stories = {
	KERNEL_MODE_FLOOR, KERNEL_MODE_ROOF-1,
	ARRAY_REF(kernel_mode_story),
	.en_prefix = NULL,
};
