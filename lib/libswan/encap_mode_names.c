/* encap mode, for libreswan
 *
 * Copyright (C) 2021 Andrew Cagney
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

#include "encap_mode.h"

#include "lswcdefs.h"		/* for ARRAY_REF() */
#include "enum_names.h"

static const char *encap_mode_name[] = {
#define S(E) [E-ENCAP_MODE_TRANSPORT] = #E
	S(ENCAP_MODE_TRANSPORT),
	S(ENCAP_MODE_IPTFS),
#undef S
};

const struct enum_names encap_mode_names = {
	ENCAP_MODE_TRANSPORT,
	ENCAP_MODE_IPTFS,
	ARRAY_REF(encap_mode_name),
	.en_prefix = "ENCAP_MODE_",
};

static const char *encap_mode_story_name[] = {
#define S(E,V) [E-ENCAP_MODE_TRANSPORT] = V
	S(ENCAP_MODE_TRANSPORT, "transport"),
	S(ENCAP_MODE_IPTFS, "iptfs"),
#undef S
};

const struct enum_names encap_mode_story = {
	ENCAP_MODE_TRANSPORT,
	ENCAP_MODE_IPTFS,
	ARRAY_REF(encap_mode_story_name),
	.en_prefix = NULL,
};
