/* encap proto, for libreswan
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

#include "encap_proto.h"

#include "lswcdefs.h"		/* for ARRAY_REF */
#include "enum_names.h"

static const char *encap_proto_name[] = {
#define S(E) [E - ENCAP_PROTO_ESP] = #E
	S(ENCAP_PROTO_ESP),
	S(ENCAP_PROTO_AH),
#undef S
};

const struct enum_names encap_proto_names = {
	ENCAP_PROTO_ESP,
	ENCAP_PROTO_AH,
	ARRAY_REF(encap_proto_name),
	.en_prefix = "ENCAP_PROTO_",
};

static const char *encap_proto_story_name[] = {
#define S(E,V) [E - ENCAP_PROTO_ESP] = V
	S(ENCAP_PROTO_ESP, "esp"),
	S(ENCAP_PROTO_AH, "ah"),
#undef S
};

const struct enum_names encap_proto_story = {
	ENCAP_PROTO_ESP,
	ENCAP_PROTO_AH,
	ARRAY_REF(encap_proto_story_name),
	.en_prefix = NULL,
};
