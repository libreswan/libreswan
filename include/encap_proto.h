/* encap proto, for libreswan
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
 *
 */

#ifndef ENCAP_PROTO_H
#define ENCAP_PROTO_H

/*
 * (outer) Encapsulation Protocol.
 *
 * There may also be an inner compression encapsulation.
 */

enum encap_proto {
	ENCAP_PROTO_UNSET = 0,
	ENCAP_PROTO_ESP,
	ENCAP_PROTO_AH,
};

extern const struct enum_names encap_proto_names;
extern const struct enum_names encap_proto_story; /* lower-case */

#endif
