/* encap type, for libreswan
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

#ifndef ENCAP_TYPE_H
#define ENCAP_TYPE_H

/*
 * Encapsulation type.
 *
 * SHUNT_TYPEs are mapped onto the below before being passed to the
 * kernel.
 *
 *          Linux  OpenBSD  Net/Free  SHUNT
 * TRAP:    ALLOW  ACQUIRE   IPSEC    TRAP
 * IPSEC:   ALLOW  REQUIRE   IPSEC    IPSEC
 * PASS:    ALLOW  BYPASS    NONE     PASS
 * DROP:    BLOCK   DENY     DISCARD  DROP,REJECT,HOLD
 * invalid:                           NONE!
 */

enum encap_type {
	ENCAP_TYPE_TRAP = 1,
	ENCAP_TYPE_IPSEC,
	ENCAP_TYPE_PASS,
	ENCAP_TYPE_DROP,
};

extern const struct enum_names encap_type_names;

#endif
