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
 *
 */

#ifndef ENCAP_MODE_H
#define ENCAP_MODE_H

/*
 * Encapsulation mode.
 *
 * Contrary to the RFCs and ENCAPSULATION_MODE_*, the kernel only has
 * to handle 3 modes + BEET. Hence an ENUM that only defines the values pluto support.
 *
 * Except contrary to that, PF KEY v2 accepts the mode "any".
 */

enum encap_mode {
	ENCAP_MODE_UNSET,
	ENCAP_MODE_TRANSPORT = 2, /*>true */
	ENCAP_MODE_TUNNEL,
	ENCAP_MODE_IPTFS,
};

extern const struct enum_names encap_mode_names;
extern const struct enum_names encap_mode_story; /* lower-case */

#endif
