/* direction of travel, for libreswan
 *
 * Copyright (C) 2021-2024,2026  Andrew Cagney
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

#ifndef DIRECTION_H
#define DIRECTION_H

enum direction {
	DIRECTION_INBOUND = 2, /*>true*/
	DIRECTION_OUTBOUND = 4, /* so lset_t works */
};

extern const struct names direction_names;

enum directions {
	DIRECTIONS_INBOUND = DIRECTION_INBOUND,
	DIRECTIONS_OUTBOUND = DIRECTION_OUTBOUND,
	DIRECTIONS_INBOUND_AND_OUTBOUND = DIRECTION_INBOUND|DIRECTION_OUTBOUND,
};

#endif
