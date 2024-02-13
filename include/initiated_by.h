/* initiating connections, for libreswan
 *
 * Copyright (C) 2023  Andrew Cagney
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

#ifndef INITIATED_BY_H
#define INITIATED_BY_H

enum initiated_by {
	INITIATED_BY_UNKNOWN = 0,
	INITIATED_BY_WHACK,
	INITIATED_BY_REVIVE,
	INITIATED_BY_ACQUIRE,
	INITIATED_BY_REPLACE,
	INITIATED_BY_IKE,	/* i.e., IKE_AUTH */
	INITIATED_BY_PEER,
};

#define INITIATED_BY_ROOF (INITIATED_BY_PEER+1)

extern const struct enum_names initiated_by_names;

#endif
