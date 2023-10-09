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
	INITIATED_BY_NONE,
	INITIATED_BY_WHACK, /*guess*/
	INITIATED_BY_REVIVE,
	INITIATED_BY_ACQUIRE,
	INITIATED_BY_REPLACE,
};

extern const struct enum_names initiated_by_names;

#endif
