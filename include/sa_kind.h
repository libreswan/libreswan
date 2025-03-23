/* SA kind, for libreswan
 *
 * Copyright (C) 2019 Andrew Cagney
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

#ifndef SA_KIND_H
#define SA_KIND_H

enum sa_kind {
#define SA_KIND_FLOOR 0
	IKE_SA = SA_KIND_FLOOR,
	CHILD_SA,
#define SA_KIND_ROOF (CHILD_SA+1)
};

extern const struct enum_names sa_kind_names;

#endif
