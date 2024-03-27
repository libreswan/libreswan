/* state categories, for libreswan
 *
 * Copyright (C) 2018 Andrew Cagney
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

#ifndef STATE_CATEGORY_H
#define STATE_CATEGORY_H

/*
 * For auditing, different categories of a state.  Of most interest is
 * half-open states which suggest libreswan being under attack.
 *
 * "half-open" is where only one packet was received.
 */
enum state_category {
	CAT_UNKNOWN = 0,
	CAT_HALF_OPEN_IKE_SA,
	CAT_OPEN_IKE_SA,
	CAT_ESTABLISHED_IKE_SA,
	CAT_OPEN_CHILD_SA,
	CAT_ESTABLISHED_CHILD_SA,
	CAT_INFORMATIONAL,
	CAT_IGNORE,
#define CAT_ROOF (CAT_IGNORE+1)
};

extern const struct enum_names state_category_names;

#endif
