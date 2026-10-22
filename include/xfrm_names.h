/* tables of names for values defined in constants.h
 *
 * Copyright (C) 2022 Andrew Cagney
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

#ifndef XFRM_NAMES_H
#define XFRM_NAMES_H

#ifndef KERNEL_XFRM
# error "XFRM only"
#endif

extern const struct enum_names xfrm_policy_names;	/* #ifdef KERNEL_XFRM */
extern const struct sparse_names xfrm_type_names;	/* #ifdef KERNEL_XFRM */
extern const struct sparse_names rtm_type_names;	/* #ifdef KERNEL_XFRM */
#endif
