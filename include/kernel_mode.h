/* kernel mode, for libreswan
 *
 * Copyright (C) 2024 Andrew Cagney
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

#ifndef KERNEL_MODE_H
#define KERNEL_MODE_H

/*
 * Kernel's outer most encapsulation mode.
 *
 * Contrary to the RFCs and ENCAPSULATION_MODE_*, the kernel only has
 * to handle three outermost encapsulation.  Hence an ENUM that only
 * defines those values.
 *
 * Except contrary to that, PF KEY v2 accepts the mode "any".
 */

enum kernel_mode {
#define KERNEL_MODE_FLOOR 1
	KERNEL_MODE_TRANSPORT = 1,
	KERNEL_MODE_TUNNEL,
	KERNEL_MODE_IPTFS,
#define KERNEL_MODE_ROOF (KERNEL_MODE_IPTFS+1)
};

extern const struct enum_names kernel_mode_names;
extern const struct enum_names kernel_mode_stories;

#endif
