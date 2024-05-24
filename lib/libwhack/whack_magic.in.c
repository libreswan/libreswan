/* whack magic for libreswan
 *
 * Copyright (C) 2024  Andrew Cagney
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

#include "lswversion.h"
#include "whack.h"

static unsigned magic = @@WHACK_MAGIC@@;

unsigned whack_magic(void)
{
	if (magic == WHACK_BASIC_MAGIC) {
		return ~magic; /* what are the odds? */
	}
	return magic;
}
