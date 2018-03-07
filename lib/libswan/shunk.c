/* string fragments, for libreswan
 *
 * Copyright (C) 2018 Andrew Cagney
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#include "shunk.h"
#include "lswalloc.h"

const shunk_t empty_shunk;

shunk_t shunk1(const char *ptr)
{
	return shunk2(ptr, strlen(ptr));
}

shunk_t shunk2(const char *ptr, int len)
{
	return (shunk_t) { .ptr = ptr, .len = len, };
}
