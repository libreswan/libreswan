/* keyid_t for libreswan
 *
 * Copyright (C) 2020 Andrew Cagney
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

#ifndef KEYID_H
#define KEYID_H

#include <stddef.h>	/* for size_t */
#include <stdint.h>

#define KEYID_BUF       10      /* up to 9 text digits plus NUL */

size_t splitkeytoid(const uint8_t *e, size_t elen, const void *m, size_t mlen,
		    char *dst /* need not be valid if dstlen is 0 */,
		    size_t dstlen);
size_t keyblobtoid(const uint8_t *src, size_t srclen,
		   char *dst /* need not be valid if dstlen is 0 */,
		   size_t dstlen);

#endif
