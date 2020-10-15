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

#include "err.h"
#include "lswcdefs.h"

typedef struct { char keyid[10/* up to 9 text digits + NUL */]; } keyid_t;

extern const keyid_t empty_keyid;

#define str_keyid(KEYID) (KEYID).keyid

err_t splitkey_to_keyid(const uint8_t *e, size_t elen, const uint8_t *m, size_t mlen,
			keyid_t *dst) MUST_USE_RESULT;
err_t keyblob_to_keyid(const uint8_t *src, size_t srclen,
		       keyid_t *dst) MUST_USE_RESULT;

#endif
