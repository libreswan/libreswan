/* scale binary IEC 60027-2, for libreswan
 *
 * Copyright (C) 2022  Antony Antony
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/lgpl-2.1.txt>.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 *
 */

#ifndef BINARYSCALE_H
#define BINARYSCALE_H    /* seen it, no need to see it again */

#include <stdint.h>	/* for uintmax_t */

#include "shunk.h"

struct binaryscale {
	const char *suffix;
	uint64_t b;
};

extern const struct binaryscale bin_default;
extern const struct binaryscale bin_bytedefult;

#define PRI_BINARYSCALE "1%s(%ju%s)"
#define pri_binaryscale(B) (B).suffix, (B).b, (B).prefix

const struct binaryscale *ttobinaryscale(shunk_t s);
const struct binaryscale *ttobinarybytesscale(shunk_t s);

#endif
