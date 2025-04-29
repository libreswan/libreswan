/* binary IEC 60027-2 prefix and scale, for libreswan
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

#ifndef TTOBINARY_H
#define TTOBINARY_H    /* seen it, no need to see it again */

#include <stdint.h>	/* for uintmax_t */

#include "diag.h"
#include "shunk.h"

diag_t ttobinary(shunk_t t,  uintmax_t *b, bool prefix_B);

#endif
