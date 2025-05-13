/* ttobinary(), for libreswan
 *
 * Copyright (C) 2022 Antony Antony
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

#include <limits.h>

#include "lswcdefs.h"		/* for elemsof() */
#include "constants.h"		/* for strncaseeq() */
#include "enum_names.h"

#include "binary-iec-60027-2.h"
#include "binaryscale-iec-60027-2.h"
#include "passert.h"
#include "lswalloc.h"
#include "ip_protocol.h"
#include "ip_encap.h"
#include "jambuf.h"

diag_t ttobinary(shunk_t t, uintmax_t *r, bool byte_scale)
{
	*r = 0;
	shunk_t cursor = t;
	const char *suffix = (byte_scale ? " Bytes" : "");

	struct mixed_decimal number;
	err_t err = tto_mixed_decimal(cursor, &cursor, &number);
	if (err != NULL) {
		return diag("bad binary%s value \""PRI_SHUNK"\": %s",
			    suffix,  pri_shunk(t), err);
	}

	const struct scale *scale =
		(byte_scale ? ttobinarybytesscale(cursor) :
		 ttobinaryscale(cursor));

	if (scale == NULL) {
		return diag("unrecognized binary%s multiplier \""PRI_SHUNK"\"",
			    suffix, pri_shunk(cursor));
	}

	uintmax_t binary;
	err_t e = scale_mixed_decimal(scale, number, &binary);
	if (e != NULL) {
		return diag("invalid binary%s \""PRI_SHUNK"\", %s",
			    suffix, pri_shunk(t), e);
	}

	*r = binary;
	return NULL;
}
