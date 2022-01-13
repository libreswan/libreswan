/*
 * tables of names for values defined in constants.h
 * Copyright (C) 2012-2017 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 1998-2002,2015  D. Hugh Redelmeier.
 * Copyright (C) 2016-2017 Andrew Cagney
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2020 Yulia Kuzovkova <ukuzovkova@gmail.com>
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

#include <stdio.h>

#include "sparse_names.h"

/* look up enum names in a sparse_names */
const char *sparse_name(sparse_names sd, unsigned long val)
{
	for (const struct sparse_name *p = sd; p->name != NULL; p++) {
		if (p->val == val) {
			return p->name;
		}
	}

	return NULL;
}

/*
 * find or construct a string to describe an sparse value
 *
 * Result may be in STATIC buffer -- NOT RE-ENTRANT!
 */
const char *sparse_val_show(sparse_names sd, unsigned long val)
{
	const char *p = sparse_name(sd, val);

	if (p == NULL) {
		static sparse_buf b;	/* STATIC!! */

		snprintf(b.buf, sizeof(b.buf), "%lu??", val);
		p = b.buf;
	}
	return p;
}
