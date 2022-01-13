/* sparse_names, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2004-2008  Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2004-2009  Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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

#ifndef SPARSE_NAMES_H
#define SPARSE_NAMES_H

/*
 * sparse_names is much like enum_names, except values are not known
 * to be contiguous or ordered.
 *
 * The array of names is ended with one with the name sparse_end (this
 * avoids having to reserve a value to signify the end).  Often
 * appropriate for enums and macros defined by others.
 */

struct sparse_name {
	unsigned long val;
	const char *const name;
};

typedef const struct sparse_name sparse_names[];
extern const char sparse_end[];

typedef struct {
	char buf[16];/*how big?*/
} sparse_buf;

extern const char *sparse_name(sparse_names sd, unsigned long val);
extern const char *sparse_val_show(sparse_names sd, unsigned long val); /* uses static buffer -- NOT RE-ENTRANT */

#endif
