/* impair operation
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

#ifndef IMPAIR_H
#define IMPAIR_H

#include <stdbool.h>

#include "lswcdefs.h"

/*
 * Ways to impair something.  This is just the start ...
 */

enum send_impairment {
	SEND_NORMAL = 0,
	SEND_OMIT,
	SEND_EMPTY,
	SEND_ROOF, /* >= ROOF -> <number> */
};

#if 0
enum xxx_impair ...;
#endif

/*
 * What can be impaired.
 *
 * XXX: make this a structure so it can be copied?
 */

extern enum send_impairment impair_ke_payload;
extern enum send_impairment impair_key_length_attribute;

/*
 * What whack sends across the wire for a impair.
 */

struct whack_impair {
	unsigned what;
	unsigned how;
};

bool parse_impair(const char *optarg, struct whack_impair *whack_impair, bool enable);

void process_impair(const struct whack_impair *whack_impair);

void help_impair(const char *prefix);

#endif
