/* FIPS functions to determine FIPS status
 *
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
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

#ifndef FIPS_MODE_H
#define FIPS_MODE_H

#include <stdbool.h>	/* for bool */

struct logger;

enum fips_mode {
#define FIPS_MODE_UNSET 0	/* 0 is reserved; and not an enum */
#define FIPS_MODE_FLOOR FIPS_MODE_OFF
	FIPS_MODE_OFF = 1,
	FIPS_MODE_ON,
#define FIPS_MODE_ROOF (FIPS_MODE_ON+1)
};

extern const struct enum_names fips_mode_names;

void set_fips_mode(enum fips_mode fips);
enum fips_mode get_fips_mode(const struct logger *logger);

bool is_fips_mode(void);

extern int libreswan_selinux(struct logger *logger);

#endif
