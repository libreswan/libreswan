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

#ifndef LSWFIPS_H
#define LSWFIPS_H

#include <stdbool.h>	/* for bool */

enum lsw_fips_mode {
	LSW_FIPS_UNSET = 0,
	LSW_FIPS_UNKNOWN,
	LSW_FIPS_OFF,
	LSW_FIPS_ON
};

extern void lsw_set_fips_mode(enum lsw_fips_mode fips);
extern enum lsw_fips_mode lsw_get_fips_mode(void);
extern bool libreswan_fipsmode(void);

#endif

