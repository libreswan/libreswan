/* getopt parsing, for libreswan
 *
 * Copyright (C) 2017 Paul Wouters
 * Copyright (C) 2026 Anish Singh Rawat
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

#include "optarg.h"
#include "ipsecconf/setup.h"

uintmax_t optarg_seedbits(struct logger *logger)
{
	/* Why not allow zero aka disable? */
	uintmax_t seedbits = optarg_uintmax(logger);
	if (seedbits == 0) {
		optarg_fatal(logger, "seedbits must be an integer > 0");
	}
	
	/* Store in config setup for programs like pluto that use it */
	update_setup_option(KBF_SEEDBITS, seedbits);
	
	return seedbits;
}
