/* getopt parsing, for libreswan
 *
 * Copyright (C) 2023-2025 Andrew Cagney
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

ip_address optarg_address_num(const struct logger *logger, struct optarg_family *family)
{
	ip_address address;
	diag_t d = ttoaddress_num(shunk1(optarg), family->type, &address);
	if (d != NULL) {
		optarg_fatal(logger, "%s", str_diag(d));
	}
	optarg_family(family, address_info(address));
	return address;
}
