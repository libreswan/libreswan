/* test IP code, for libreswan
 *
 * Copyright (C) 2000  Henry Spencer.
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2018 Andrew Cagney
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

#include <stdio.h>

#include "lswlog.h" /* for log_ip */
#include "constants.h"
#include "ip_address.h"
#include "stdlib.h"
#include "ipcheck.h"

unsigned fails;

int main(int argc UNUSED, char *argv[] UNUSED)
{
	log_ip = false; /* force sensitive */
	ip_address_check();
	ip_endpoint_check();
	ip_range_check();
	ip_subnet_check();
	if (fails > 0) {
		return 1;
	} else {
		return 0;
	}
}
