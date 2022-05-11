/*
 * routines that are FreeBSD specific
 *
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
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
 *
 */

#include "ip_info.h"

#include "kernel_iface.h"

struct raw_iface *find_raw_ifaces4(struct logger *logger)
{
	return find_raw_ifaces(&ipv4_info, logger);
}

struct raw_iface *find_raw_ifaces6(struct logger *logger UNUSED)
{
	return find_raw_ifaces(&ipv6_info, logger);
}
