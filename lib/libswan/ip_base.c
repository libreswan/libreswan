/* base of ip structures, for libreswan
 *
 * Copyright (C) 2025  Andrew Cagney.
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
 */

#include "ip_base.h"
#include "jambuf.h"
#include "ip_info.h"

size_t jam_ip_invalid(struct jambuf *buf,
		      const char *what,
		      const struct ip_base *ip,
		      const struct ip_info **afi)
{
	if (ip == NULL) {
		return jam(buf, "<null-%s>", what);
	}

	if (!ip->is_set) {
		return jam(buf, "<unset-%s>", what);
	}

	(*afi) = ip_version_info(ip->version);
	if (*afi == NULL) {
		return jam(buf, "<unknown-%s>", what);
	}

	if ((*afi)->af == AF_UNSPEC) {
		return jam(buf, "<unspecified-%s>", what);
	}

	return 0;
}
