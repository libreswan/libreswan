/*
 * initialize address structure
 * Copyright (C) 2000  Henry Spencer.
 * Copyroght (C) 2009 Paul Wouters <paul@xelerance.com>
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

#include <string.h>

#include "ip_info.h"
#include "ip_address.h"
#include "passert.h"
#include "lswlog.h"		/* for bad_case() */

/*
   - initaddr - initialize ip_address from bytes
 */
err_t data_to_address(const void *data, size_t sizeof_data,
		      const struct ip_info *afi, ip_address *dst)
{
	if (afi == NULL) {
		*dst = unset_address;
		return "unknown address family";
	}
	switch (afi->af) {
	case AF_INET:
		if (sizeof_data != 4)
			return "IPv4 address must be exactly 4 bytes";
		passert(sizeof_data == sizeof(struct in_addr));
		struct in_addr in; /* force alignment of data */
		memcpy(&in, data, sizeof_data);
		*dst = address_from_in_addr(&in);
		break;
	case AF_INET6:
		if (sizeof_data != 16)
			return "IPv6 address must be exactly 16 bytes";
		passert(sizeof_data == sizeof(struct in6_addr));
		struct in6_addr in6; /* force alignment of data */
		memcpy(&in6, data, sizeof_data);
		*dst = address_from_in6_addr(&in6);
		break;
	default:
		bad_case(afi->af);
	}
	return NULL;
}
