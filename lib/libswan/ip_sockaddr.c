/* ip endpoint (address + port), for libreswan
 *
 * Copyright (C) 2018-2019 Andrew Cagney <cagney@gnu.org>
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

#include "ip_sockaddr.h"
#include "ip_info.h"

#include "lswlog.h"		/* for bad_case() */

const ip_sockaddr unset_sockaddr;

err_t sockaddr_to_address_port(const struct sockaddr *unaligned_sa, size_t len,
			       ip_address *address, ip_port *port)
{
	/* always clear; both are optional */
	if (address != NULL) {
		*address = unset_address;
	}
	if (port != NULL) {
		*port = unset_port;
	}

	/*
	 * Move to an aligned structure.
	 *
	 * UNALIGNED_SA can point into a raw buffer.  LEN indicates
	 * the max number of bytes that can be safely read.
	 *
	 * XXX: use PMIN(), and not min(), to avoid gcc/102288.
	 */
	ip_sockaddr sa = { .len = PMIN(len, sizeof(sa.sa)), };
	memcpy(&sa.sa, unaligned_sa, sa.len);

	socklen_t min_len = offsetof(struct sockaddr, sa_family) + sizeof(sa_family_t);
	if (sa.len < min_len) {
		return "too small";
	}

	const struct ip_info *afi = aftoinfo(sa.sa.sa.sa_family);
	if (afi == NULL) {
		return "unexpected address family";
	}

	if (sa.len < afi->sockaddr_size) {
		return "address truncated";
	}

	if (address != NULL) {
		*address = afi->address_from_sockaddr(sa);
	}

	if (port != NULL) {
		*port = afi->port_from_sockaddr(sa);
	}

	return NULL;
}

/*
 * Construct and return a sockaddr structure.
 */

ip_sockaddr sockaddr_from_address_port(const ip_address address, ip_port port)
{
	if (address_is_unset(&address)) {
		return unset_sockaddr;
	}

	const struct ip_info *afi = address_info(address);
	shunk_t src_addr = address_as_shunk(&address);
	chunk_t dst_addr;
	ip_sockaddr sa = unset_sockaddr;

	switch (afi->af) {
	case AF_INET:
		sa.sa.sin.sin_family = afi->af;
		sa.sa.sin.sin_port = nport(port);
		dst_addr = THING_AS_CHUNK(sa.sa.sin.sin_addr);
#ifdef USE_SOCKADDR_LEN
		sa.sa.sin.sin_len = sizeof(struct sockaddr_in);
#endif
		break;
	case AF_INET6:
		sa.sa.sin6.sin6_family = afi->af;
		sa.sa.sin6.sin6_port = nport(port);
		dst_addr = THING_AS_CHUNK(sa.sa.sin6.sin6_addr);
#ifdef USE_SOCKADDR_LEN
		sa.sa.sin6.sin6_len = sizeof(struct sockaddr_in6);
#endif
		break;
	default:
		bad_case(afi->af);
	}

	passert(src_addr.len == afi->ip_size);
	passert(dst_addr.len == afi->ip_size);
	memcpy(dst_addr.ptr, src_addr.ptr, src_addr.len);
	sa.len = afi->sockaddr_size;
	return sa;
}

ip_sockaddr sockaddr_from_address(const ip_address address)
{
	return sockaddr_from_address_port(address, unset_port);
}

ip_sockaddr sockaddr_from_endpoint(const ip_endpoint endpoint)
{
	if (endpoint_is_unset(&endpoint)) {
		return unset_sockaddr;
	}

	return sockaddr_from_address_port(endpoint_address(endpoint),
					  endpoint_port(endpoint));
}
