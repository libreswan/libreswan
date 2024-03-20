/*
 * conversion from text forms of addresses to internal ones
 *
 * Copyright (C) 2000  Henry Spencer.
 * Copyright (C) 2019-2021 Andrew Cagney <cagney@gnu.org>
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

/*
 * Unit testing is available through
 *   OBJ.$WHATEVER/testing/programs/ipcheck/ipcheck
 * This does not require KVM and is built by "make base".
 */

#include <string.h>
#include <netdb.h>		/* for freeaddrinfo(), getaddrinfo() */
#include <sys/socket.h>		/* for AF_INET/AF_INET6/AF_UNSPEC */

#include "passert.h"
#include "ip_address.h"
#include "ip_info.h"
#include "lswalloc.h"

/*
 * ttoaddress_dns
 *
 * ??? numeric addresses are handled by getaddrinfo; perhaps the hex form is lost.
 * ??? change: we no longer filter out bad characters.  Surely getaddrinfo(3) does.
 */
err_t ttoaddress_dns(shunk_t src, const struct ip_info *afi, ip_address *dst)
{
	*dst = unset_address;

	char *name = clone_hunk_as_string(src, "ttoaddress_dns"); /* must free */
	struct addrinfo *res = NULL; /* must-free when EAI==0 */
	int family = afi == NULL ? AF_UNSPEC : afi->af;
	const struct addrinfo hints = (struct addrinfo) {
		.ai_family = family,
	};
	int eai = getaddrinfo(name, NULL, &hints, &res);

	if (eai != 0) {
		/*
		 * Return what the pluto testsuite expects for now.
		 *
		 * Error return is intricate because we cannot compose
		 * a static string.
		 *
		 * XXX: How portable are errors returned by
		 * gai_strerror(eai)?
		 *
		 * XXX: what is with "(no validation performed)"?
		 * Perhaps it is referring to DNSSEC.
		 */
		pfree(name);
		/* RES is not defined */
		switch (family) {
		case AF_INET6:
			return "not a numeric IPv6 address and name lookup failed (no validation performed)";
		case AF_INET:
			return "not a numeric IPv4 address and name lookup failed (no validation performed)";
		default:
			return "not a numeric IPv4 or IPv6 address and name lookup failed (no validation performed)";
		}
	}

	/*
	 * If getaddrinfo succeeded, res must be non-empty.
	 * Make this assumption manifest: it quiets lclint.
	 */
	passert(res != NULL);

	/*
	 * When AFI is specified, use the first entry; and prefer IPv4
	 * when it wasn't.
	 *
	 * Linux orders things IPv4->IPv6, but NetBSD at least is the
	 * reverse; hence the search.
	 */
	struct addrinfo *winner = res;
	if (afi == NULL) {
		for (struct addrinfo *r = res; r!= NULL; r = r->ai_next) {
			if (r->ai_family == AF_INET) {
				winner = r;
				break;
			}
		}
	}

	/* boneheaded getaddrinfo(3) leaves port field undefined */
	err_t err = sockaddr_to_address_port(winner->ai_addr, winner->ai_addrlen,
					     dst, NULL/*ignore port*/);
	passert(address_type(dst)->af == winner->ai_family);

	freeaddrinfo(res);
	pfree(name);
	return err;
}
