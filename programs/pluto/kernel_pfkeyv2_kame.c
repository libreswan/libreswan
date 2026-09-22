/* Interface to the PF_KEY v2 IPsec mechanism, for Libreswan
 *
 * Copyright (C)  2022-2026  Andrew Cagney
 * Copyright (C)  2026 Amrinder Singh <officialamrindersinghh@gmail.com>
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

#include <errno.h>
#include <sys/types.h>		/* for u_int16_, used by ipsec.h */
#include <netipsec/ipsec.h>

#include "kernel_pfkeyv2.h"
#include "log.h"
#include "ip_info.h"

static bool pfkeyv2_poke_ipsec_policy_dir(int fd, int sol, int opt,
					  const char *dir, struct logger *logger)
{
	char *policy = ipsec_set_policy((char *)dir, strlen(dir)); /* must free() */
	if (policy == NULL) {
		llog(ERROR_STREAM, logger,
		     "ipsec_set_policy %s: %s", dir, ipsec_strerror());
		return false;
	}
	bool ok = (setsockopt(fd, sol, opt, policy, ipsec_get_policylen(policy)) == 0);
	if (!ok) {
		llog_errno(ERROR_STREAM, logger, errno,
			   "setsockopt IP_IPSEC_POLICY %s: ", dir);
	}
	free(policy); /* not pfree() */
	return ok;
}

bool pfkeyv2_poke_ipsec_policy_hole(int fd, const struct ip_info *afi,
				    struct logger *logger)
{
	int af = afi->af;

	int opt, sol;
	switch (af) {
	case AF_INET:
		sol = IPPROTO_IP;
		opt = IP_IPSEC_POLICY;
		break;
	case AF_INET6:
		sol = IPPROTO_IPV6;
		opt = IPV6_IPSEC_POLICY;
		break;
	default:
		bad_case(af);
	}

	return pfkeyv2_poke_ipsec_policy_dir(fd, sol, opt, "in bypass", logger) &&
	       pfkeyv2_poke_ipsec_policy_dir(fd, sol, opt, "out bypass", logger);
}
