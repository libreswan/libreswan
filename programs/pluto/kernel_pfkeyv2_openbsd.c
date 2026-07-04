/* OpenBSD PFKEYv2 bits, for libreswan
 *
 * Copyright (C) 2026 Amrinder Singh <officialamrindersinghh@gmail.com>
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

#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_ipsp.h>

#include "ip_info.h"
#include "log.h"

#include "kernel_pfkeyv2.h"

static bool pfkeyv2_poke_ipsec_level(int fd, int sol, int opt, struct logger *logger)
{
	int level = IPSEC_LEVEL_BYPASS;
	if (setsockopt(fd, sol, opt, &level, sizeof(level)) != 0) {
		llog_errno(ERROR_STREAM, logger, errno,
			   "setsockopt bypass level: ");
		return false;
	}
	return true;
}

bool pfkeyv2_poke_ipsec_policy_hole(int fd, const struct ip_info *afi, struct logger *logger)
{
	switch (afi->af) {
	case AF_INET:
		return pfkeyv2_poke_ipsec_level(fd, IPPROTO_IP, IP_AUTH_LEVEL, logger) &&
		       pfkeyv2_poke_ipsec_level(fd, IPPROTO_IP, IP_ESP_TRANS_LEVEL, logger) &&
		       pfkeyv2_poke_ipsec_level(fd, IPPROTO_IP, IP_ESP_NETWORK_LEVEL, logger);
	case AF_INET6:
		return pfkeyv2_poke_ipsec_level(fd, IPPROTO_IPV6, IPV6_AUTH_LEVEL, logger) &&
		       pfkeyv2_poke_ipsec_level(fd, IPPROTO_IPV6, IPV6_ESP_TRANS_LEVEL, logger) &&
		       pfkeyv2_poke_ipsec_level(fd, IPPROTO_IPV6, IPV6_ESP_NETWORK_LEVEL, logger);
	default:
		bad_case(afi->af);
	}
}
