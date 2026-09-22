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
#include "kernel_sadb.h"
#include "log.h"
#include "ip_info.h"
#include "kernel.h"		/* for struct kernel_acquire */

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

static bool parse_sadb_x_policy(struct verbose verbose, const struct sadb_msg *b,
				shunk_t *ext_cursor,
				enum kernel_policy_id *policy_id)
{
	verbose.level++;
	shunk_t policy_cursor;
	const struct sadb_x_policy *policy =
		get_sadb_x_policy(ext_cursor, &policy_cursor, verbose);
	if (policy == NULL) {
		return false;
	}
	llog_sadb_x_policy(verbose, b, policy);
	verbose.level++;
	*policy_id = policy->sadb_x_policy_id;
	return true;
}

/*
 * XXX: KAME and OpenBSD have different sadb_address structures.
 */
static bool parse_sadb_address(struct verbose verbose, const struct sadb_msg *b,
			       shunk_t *ext_cursor, ip_address *addr, ip_port *port)
{
	shunk_t address_cursor;
	const struct sadb_address *address =
		get_sadb_address(ext_cursor, &address_cursor, verbose);
	if (address == NULL) {
		return false;
	}
	llog_sadb_address(verbose, b, address);
	verbose.level++;
	if (!get_sadb_sockaddr_address_port(&address_cursor, addr, port, verbose)) {
		return false;
	}
	address_buf ab;
	port_buf pb;
	verbose("%s:%s", str_address(addr, &ab), str_hport(*port, &pb));
	return true;
}

bool pfkeyv2_parse_sadb_acquire(const struct sadb_msg *msg,
				shunk_t msg_cursor,
				struct kernel_acquire *acquire,
				struct verbose verbose)
{
	vdbg("%s() ...", __func__);
	verbose.level++;
	zero(acquire);

	ip_address src_address = unset_address;
	ip_address dst_address = unset_address;
	ip_port src_port, dst_port;
	enum kernel_policy_id policy_id = 0;

	while (msg_cursor.len > 0) {

		shunk_t ext_cursor;
		const struct sadb_ext *ext =
			get_sadb_ext(&msg_cursor, &ext_cursor, verbose);
		if (ext == NULL) {
			llog_pexpect(verbose.logger, HERE, "bad ext");
			return false;
		}

		enum sadb_exttype exttype = ext->sadb_ext_type;
		switch (exttype) {

		case SADB_EXT_ADDRESS_SRC:
			if (!parse_sadb_address(verbose, msg, &ext_cursor, &src_address, &src_port)) {
				return false;
			}
			break;
		case SADB_EXT_ADDRESS_DST:
			if (!parse_sadb_address(verbose, msg, &ext_cursor, &dst_address, &dst_port)) {
				return false;
			}
			break;
		case SADB_X_EXT_POLICY:
			policy_id = 0;
			if (!parse_sadb_x_policy(verbose, msg, &ext_cursor, &policy_id)) {
				return false;
			}
			break;

		default:
			if (verbose.debug) {
				verbose("ignore: ");
				verbose.level++;
				llog_sadb_ext(verbose, msg, ext, ext_cursor);
				verbose.level--;
			}
			break;
		}
	}

	if (address_is_unset(&src_address) || address_is_unset(&dst_address)) {
		vdbg("something isn't set");
		return false;
	}

	ip_packet packet = packet_from_raw(HERE,
					   address_info(src_address),
					   &src_address.bytes,
					   &dst_address.bytes,
					   &ip_protocol_all,
					   src_port,
					   dst_port);
	*acquire = (struct kernel_acquire) {
		.packet = packet,
		.by_acquire = true,
		.logger = verbose.logger, /*on-stack*/
		.background = true, /* no whack so doesn't matter */
		.sec_label = null_shunk,
		.policy_id = policy_id,
	};
	return true;
}
