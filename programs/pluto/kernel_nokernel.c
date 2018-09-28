/* interface to fake kernel interface, used for testing pluto in-vitro.
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright (C) 2003-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2003 Herbert Xu.
 * Copyright (C) 2008 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2017 Paul Wouters <pwouters@redhat.com>
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

#include "kernel.h"
#include "kernel_nokernel.h"

static void init_nokernel(void)
{
}

/* asynchronous messages from our queue */
static void nokernel_dequeue(void)
{
}

/* asynchronous messages directly from PF_KEY socket */
static void nokernel_event(int fd UNUSED)
{
}

static void nokernel_register_response(const struct sadb_msg *msg UNUSED)
{
}

static void nokernel_register(void)
{
}

static bool nokernel_raw_eroute(const ip_address *this_host UNUSED,
			       const ip_subnet *this_client UNUSED,
			       const ip_address *that_host UNUSED,
			       const ip_subnet *that_client UNUSED,
			       ipsec_spi_t cur_spi UNUSED,
			       ipsec_spi_t new_spi UNUSED,
			       int sa_proto UNUSED,
			       unsigned int transport_proto UNUSED,
			       unsigned int satype UNUSED,
			       const struct pfkey_proto_info *proto_info UNUSED,
			       deltatime_t use_lifetime UNUSED,
			       uint32_t sa_priority UNUSED,
			       const struct sa_marks *sa_marks UNUSED,
			       unsigned int op UNUSED,
			       const char *text_said UNUSED
#ifdef HAVE_LABELED_IPSEC
			       , const char *policy_label UNUSED
#endif
			       )
{
	return TRUE;
}

static bool nokernel_add_sa(const struct kernel_sa *sa UNUSED,
			   bool replace UNUSED)
{
	return TRUE;
}

static bool nokernel_grp_sa(const struct kernel_sa *sa0 UNUSED,
			   const struct kernel_sa *sa1 UNUSED)
{
	return TRUE;
}

static bool nokernel_del_sa(const struct kernel_sa *sa UNUSED)
{
	return TRUE;
}

static bool nokernel_sag_eroute(const struct state *st UNUSED,
			       const struct spd_route *sr UNUSED,
			       enum pluto_sadb_operations op UNUSED,
			       const char *opname UNUSED)
{
	return TRUE;
}

static bool nokernel_shunt_eroute(const struct connection *c UNUSED,
				 const struct spd_route *sr UNUSED,
				 enum routing_t rt_kind UNUSED,
				 enum pluto_sadb_operations op UNUSED,
				 const char *opname UNUSED)
{
	return TRUE;
}

static void nokernel_scan_shunts(void)
{
}

const struct kernel_ops nokernel_kernel_ops = {
	.type = NO_KERNEL,
	.async_fdp = NULL,
	.route_fdp = NULL,

	.init = init_nokernel,
	.pfkey_register = nokernel_register,
	.pfkey_register_response = nokernel_register_response,
	.process_queue = nokernel_dequeue,
	.process_msg = nokernel_event,
	.raw_eroute = nokernel_raw_eroute,
	.add_sa = nokernel_add_sa,
	.grp_sa = nokernel_grp_sa,
	.del_sa = nokernel_del_sa,
	.get_sa = NULL,
	.sag_eroute = nokernel_sag_eroute,
	.shunt_eroute = nokernel_shunt_eroute,
	.get_spi = NULL,
	.inbound_eroute = FALSE,
	.scan_shunts = nokernel_scan_shunts,
	.exceptsocket = NULL,
	.docommand = NULL,
	.kern_name = "nokernel",
	.overlap_supported = FALSE,
	.sha2_truncbug_support = FALSE,
};
