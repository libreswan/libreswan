/* interface to fake kernel interface, used for testing pluto in-vitro.
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright (C) 2003-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2003 Herbert Xu.
 * Copyright (C) 2008 Paul Wouters <paul@xelerance.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/select.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <libreswan.h>
#include <libreswan/pfkeyv2.h>
#include <libreswan/pfkey.h>

#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "id.h"
#include "connections.h"
#include "kernel.h"
#include "kernel_noklips.h"
#include "log.h"
#include "whack.h"      /* for RC_LOG_SERIOUS */

static void init_noklips(void)
{
}

/* asynchronous messages from our queue */
static void noklips_dequeue(void)
{
}

/* asynchronous messages directly from PF_KEY socket */
static void noklips_event(void)
{
}

static void noklips_register_response(const struct sadb_msg *msg UNUSED)
{
}

static void noklips_register(void)
{
}

static bool noklips_raw_eroute(const ip_address *this_host UNUSED,
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

static bool noklips_add_sa(const struct kernel_sa *sa UNUSED,
			   bool replace UNUSED)
{
	return TRUE;
}

static bool noklips_grp_sa(const struct kernel_sa *sa0 UNUSED,
			   const struct kernel_sa *sa1 UNUSED)
{
	return TRUE;
}

static bool noklips_del_sa(const struct kernel_sa *sa UNUSED)
{
	return TRUE;
}

static bool noklips_sag_eroute(const struct state *st UNUSED,
			       const struct spd_route *sr UNUSED,
			       enum pluto_sadb_operations op UNUSED,
			       const char *opname UNUSED)
{
	return TRUE;
}

static bool noklips_shunt_eroute(const struct connection *c UNUSED,
				 const struct spd_route *sr UNUSED,
				 enum routing_t rt_kind UNUSED,
				 enum pluto_sadb_operations op UNUSED,
				 const char *opname UNUSED)
{
	return TRUE;
}

const struct kernel_ops noklips_kernel_ops = {
	.type = NO_KERNEL,
	.async_fdp = NULL,

	.init = init_noklips,
	.pfkey_register = noklips_register,
	.pfkey_register_response = noklips_register_response,
	.process_queue = noklips_dequeue,
	.process_msg = noklips_event,
	.raw_eroute = noklips_raw_eroute,
	.add_sa = noklips_add_sa,
	.grp_sa = noklips_grp_sa,
	.del_sa = noklips_del_sa,
	.get_sa = NULL,
	.sag_eroute = noklips_sag_eroute,
	.shunt_eroute = noklips_shunt_eroute,
	.get_spi = NULL,
	.inbound_eroute = FALSE,
	.policy_lifetime = FALSE,
	.exceptsocket = NULL,
	.docommand = NULL,
	.kern_name = "noklips",
	.overlap_supported = FALSE,
	.sha2_truncbug_support = FALSE,
};
