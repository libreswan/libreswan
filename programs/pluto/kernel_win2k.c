/* netlink interface to the kernel's IPsec mechanism
 * Copyright (C) 2003 Herbert Xu.
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

#if defined(WIN32) && defined(WIN32_NATIVE_IPSEC)

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <rtnetlink.h>
#include <xfrm.h>

#include <libreswan.h>
#include <libreswan/pfkeyv2.h>
#include <libreswan/pfkey.h>

#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "id.h"
#include "connections.h"
#include "kernel.h"
#include "kernel_netlink.h"
#include "kernel_pfkey.h"
#include "log.h"
#include "whack.h"      /* for RC_LOG_SERIOUS */
#include "kernel_alg.h"

/** init_netlink - Initialize the netlink inferface.  Opens the sockets and
 * then binds to the broadcast socket.
 */
static void win2k_init(void)
{
	/* open access to the kernel */
}

/** netlink_raw_eroute
 *
 * @param this_host ip_address
 * @param this_client ip_subnet
 * @param that_host ip_address
 * @param that_client ip_subnet
 * @param spi
 * @param sa_proto int (Currently unused) 4=tunnel, 50=esp, 108=ipcomp, etc ...
 * @param transport_proto unsigned int (Currently unused) Contains protocol (6=tcp, 17=udp, etc...)
 * @param esatype int
 * @param proto_info
 * @param lifetime (Currently unused)
 * @param op int
 * @return boolean True if successful
 */
static bool win2k_raw_eroute(const ip_address *this_host UNUSED,
			     const ip_subnet *this_client UNUSED,
			     const ip_address *that_host UNUSED,
			     const ip_subnet *that_client UNUSED,
			     ipsec_spi_t spi UNUSED,
			     int sa_proto UNUSED,
			     unsigned int transport_proto UNUSED,
			     unsigned int esatype UNUSED,
			     const struct pfkey_proto_info *proto_info UNUSED,
			     deltatime_t use_lifetime UNUSED,
			     uint32_t sa_priority UNUSED,
			     const struct sa_mark *sa_mark UNUSED,
			     unsigned int op UNUSED,
			     const char *text_said UNUSED
#ifdef HAVE_LABELED_IPSEC
			     , const char *policy_label UNSUSED
#endif
			     )
{
	return FALSE;
}

/** netlink_add_sa - Add an SA into the kernel SPDB via netlink
 *
 * @param sa Kernel SA to add/modify
 * @param replace boolean - true if this replaces an existing SA
 * @return bool True if successfull
 */
static bool win2k_add_sa(const struct kernel_sa *sa, bool replace)
{
	return FALSE;
}

/** netlink_del_sa - Delete an SA from the Kernel
 *
 * @param sa Kernel SA to be deleted
 * @return bool True if successfull
 */
static bool win2k_del_sa(const struct kernel_sa *sa)
{
	/* delete an SA */
	return FALSE;
}

static void win2k_pfkey_register_response(const struct sadb_msg *msg)
{
	/* something */
}

/** linux_pfkey_register - Register via PFKEY our capabilities
 *
 */
static void win2k_pfkey_register(void)
{
	/* do something */
}

static bool win2k_get(void)
{
	return TRUE;
}

static ipsec_spi_t win2k_get_spi(const ip_address *src,
				 const ip_address *dst,
				 int proto,
				 bool tunnel_mode,
				 unsigned reqid,
				 ipsec_spi_t min,
				 ipsec_spi_t max,
				 const char *text_said)
{
	return 0;
}

const struct kernel_ops win2k_kernel_ops = {
	.type = USE_WIN2K,
	.inbound_eroute = TRUE,
	.policy_lifetime = TRUE,
	.async_fdp = &win2k_bcast_fd,
	.replay_window = 32,

	.init = win2k_init,
	.pfkey_register = win2k_pfkey_register,
	.pfkey_register_response = win2_pfkey_register_response,
	.process_msg = win2k_process_msg,
	.raw_eroute =  win2k_raw_eroute,
	.add_sa = win2k_add_sa,
	.del_sa = win2k_del_sa,
	.get_sa = NULL,
	.process_queue = NULL,
	.grp_sa = NULL,
	.get_spi = win2k_get_spi,
	.exceptsocket = NULL,
	.docommand = do_command_win2k,
	.opname = "win2k",
	.overlap_supported = FALSE,
	.sha2_truncbug_support = FALSE,
};
#endif /* WIN32_NATIVE */
