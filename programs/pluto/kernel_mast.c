/* pfkey interface to the kernel's IPsec mechanism
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
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
 *
 * RCSID $Id: kernel_pfkey.c,v 1.25 2005/08/24 22:50:50 mcr Exp $
 */

#ifdef KLIPS

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/select.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <openswan.h>
#include <openswan/pfkeyv2.h>
#include <openswan/pfkey.h>

#include "sysdep.h"
#include "constants.h"
#include "oswlog.h"

#include "defs.h"
#include "id.h"
#include "connections.h"
#include "state.h"
#include "kernel.h"
#include "kernel_pfkey.h"
#include "timer.h"
#include "log.h"
#include "whack.h"	/* for RC_LOG_SERIOUS */
#ifdef NAT_TRAVERSAL
#include "packet.h"  /* for pb_stream in nat_traversal.h */
#include "nat_traversal.h"
#endif

#include "alg_info.h"
#include "kernel_alg.h"

const struct kernel_ops mast_kernel_ops = {
    kern_name: "mast",
    .overlap_supported = TRUE
    type: USE_MASTKLIPS,
    async_fdp: &pfkeyfd,
    replay_window: 64,
    
    pfkey_register: klips_pfkey_register,
    pfkey_register_response: klips_pfkey_register_response,
    process_queue: pfkey_dequeue,
    process_msg: pfkey_event,
    raw_eroute: NULL,
    shunt_eroute: NULL,
    sag_eroute: NULL,
    add_sa: pfkey_add_sa,
    grp_sa: pfkey_grp_sa,
    del_sa: pfkey_del_sa,
    get_spi: NULL,
    eroute_idle: pfkey_was_eroute_idle,
    inbound_eroute: FALSE,
    policy_lifetime: FALSE,
    init: init_pfkey,
    docommand: NULL,
    set_debug: pfkey_set_debug,
    remove_orphaned_holds: pfkey_remove_orphaned_holds,
    process_ifaces: NULL,
};
#endif /* KLIPS */
