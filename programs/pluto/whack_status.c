/* show functions, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2005-2007 Michael Richardson
 * Copyright (C) 2006-2010 Bart Trojanowski
 * Copyright (C) 2008-2012 Paul Wouters
 * Copyright (C) 2008-2010 David McCullough.
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2017-2019 Andrew Cagney <cagney@gnu.org>
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

#include "sysdep.h"
#include "constants.h"
#include "fips_mode.h"


#include "defs.h"
#include "log.h"
#include "server.h"
#include "state.h"
#include "pluto_stats.h"
#include "connections.h"
#include "kernel.h"
#include "virtual_ip.h"
#include "plutoalg.h"
#include "crypto.h"
#include "ikev1_db_ops.h"
#include "iface.h"
#include "show.h"
#ifdef USE_SECCOMP
#include "pluto_seccomp.h"
#endif
#include "whack_status.h"
#include "whack_connectionstatus.h"	/* for show_connection_statuses() */
#include "whack_showstates.h"

static void show_system_security(struct show *s)
{
	int selinux = libreswan_selinux(show_logger(s));
	bool fips = is_fips_mode();

	show_separator(s);
	show(s, "fips mode=%s;", fips ? "enabled" : "disabled");
	show(s, "SElinux=%s",
		selinux == 0 ? "disabled" : selinux == 1 ? "enabled" : "indeterminate");
#ifdef USE_SECCOMP
	show(s, "seccomp=%s",
		     pluto_seccomp_mode == SECCOMP_ENABLED ? "enabled" :
		     pluto_seccomp_mode == SECCOMP_TOLERANT ? "tolerant" : "disabled");
#else
	show(s, "seccomp=unsupported");
#endif
}

void whack_globalstatus(const struct whack_message *wm, struct show *s)
{
	show_globalstate_status(s);
	whack_showstats(wm, s);
}

void whack_status(struct show *s, const monotime_t now)
{
	show_kernel_interface(s);
	show_ifaces_status(s);
	show_system_security(s);
	show_setup_plutomain(s);
	show_debug_status(s);
	show_setup_natt(s);
	show_virtual_private(s);
	show_kernel_alg_status(s);
	show_ike_alg_status(s);
	show_db_ops_status(s);
	show_connection_statuses(s);
	whack_briefstatus(NULL/*wm:ignored*/, s);
	show_states(s, now);
	whack_shuntstatus(NULL/*wm:ignored*/, s);
}
