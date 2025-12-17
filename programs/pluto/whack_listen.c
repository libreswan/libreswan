/* <<ipsec listen>>, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001,2013-2016 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2011 Mika Ilmaranta <ilmis@foobar.fi>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2014-2020 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2014-2017 Antony Antony <antony@phenome.org>
 * Copyright (C) 2019-2023 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2020 Nupur Agrawal <nupur202000@gmail.com>
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

#include "whack_listen.h"

#include "defs.h"
#include "show.h"
#include "whack.h"
#include "log.h"
#include "ipsecconf/setup.h"
#include "iface.h"		/* for pluto_ike_socket_errqueue; */
#include "pluto_sd.h"
#include "server.h"		/* for listening; */
#include "keys.h"		/* for load_preshared_secrets() */
#include "foodgroups.h"		/* for load_groups() */

void whack_listen(const struct whack_message *wm, struct show *s)
{
	struct logger *logger = show_logger(s);
	const struct whack_listen *wl = &wm->whack.listen;

	/* first extract current values from config */

	const struct config_setup *oco = config_setup_singleton();
	pluto_ike_socket_errqueue = config_setup_yn(oco, KYN_IKE_SOCKET_ERRQUEUE);
	pluto_ike_socket_bufsize = config_setup_option(oco, KBF_IKE_SOCKET_BUFSIZE);

	/* Update MSG_ERRQUEUE settings before listen. */

	bool errqueue_set = false;
	if (wl->ike_socket_errqueue_toggle) {
		errqueue_set = true;
		pluto_ike_socket_errqueue = !pluto_ike_socket_errqueue;
	}

	switch (wl->ike_socket_errqueue) {
	case YN_YES:
		errqueue_set = true;
		pluto_ike_socket_errqueue = true;
		break;
	case YN_NO:
		errqueue_set = true;
		pluto_ike_socket_errqueue = false;
		break;
	case YN_UNSET:
		break;
	}

	if (errqueue_set) {
		llog(RC_LOG, logger, "%s IKE socket MSG_ERRQUEUEs",
		     (pluto_ike_socket_errqueue ? "enabling" : "disabling"));
	}

	/* Update MSG buffer size before listen */

	if (wl->ike_socket_bufsize != 0) {
		pluto_ike_socket_bufsize = wl->ike_socket_bufsize;
		llog(RC_LOG, logger, "set IKE socket buffer to %u", pluto_ike_socket_bufsize);
	}

	/* now put values back into config_setup */
	update_setup_yn(KYN_IKE_SOCKET_ERRQUEUE, (pluto_ike_socket_errqueue ? YN_YES : YN_NO));
	update_setup_option(KBF_IKE_SOCKET_BUFSIZE, pluto_ike_socket_bufsize);

	/* do the deed */

#ifdef USE_SYSTEMD_WATCHDOG
	pluto_sd(PLUTO_SD_RELOADING, SD_REPORT_NO_STATUS, logger);
#endif
	llog(RC_LOG, logger, "listening for IKE messages");
	listening = true;
	find_ifaces(true /* remove dead interfaces */, logger);

	load_preshared_secrets(logger);
	load_groups(logger);
#ifdef USE_SYSTEMD_WATCHDOG
	pluto_sd(PLUTO_SD_READY, SD_REPORT_NO_STATUS, logger);
#endif
}
