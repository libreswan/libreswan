/* get-next-event loop, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002, 2013,2016 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael C Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012-2017 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Wolfgang Nothdurft <wolfgang@linogate.de>
 * Copyright (C) 2016-2021 Andrew Cagney
 * Copyright (C) 2017 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
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

#include "ddos.h"

#include "constants.h"
#include "config_setup.h"

#include "defs.h"
#include "log.h"
#include "whack.h"
#include "show.h"
#include "state.h"		/* for total_halfopen_ike() */
#include "whack_shutdown.h"	/* for whack_shutdown() and exiting_pluto; */

static enum ddos_mode pluto_ddos_mode; /* set below */
static unsigned int pluto_max_halfopen_ike; /* set below */
static unsigned int pluto_ddos_ike_threshold; /* set below */

void set_ddos_mode(enum ddos_mode mode, struct logger *logger)
{
	if (mode == pluto_ddos_mode) {
		name_buf nb;
		llog(RC_LOG, logger,
		     "pluto DDoS protection remains in %s mode",
		     str_sparse_short(&ddos_mode_names, pluto_ddos_mode, &nb));
		return;
	}

	pluto_ddos_mode = mode;
	name_buf nb;
	llog(RC_LOG, logger, "pluto DDoS protection mode set to %s",
	     str_sparse_short(&ddos_mode_names, pluto_ddos_mode, &nb));
}

void whack_ddos(const struct whack_message *wm, struct show *s)
{
	const struct whack_ddos *wd = &wm->whack.ddos;
	set_ddos_mode(wd->mode, show_logger(s));
	/* keep things in sync */
	update_setup_option(KBF_DDOS_MODE, pluto_ddos_mode);
}

bool require_ddos_cookies(void)
{
	if (pluto_ddos_mode == DDOS_FORCE_BUSY) {
		return true;
	}
	if (pluto_ddos_mode == DDOS_AUTO &&
	    total_halfopen_ike() >= pluto_ddos_ike_threshold) {
		return true;
	}
	return false;
}

err_t drop_new_exchanges(struct logger *logger)
{
	if (exiting_pluto) {
		ldbg(logger, "%s() exiting_pluto!", __func__);
		return "exiting pluto";
	}
	if (total_halfopen_ike() >= pluto_max_halfopen_ike) {
		ldbg(logger, "%s() half open count >= %u", __func__, pluto_max_halfopen_ike);
		return "too many half open IKE SAs";
	}
	return false;
}

void init_ddos(const struct config_setup *oco, struct logger *logger UNUSED)
{
	pluto_ddos_mode = config_setup_option(oco, KBF_DDOS_MODE);
	pluto_ddos_ike_threshold = config_setup_option(oco, KBF_DDOS_IKE_THRESHOLD);
	pluto_max_halfopen_ike = config_setup_option(oco, KBF_MAX_HALFOPEN_IKE);
}
