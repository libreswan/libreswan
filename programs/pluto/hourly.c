/* randomness machinery
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2006-2007 Michael C Richardson <mcr@xelerance.com>
 * Copyright (C) 2007-2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2007-2008 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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

#include "defs.h"

#include "hourly.h"
#include "timer.h"

#include "ike_spi.h"		/* for refresh_ike_spi_secret() */
#include "ikev2_cookie.h"	/* for refresh_v2_cookie_secret() */
#include "ikev2_ike_session_resume.h"

static void refresh_secrets(struct logger *logger)
{
	/*
	 * Generate the secret value for responder cookies, and
	 * schedule an event for refresh.
	 */
	refresh_ike_spi_secret(logger);
	refresh_v2_cookie_secret(logger);
	refresh_v2_ike_session_resume(logger);
}

void init_secret_timer(struct logger *logger)
{
	enable_periodic_timer(EVENT_REINIT_SECRET, refresh_secrets,
			      deltatime(EVENT_REINIT_SECRET_DELAY), logger);
	refresh_secrets(logger);
}
