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

#include <pk11pub.h>

#include "rnd.h"
#include "lswnss.h"
#include "ike_spi.h"		/* for refresh_ike_spi_secret() */
#include "ikev2_cookie.h"	/* for refresh_v2_cookie_secret() */

#include "defs.h"
#include "server.h"
#include "log.h"

/* A true random number generator (we hope)
 *
 * Under LINUX, use NSS for FIPS compliant RNG.
 * Under OpenBSD ("__OpenBSD__" predefined), use arc4random().
 * Otherwise use our own random number generator based on clock skew.
 *   I (ADK) first heard of the idea from John Ioannidis, who heard it
 *   from Matt Blaze and/or Jack Lacy.
 * ??? Why is mixing need for linux but not OpenBSD?
 */

/* Pluto's uses of randomness:
 *
 * - Setting up the "secret_of_the_day".  This changes every hour!  20
 *   bytes a shot.  It is used in building responder cookies.
 *
 * - generating initiator cookies (8 bytes, once per Phase 1 initiation).
 *
 * - IKEv1: 32 bytes per DH local secret.  Once per Aggr/Main Mode exchange and once
 *   per Quick Mode Exchange with PFS.  (Size is our choice, with
 *   tradeoffs.)
 * - IKEv2:
 *
 * - IKEv1: 16 bytes per nonce we generate.  Once per Aggr/Main Mode exchange and
 *   once per Quick Mode exchange.  (Again, we choose the size.)
 * - IKEv2:
 *
 * - 4 bytes per SPI number that we generate.  We choose the SPIs for all
 *   inbound SPIs, one to three per IPSEC SA (one for AH (rare, probably)
 *   one for ESP (almost always), and one for tunnel (very common)).
 *   I don't actually know how the kernel would generate these numbers --
 *   currently Pluto generates them; this isn't the way things will be
 *   done in the future.
 *
 * - 4 bytes per Message ID we need to generate.  One per Quick Mode
 *   exchange.  Eventually, one per informational exchange.
 */

void get_rnd_bytes(void *buffer, size_t length)
{
	SECStatus rv = PK11_GenerateRandom(buffer, length);
	if (rv != SECSuccess) {
		/* XXX: hack */
		struct logger logger = GLOBAL_LOGGER(null_fd);
		passert_nss_error(&logger, HERE, "RNG failed");
	}
}

void fill_rnd_chunk(chunk_t chunk)
{
	get_rnd_bytes(chunk.ptr, chunk.len);
}

static void refresh_secrets(struct logger *unused_logger UNUSED)
{
	/*
	 * Generate the secret value for responder cookies, and
	 * schedule an event for refresh.
	 */
	refresh_ike_spi_secret();
	refresh_v2_cookie_secret();
}

void init_secret(struct logger *logger)
{
	enable_periodic_timer(EVENT_REINIT_SECRET, refresh_secrets,
			      deltatime(EVENT_REINIT_SECRET_DELAY));
	refresh_secrets(logger);
}
