/* whack debug routines, for libreswan
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

#include "defs.h"
#include "whack_debug.h"
#include "connections.h"
#include "log.h"
#include "show.h"
#include "fips_mode.h"
#include "visit_connection.h"

static unsigned whack_debug_connection(const struct whack_message *m,
				       struct show *s,
				       struct connection *c)
{
	connection_attach(c, show_logger(s));
	c->logger->debugging = lmod(c->logger->debugging, m->whack_debugging);
	if (LDBGP(DBG_BASE, c->logger)) {
		LLOG_JAMBUF(DEBUG_STREAM|ADD_PREFIX, c->logger, buf) {
			jam_string(buf, "extra_debugging = ");
			jam_lset_short(buf, &debug_names,
				       "+", c->logger->debugging);
		}
	}
	connection_detach(c, show_logger(s));
	return 1; /* the connection counts */
}

void whack_debug(const struct whack_message *m, struct show *s)
{
	struct logger *logger = show_logger(s);
	if (is_fips_mode()) {
		if (lmod_is_set(m->whack_debugging, DBG_PRIVATE)) {
			llog_rc(RC_FATAL, logger,
				"FIPS: --debug private is not allowed in FIPS mode, aborted");
			return; /*don't shutdown*/
		}
		if (lmod_is_set(m->whack_debugging, DBG_CRYPT)) {
			llog_rc(RC_FATAL, logger,
				"FIPS: --debug crypt is not allowed in FIPS mode, aborted");
			return; /*don't shutdown*/
		}
	}
	if (m->name == NULL) {
		/*
		 * This is done in two two-steps so that if either old
		 * or new would cause a debug message to print, it
		 * will be printed.
		 *
		 * XXX: why not unconditionally send what was changed
		 * back to whack?
		 */
		lset_t old_debugging = cur_debugging & DBG_MASK;
		lset_t new_debugging = lmod(old_debugging, m->whack_debugging);
		set_debugging(cur_debugging | new_debugging);
		LDBGP_JAMBUF(DBG_BASE, logger, buf) {
			jam(buf, "old debugging ");
			jam_lset_short(buf, &debug_names,
				       "+", old_debugging);
			jam(buf, " + ");
			jam_lmod(buf, &debug_names, m->whack_debugging);
		}
		LDBGP_JAMBUF(DBG_BASE, logger, buf) {
			jam(buf, "new debugging = ");
			jam_lset_short(buf, &debug_names,
				       "+", new_debugging);
		}
		set_debugging(new_debugging);
	} else if (m->whack_command != WHACK_ADD) {
		visit_root_connection(m, s, whack_debug_connection,
				      /*alias_order*/OLD2NEW,
				      (struct each) {
					      .log_unknown_name = true,
				      });
	}
}
