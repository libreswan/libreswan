/* Dump known vendor IDs, for libreswan.
 *
 * Copyright (C) 2002-2003 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2005-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007 Ken Bantoft <ken@xelerance.com>
 * Copyright (C) 2008-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013-2018 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 Wolfgang Nothdurft <wolfgang@linogate.de>
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

#include <stdlib.h>	/* for exit() */

#include "lswtool.h"
#include "vendorid.h"
#include "lswlog.h"	/* for log_to_stderr */
#include "lswnss.h"

int main(int argc, char *argv[])
{
#if 0
	log_to_stderr = true;
	cur_debugging = DBG_BASE | DBG_TMI;
#endif
	struct logger *logger = tool_logger(argc, argv);

	if (argc != 1) {
		fprintf(stderr, ("usage:\n"
				 "\tipsec _vendoridcheck\n"
				 "list known Vendor IDs\n"));
		exit(1);
	}

	/*
	 * init_vendorid() uses MD5 which requires NSS!
	 *
	 * Should just hardwire those hashes.
	 */
	init_nss(NULL, (struct nss_flags) { .open_readonly = true}, logger);
	init_vendorid(logger);
	llog_vendorids(NO_PREFIX|WHACK_STREAM, logger);

	/* shhh; try some bonus searches */
	static const struct {
		enum known_vendorid id;
		const char *vid;
	} tests[] = {
		{ VID_OPENSWANORG,   "\x4f\x45", },
		{ VID_OPENSWANORG,   "\x4f\x45\x01", },
		{ VID_OPENSWANORG,   "\x4f\x45\x4f\x01", },
		{ VID_LIBRESWAN_OLD, "\x4f\x45\x4e", },
		{ VID_LIBRESWAN_OLD, "\x4f\x45\x4e\x01", },
		{ VID_LIBRESWAN,     "\x4f\x45\x2d\x4c\x69\x62\x72\x65\x73\x77\x61\x6e\x2d", },
		{ VID_LIBRESWAN,     "\x4f\x45\x2d\x4c\x69\x62\x72\x65\x73\x77\x61\x6e\x2d\x01", },
	};

	FOR_EACH_ELEMENT(t, tests) {
		shunk_t vid = shunk1(t->vid);
		if (DBGP(DBG_TMI)) {
			enum_buf tidb;
			DBG_log("looking up %d [%s]",
				t->id, str_vendorid(t->id, &tidb));
			DBG_dump_hunk(NULL, vid);
		}

		enum known_vendorid id = vendorid_by_shunk(vid);
		if (id != t->id) {
			enum_buf idb, tidb;
			llog_passert(logger, HERE,
				     "lookup for %d [%s] returned %d [%s]",
				     t->id, str_vendorid(t->id, &tidb),
				     id, str_vendorid(id, &idb));
		}
	}

	exit(0);
}
