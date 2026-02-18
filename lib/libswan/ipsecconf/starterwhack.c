/*
 * Libreswan whack functions to communicate with pluto (whack.c)
 *
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2004-2006 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2010-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2011 Mattias Walström <lazzer@vmlinux.org>
 * Copyright (C) 2012-2017 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Philippe Vouters <Philippe.Vouters@laposte.net>
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2016, Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
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

#include <stdbool.h>
#include <stdio.h>

#include "ipsecconf/starterwhack.h"
#include "whack.h"
#include "ipsecconf/confread.h"

static bool set_whack_end(struct whack_end *w,
			  const struct starter_end *l)
{
	const char *lr = l->leftright;
	w->leftright = lr;

	for (enum config_conn_keyword kw = 1; kw < CONFIG_CONN_KEYWORD_ROOF; kw++) {
		w->conn->value[kw] = l->values[kw].string;
	}

	return true;
}

int starter_whack_add_conn(const char *ctlsocket,
			   const struct starter_conn *conn,
			   struct logger *logger,
			   bool dry_run,
			   enum yn_options async,
			   enum whack_noise noise)
{
	struct whack_message msg;
	init_whack_message(&msg, WHACK_FROM_ADDCONN);

	msg.whack_command = WHACK_ADD;
	msg.name = conn->name;
	msg.whack_async = (async == YN_YES);

	for (enum config_conn_keyword kw = 1; kw < CONFIG_CONN_KEYWORD_ROOF; kw++) {
		msg.conn[END_ROOF].value[kw] = conn->values[kw].string;
	}

	msg.autostart = conn->values[KNCF_AUTO].option;

	if (!set_whack_end(&msg.end[LEFT_END], &conn->end[LEFT_END])) {
		return -1;
	}
	if (!set_whack_end(&msg.end[RIGHT_END], &conn->end[RIGHT_END])) {
		return -1;
	}

	if (dry_run) {
		enum autostart autostart = conn->values[KNCF_AUTO].option;
		printf("ipsec add");
		if (autostart != 0) {
			name_buf asb;
			printf(" --auto=%s",
			       str_sparse_short(&autostart_names, autostart, &asb));
		}
		printf(" %s\n", conn->name);
		return 0;
	}

	int r = whack_send_msg(&msg, ctlsocket, NULL, NULL, 0, 0, logger, noise);
	if (r != 0)
		return r;

	return 0;
}
