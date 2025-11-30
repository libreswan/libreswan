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

#include <sys/types.h>
#include <sys/un.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "lsw_socket.h"

#include "ttodata.h"

#include "ipsecconf/starterwhack.h"
#include "ipsecconf/confread.h"
#include "ipsecconf/keywords.h"
#include "lswalloc.h"
#include "lswlog.h"
#include "whack.h"
#include "id.h"
#include "ip_address.h"
#include "ip_info.h"
#include "lswlog.h"

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
			   struct logger *logger)
{
	struct whack_message msg;
	init_whack_message(&msg, WHACK_FROM_ADDCONN);

	msg.whack_command = WHACK_ADD;
	msg.name = conn->name;

	for (enum config_conn_keyword kw = 1; kw < CONFIG_CONN_KEYWORD_ROOF; kw++) {
		msg.conn[END_ROOF].value[kw] = conn->values[kw].string;
	}

	msg.type = conn->values[KNCF_TYPE].option;
	msg.authby = conn->values[KWS_AUTHBY].string;

	msg.never_negotiate_shunt = conn->never_negotiate_shunt;
	msg.negotiation_shunt = conn->negotiation_shunt;
	msg.failure_shunt = conn->failure_shunt;
	msg.autostart = conn->values[KNCF_AUTO].option;

	msg.debug = conn->values[KWS_DEBUG].string;

	if (conn->values[KNCF_XAUTHBY].set)
		msg.xauthby = conn->values[KNCF_XAUTHBY].option;
	if (conn->values[KNCF_XAUTHFAIL].set)
		msg.xauthfail = conn->values[KNCF_XAUTHFAIL].option;

	if (!set_whack_end(&msg.end[LEFT_END], &conn->end[LEFT_END])) {
		return -1;
	}
	if (!set_whack_end(&msg.end[RIGHT_END], &conn->end[RIGHT_END])) {
		return -1;
	}

	msg.phase2 = conn->values[KNCF_PHASE2].option;

	int r = whack_send_msg(&msg, ctlsocket, NULL, NULL, 0, 0, logger);
	if (r != 0)
		return r;

	return 0;
}

int starter_whack_listen(const char *ctlsocket, struct logger *logger)
{
	struct whack_message msg;
	init_whack_message(&msg, WHACK_FROM_ADDCONN);
	msg.whack_command = WHACK_LISTEN;
	return whack_send_msg(&msg, ctlsocket, NULL, NULL, 0, 0, logger);
}
