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

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>		/* for getentropy() */
#ifdef __APPLE__
#include <sys/random.h>		/* for getentropy() */
#endif

#include "names.h"
#include "ipsecconf/starterwhack.h"
#include "whack.h"
#include "lswlog.h"
#include "ipsecconf/confread.h"
#include "ipsecconf/setup.h"

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

static int add_conn(const char *ctlsocket,
		    const struct starter_conn *conn,
		    struct logger *logger,
		    enum yn_options async,
		    enum whack_noise noise,
		    const struct whack_autoall *autoall)
{
	struct whack_message msg;
	init_whack_message(&msg, WHACK_FROM_ADDCONN);

	msg.whack_command = WHACK_ADD;
	msg.name = conn->name;
	msg.whack_async = (async == YN_YES);
	msg.whack_autoall = *autoall;

	for (enum config_conn_keyword kw = 1; kw < CONFIG_CONN_KEYWORD_ROOF; kw++) {
		msg.conn[END_ROOF].value[kw] = conn->values[kw].string;
	}

	enum autostart autostart = conn_auto(conn);

	if (!set_whack_end(&msg.end[LEFT_END], &conn->end[LEFT_END])) {
		return -1;
	}
	if (!set_whack_end(&msg.end[RIGHT_END], &conn->end[RIGHT_END])) {
		return -1;
	}

	if (autoall->dry_run && autoall->run == 0) {
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

int starter_whack_add_conn(const char *ctlsocket,
			   const struct starter_conn *conn,
			   struct logger *logger,
			   bool dry_run,
			   enum yn_options async,
			   enum whack_noise noise)
{
	return add_conn(ctlsocket, conn, logger, async, noise,
			&(struct whack_autoall) { .dry_run = dry_run, });
}

static int send_autoall(const char *ctlsocket,
			enum whack_command command,
			const struct whack_autoall *autoall,
			struct logger *logger,
			enum whack_noise noise)
{
	struct whack_message msg;
	init_whack_message(&msg, WHACK_FROM_ADDCONN);
	msg.whack_command = command;
	msg.whack_autoall = *autoall;
	return whack_send_msg(&msg, ctlsocket, NULL, NULL, 0, 0, logger, noise);
}

/*
 * Load all conns marked as auto=add or better.
 *
 * With autoall-reconcile=yes, bracket them with START and STOP so
 * that pluto keeps the unchanged connections and sweeps those that
 * were not loaded.  A dry run asks pluto what it would do instead.
 */

int starter_whack_autoall(const char *ctlsocket,
			  const struct starter_config *cfg,
			  struct logger *logger,
			  bool dry_run,
			  enum yn_options async,
			  enum whack_noise noise,
			  unsigned verbosity)
{
	if (verbosity > 0) {
		printf("loading all conns according to their auto= settings\n");
	}

	struct whack_autoall autoall = {
		.dry_run = dry_run,
	};
	if (config_setup_yn(KYN_AUTOALL_RECONCILE)) {
		/* random and non-zero, like an IKE initiator SPI */
		while (autoall.run == 0) {
			if (getentropy(&autoall.run, sizeof(autoall.run)) != 0) {
				llog_errno(ERROR_STREAM, logger, errno,
					   "not reconciling, getentropy() failed: ");
				autoall.run = 0;
				break;
			}
		}
	}

	if (autoall.run != 0) {
		int status = send_autoall(ctlsocket, WHACK_AUTOALL_START, &autoall, logger, noise);
		if (status != 0) {
			return status;
		}
	}

	/*
	 * First, do the auto=route and auto=add conns to quickly
	 * get routes in place, then do auto=start as these can be
	 * slower.
	 * This mimics behaviour of the old _plutoload
	 */
	if (verbosity > 0)
		printf("  Step #1: Loading auto=add, auto=keep, auto=route, auto=up and auto=start connections\n");

	const struct starter_conn *conn = NULL;
	TAILQ_FOREACH(conn, &cfg->conns, link) {
		enum autostart autostart = conn_auto(conn);
		switch (autostart) {
		case AUTOSTART_UNSET:
		case AUTOSTART_IGNORE:
#if 0
			if (verbosity > 0) {
				printf("    %s ignored\n", conn->name);
			}
#endif
			continue;
		case AUTOSTART_ADD:
		case AUTOSTART_ROUTE:
		case AUTOSTART_ONDEMAND:
		case AUTOSTART_KEEP:
		case AUTOSTART_UP:
			break;
		}

		if (verbosity > 0) {
			printf("    %s\n", conn->name);
		}

		int status = add_conn(ctlsocket, conn, logger, async, noise, &autoall);
		if (status == RC_AUTOALL_CONFLICT) {
			/* superseded, the later run sweeps */
			return status;
		}
		if (status < 0) {
			autoall.unsent++;
		}
	}

	if (verbosity > 0)
		printf("\n");

	if (autoall.run == 0) {
		return 0;
	}

	return send_autoall(ctlsocket, WHACK_AUTOALL_STOP, &autoall, logger, noise);
}
