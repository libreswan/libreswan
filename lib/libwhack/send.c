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

#include <unistd.h>		/* for write() */
#include <errno.h>
#include <stdlib.h>		/* for exit() */

#include "whack.h"

#include "lswlog.h"

void whack_send_reply(int sock, const char *buf, ssize_t len, struct logger *logger)
{
	/* send the secret to pluto */
	if (write(sock, buf, len) != len) {
		/* not fatal() which should be internal to pluto() */
		int e = errno;
		llog_error(logger, e, "write() failed");
		exit(RC_WHACK_PROBLEM);
	}
}

#if 0

static int starter_whack_read_reply(int sock,
				    char xauthusername[MAX_XAUTH_USERNAME_LEN],
				    char xauthpass[XAUTH_MAX_PASS_LENGTH],
				    int usernamelen,
				    int xauthpasslen,
				    struct logger *logger)
{
	char buf[4097]; /* arbitrary limit on log line length */
	char *be = buf;
	int exit_status = 0;

	for (;; ) {
		char *ls = buf;
		ssize_t rl = read(sock, be, (buf + sizeof(buf) - 1) - be);

		if (rl < 0) {
			int e = errno;

			fprintf(stderr, "whack: read() failed (%d %s)\n", e,
				strerror(e));
			return RC_WHACK_PROBLEM;
		}
		if (rl == 0) {
			if (be != buf)
				fprintf(stderr,
					"whack: last line from pluto too long or unterminated\n");


			break;
		}

		be += rl;
		*be = '\0';

		for (;; ) {
			char *le = strchr(ls, '\n');

			if (le == NULL) {
				/* move last, partial line to start of buffer */
				memmove(buf, ls, be - ls);
				be -= ls - buf;
				break;
			}
			le++;	/* include NL in line */

			/*
			 * figure out prefix number and how it should
			 * affect our exit status and printing
			 */
			char *lpe = NULL; /* line-prefix-end */
			unsigned long s = strtoul(ls, &lpe, 10);
			if (lpe == ls || *lpe != ' ') {
				/* includes embedded NL, see above */
				fprintf(stderr, "whack: log line missing NNN prefix: %*s",
					(int)(le - ls), ls);
#if 0
				ls = le;
				continue;
#else
				exit(RC_WHACK_PROBLEM);
#endif
			}

			ls = lpe + 1; /* skip NNN_ */

			if (write(STDOUT_FILENO, ls, le - ls) == -1) {
				int e = errno;
				llog_errno(RC_LOG, logger, e, "write() failed, and ignored");
			}

			/*
			 * figure out prefix number and how it should affect
			 * our exit status
			 */

			switch (s) {

			case RC_LOG:
				/*
				 * Ignore; these logs are
				 * informational only.
				 */
				break;

			case RC_ENTERSECRET:
				if (xauthpasslen == 0) {
					xauthpasslen =
						whack_get_secret(xauthpass,
								 XAUTH_MAX_PASS_LENGTH);
				}
				if (xauthpasslen > XAUTH_MAX_PASS_LENGTH) {
					/*
					 * for input >= 128,
					 * xauthpasslen would be 129
					 */
					xauthpasslen =
						XAUTH_MAX_PASS_LENGTH;
					llog_error(logger, 0,
						   "xauth password cannot be >= %d chars",
						   XAUTH_MAX_PASS_LENGTH);
				}
				whack_send_reply(sock, xauthpass, xauthpasslen, logger);
				break;

			case RC_USERPROMPT:
				if (usernamelen == 0) {
					usernamelen = whack_get_value(xauthusername,
								      MAX_XAUTH_USERNAME_LEN);
				}
				if (usernamelen > MAX_XAUTH_USERNAME_LEN) {
					/*
					 * for input >= 128,
					 * useramelen would be 129
					 */
					usernamelen = MAX_XAUTH_USERNAME_LEN;
					llog_error(logger, 0,
						   "username cannot be >= %d chars",
						   MAX_XAUTH_USERNAME_LEN);
				}
				whack_send_reply(sock, xauthusername, usernamelen, logger);

				break;

			default:
				/*
				 * Only RC_ codes between
				 * RC_EXIT_FLOOR (RC_DUPNAME) and
				 * RC_EXIT_ROOF are errors.
				 *
				 * The exit status is sticky so that
				 * incidental logs don't clear or
				 * change it.
				 */
				if (exit_status == 0 && s >= RC_EXIT_FLOOR && s < RC_EXIT_ROOF) {
					exit_status = s;
				}
				break;
			}

			ls = le;
		}
	}
	return exit_status;
}

static int send_whack_msg(struct whack_message *msg, char *ctlsocket, struct logger *logger)
{
	struct sockaddr_un ctl_addr = { .sun_family = AF_UNIX };
	int sock;
	ssize_t len;
	struct whackpacker wp;
	err_t ugh;
	int ret;

	/* copy socket location */
	fill_and_terminate(ctl_addr.sun_path, ctlsocket, sizeof(ctl_addr.sun_path));

	/*  Pack strings */
	wp.msg = msg;
	wp.str_next = (unsigned char *)msg->string;
	wp.str_roof = (unsigned char *)&msg->string[sizeof(msg->string)];

	ugh = pack_whack_msg(&wp, logger);

	if (ugh != NULL) {
		llog_error(logger, 0, "send_wack_msg(): can't pack strings: %s", ugh);
		return -1;
	}

	len = wp.str_next - (unsigned char *)msg;

	/* Connect to pluto ctl */
	sock = cloexec_socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		llog_error(logger, errno, "socket() failed");
		return -1;
	}
	if (connect(sock, (struct sockaddr *)&ctl_addr,
			offsetof(struct sockaddr_un, sun_path) +
				strlen(ctl_addr.sun_path)) <
		0) {
		llog_error(logger, errno, "connect(pluto_ctl) failed");
		close(sock);
		return -1;
	}

	/* Send message */
	if (write(sock, msg, len) != len) {
		llog_error(logger, errno, "write(pluto_ctl) failed");
		close(sock);
		return -1;
	}

	/* read reply */
	{
		char xauthusername[MAX_XAUTH_USERNAME_LEN];
		char xauthpass[XAUTH_MAX_PASS_LENGTH];

		ret = starter_whack_read_reply(sock, xauthusername, xauthpass, 0, 0, logger);
		close(sock);
	}

	return ret;
}
#endif
