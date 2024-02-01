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
#include <sys/un.h>		/* struct sockaddr_un;! */

#include "whack.h"
#include "lsw_socket.h"
#include "lswlog.h"

static void whack_send_reply(int sock, const char *buf, ssize_t len, struct logger *logger)
{
	/* send the secret to pluto */
	if (write(sock, buf, len) != len) {
		/* not fatal() which should be internal to pluto() */
		int e = errno;
		llog_error(logger, e, "write() failed");
		exit(RC_WHACK_PROBLEM);
	}
}

static int whack_read_reply(int sock,
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
			llog_error(logger, e, "read() failed");
			exit(RC_WHACK_PROBLEM);
		}

		if (rl == 0) {
			if (be != buf) {
				llog_error(logger, 0, "last line from pluto too long or unterminated");
			}
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
				llog_error(logger, 0, "log line missing NNN prefix: %*s",
					   (int)(le - ls), ls);
				exit(RC_WHACK_PROBLEM);
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
				if (xauthpass == NULL) {
					llog_error(logger, 0, "unexpected request for xauth password");
					exit(RC_WHACK_PROBLEM);
				}
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
				if (xauthusername == NULL) {
					llog_error(logger, 0, "unexpected request for xauth username");
					exit(RC_WHACK_PROBLEM);
				}
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

int whack_send_msg(struct whack_message *msg, char *ctlsocket,
		   char xauthusername[MAX_XAUTH_USERNAME_LEN],
		   char xauthpass[XAUTH_MAX_PASS_LENGTH],
		   int usernamelen, int xauthpasslen,
		   struct logger *logger)
{
	struct sockaddr_un ctl_addr = {
		.sun_family = AF_UNIX,
		.sun_path  = DEFAULT_CTL_SOCKET,
#ifdef USE_SOCKADDR_LEN
		.sun_len = sizeof(struct sockaddr_un),
#endif
	};

	/* copy socket location */

	fill_and_terminate(ctl_addr.sun_path, ctlsocket, sizeof(ctl_addr.sun_path));

	/*  Pack strings */

	struct whackpacker wp = {
		.msg = msg,
		.str_next = (unsigned char *)msg->string,
		.str_roof = (unsigned char *)&msg->string[sizeof(msg->string)],
	};

	err_t ugh = pack_whack_msg(&wp, logger);

	if (ugh != NULL) {
		llog_error(logger, 0, "send_wack_msg(): can't pack strings: %s", ugh);
		return -1;
	}

	ssize_t len = wp.str_next - (unsigned char *)msg;

	/* Connect to pluto ctl */

	if (access(ctl_addr.sun_path, R_OK | W_OK) < 0) {
		int e = errno;

		switch (e) {
		case EACCES:
			llog_error(logger, e, "no right to communicate with pluto (access(\"%s\"))",
				   ctl_addr.sun_path);
			break;
		case ENOENT:
			llog_error(logger, e, "Pluto is not running (no \"%s\")",
				   ctl_addr.sun_path);
			break;
		default:
			llog_error(logger, e, "access(\"%s\") failed",
				   ctl_addr.sun_path);
			break;
		}
		exit(RC_WHACK_PROBLEM);
	}

	int sock = cloexec_socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		llog_error(logger, errno, "socket() failed");
		exit(RC_WHACK_PROBLEM);
	}

	if (connect(sock, (struct sockaddr *)&ctl_addr,
		    offsetof(struct sockaddr_un, sun_path) + strlen(ctl_addr.sun_path)) < 0) {
		llog_error(logger, errno, "connect(pluto_ctl) failed");
		close(sock);
		exit(RC_WHACK_PROBLEM);
	}

	/* Send message */

	if (write(sock, msg, len) != len) {
		llog_error(logger, errno, "write(pluto_ctl) failed");
		close(sock);
		exit(RC_WHACK_PROBLEM);
	}

	/* read reply (possibly send further messages) */
	int ret = whack_read_reply(sock, xauthusername, xauthpass, usernamelen, xauthpasslen, logger);
	close(sock);

	return ret;
}
