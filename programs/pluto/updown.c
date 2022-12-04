/* routines that interface with the kernel's IPsec mechanism, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2010  D. Hugh Redelmeier.
 * Copyright (C) 2003-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008-2010 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2010 Bart Trojanowski <bart@jukie.net>
 * Copyright (C) 2009-2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2010 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2012-2015 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Kim B. Heino <b@bbbs.net>
 * Copyright (C) 2016-2022 Andrew Cagney
 * Copyright (C) 2019 Paul Wouters <pwouters@redhat.com>
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

#include <errno.h>

#include "ip_info.h"

#include "defs.h"
#include "state.h"
#include "connections.h"
#include "log.h"
#include "kernel.h"

static bool invoke_command(const char *verb, const char *verb_suffix, const char *cmd,
			   struct logger *logger)
{
#	define CHUNK_WIDTH	80	/* units for cmd logging */
	if (DBGP(DBG_BASE)) {
		int slen = strlen(cmd);
		int i;

		DBG_log("executing %s%s: %s",
			verb, verb_suffix, cmd);
		DBG_log("popen cmd is %d chars long", slen);
		for (i = 0; i < slen; i += CHUNK_WIDTH)
			DBG_log("cmd(%4d):%.*s:", i,
				slen-i < CHUNK_WIDTH? slen-i : CHUNK_WIDTH,
				&cmd[i]);
	}
#	undef CHUNK_WIDTH


	{
		/*
		 * invoke the script, catching stderr and stdout
		 * It may be of concern that some file descriptors will
		 * be inherited.  For the ones under our control, we
		 * have done fcntl(fd, F_SETFD, FD_CLOEXEC) to prevent this.
		 * Any used by library routines (perhaps the resolver or
		 * syslog) will remain.
		 */
		FILE *f = popen(cmd, "r");

		if (f == NULL) {
#ifdef HAVE_BROKEN_POPEN
			/*
			 * See bug #1067  Angstrom Linux on a arm7 has no
			 * popen()
			 */
			if (errno == ENOSYS) {
				/*
				 * Try system(), though it will not give us
				 * output
				 */
				DBG_log("unable to popen(), falling back to system()");
				system(cmd);
				return true;
			}
#endif
			llog(RC_LOG_SERIOUS, logger,
				    "unable to popen %s%s command",
				    verb, verb_suffix);
			return false;
		}

		/* log any output */
		for (;; ) {
			/*
			 * if response doesn't fit in this buffer, it will
			 * be folded
			 */
			char resp[256];

			if (fgets(resp, sizeof(resp), f) == NULL) {
				if (ferror(f)) {
					llog_error(logger, errno,
						   "fgets failed on output of %s%s command",
						   verb, verb_suffix);
					pclose(f);
					return false;
				} else {
					passert(feof(f));
					break;
				}
			} else {
				char *e = resp + strlen(resp);

				if (e > resp && e[-1] == '\n')
					e[-1] = '\0'; /* trim trailing '\n' */
				llog(RC_LOG, logger, "%s%s output: %s", verb,
					    verb_suffix, resp);
			}
		}

		/* report on and react to return code */
		{
			int r = pclose(f);

			if (r == -1) {
				llog_error(logger, errno,
					   "pclose failed for %s%s command",
					   verb, verb_suffix);
				return false;
			} else if (WIFEXITED(r)) {
				if (WEXITSTATUS(r) != 0) {
					llog(RC_LOG_SERIOUS, logger,
						    "%s%s command exited with status %d",
						    verb, verb_suffix,
						    WEXITSTATUS(r));
					return false;
				}
			} else if (WIFSIGNALED(r)) {
				llog(RC_LOG_SERIOUS, logger,
					    "%s%s command exited with signal %d",
					    verb, verb_suffix, WTERMSIG(r));
				return false;
			} else {
				llog(RC_LOG_SERIOUS, logger,
					    "%s%s command exited with unknown status %d",
					    verb, verb_suffix, r);
				return false;
			}
		}
	}
	return true;
}

static bool do_updown_verb(const char *verb,
			   const struct connection *c,
			   const struct spd_route *sr,
			   struct state *st,
			   /* either st, or c's logger */
			   struct logger *logger)
{
	/*
	 * Figure out which verb suffix applies.
	 */
	const char *verb_suffix;

	{
		const struct ip_info *host_afi = address_info(sr->local->host->addr);
		const struct ip_info *child_afi = selector_info(sr->local->client);
		if (host_afi == NULL || child_afi == NULL) {
			llog_pexpect(logger, HERE, "unknown address family");
			return false;
		}

		const char *hs;
		switch (host_afi->af) {
		case AF_INET:
			hs = "-host";
			break;
		case AF_INET6:
			hs = "-host-v6";
			break;
		default:
			bad_case(host_afi->af);
		}

		const char *cs;
		switch (child_afi->af) {
		case AF_INET:
			cs = "-client"; /* really child; legacy name */
			break;
		case AF_INET6:
			cs = "-client-v6"; /* really child; legacy name */
			break;
		default:
			bad_case(child_afi->af);
		}

		verb_suffix = selector_range_eq_address(sr->local->client, sr->local->host->addr) ? hs : cs;
	}

	dbg("kernel: command executing %s%s", verb, verb_suffix);

	char common_shell_out_str[2048];
	if (!fmt_common_shell_out(common_shell_out_str,
				  sizeof(common_shell_out_str), c, sr,
				  st)) {
		llog(RC_LOG_SERIOUS, logger,
			    "%s%s command too long!", verb,
			    verb_suffix);
		return false;
	}

	/* must free */
	char *cmd = alloc_printf("2>&1 "      /* capture stderr along with stdout */
				 "PLUTO_VERB='%s%s' "
				 "%s"         /* other stuff */
				 "%s",        /* actual script */
				 verb, verb_suffix,
				 common_shell_out_str,
				 c->local->config->child.updown);
	if (cmd == NULL) {
		llog(RC_LOG_SERIOUS, logger,
			    "%s%s command too long!", verb,
			    verb_suffix);
		return false;
	}

	bool ok = invoke_command(verb, verb_suffix, cmd, logger);
	pfree(cmd);
	return ok;
}

bool do_updown(enum updown updown_verb,
	       const struct connection *c,
	       const struct spd_route *spd,
	       struct state *st,
	       /* either st, or c's logger */
	       struct logger *logger)
{
#if 0
	/*
	 * Depending on context, logging for either the connection or
	 * the state?
	 *
	 * The sec_label code violates this expectation somehow.
	 */
	PEXPECT(logger, ((c != NULL && c->logger == logger) ||
			 (st != NULL && st->st_logger == logger)));
#endif

	const char *verb;
	switch (updown_verb) {
#define C(E,N) case E: verb = N; break
		C(UPDOWN_PREPARE, "prepare");
		C(UPDOWN_ROUTE, "route");
		C(UPDOWN_UNROUTE, "unroute");
		C(UPDOWN_UP, "up");
		C(UPDOWN_DOWN, "down");
#ifdef HAVE_NM
		C(UPDOWN_DISCONNECT_NM, "disconnectNM");
#endif
#undef C
	default:
		bad_case(updown_verb);
	}

	/*
	 * Support for skipping updown, eg leftupdown=""
	 * Useful on busy servers that do not need to use updown for anything
	 */
	const char *updown = c->local->config->child.updown;
	if (updown == NULL) {
		ldbg(logger, "kernel: skipped updown %s command - disabled per policy", verb);
		return true;
	}
	ldbg(logger, "kernel: running updown command \"%s\" for verb %s ", updown, verb);

	return do_updown_verb(verb, c, spd, st, logger);
}
