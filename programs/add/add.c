/*
 * A program to read the configuration file and load a single conn
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012-2014 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2014 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2012-2013 Kim B. Heino <b@bbbs.net>
 * Copyright (C) 2019-2026 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2019 Paul Wouters <pwouters@redhat.com>
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

#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "lswlog.h"
#include "lswcdefs.h"	/* for UNUSED */
#include "lswalloc.h"
#include "lswtool.h"
#include "whack.h"
#include "ipsecconf/setup.h"
#include "ipsecconf/conn.h"
#include "ipsecconf/keywords.h"
#include "ipsecconf/confread.h"
#include "ipsecconf/confwrite.h"
#include "ipsecconf/starterwhack.h"

#ifdef USE_SECCOMP
#include "seccomp_mode.h"
#include "lswseccomp.h"
#endif

#include "optarg.h"

#ifdef USE_SECCOMP
static void init_seccomp(uint32_t def_action, struct logger *logger)
{
	scmp_filter_ctx ctx = seccomp_init(def_action);
	if (ctx == NULL) {
		fatal(PLUTO_EXIT_SECCOMP_FAIL, logger, /*no-errno*/0, "%s() failed!", __func__);
	}

	/*
	 * Because on bootup, add is started by pluto, any syscall
	 * here MUST also appear in the syscall list for "main" inside
	 * pluto
	 */
	LSW_SECCOMP_ADD(access);
	LSW_SECCOMP_ADD(arch_prctl);
	LSW_SECCOMP_ADD(brk);
	LSW_SECCOMP_ADD(bind);
	LSW_SECCOMP_ADD(clone);
	LSW_SECCOMP_ADD(clock_gettime);
	LSW_SECCOMP_ADD(close);
	LSW_SECCOMP_ADD(connect);
	LSW_SECCOMP_ADD(epoll_create);
	LSW_SECCOMP_ADD(epoll_create1);
	LSW_SECCOMP_ADD(epoll_ctl);
	LSW_SECCOMP_ADD(epoll_wait);
	LSW_SECCOMP_ADD(epoll_pwait);
	LSW_SECCOMP_ADD(exit_group);
	LSW_SECCOMP_ADD(faccessat);
	LSW_SECCOMP_ADD(fcntl);
	LSW_SECCOMP_ADD(fstat);
	LSW_SECCOMP_ADD(futex);
	LSW_SECCOMP_ADD(getdents);
	LSW_SECCOMP_ADD(getegid);
	LSW_SECCOMP_ADD(getpid);
	LSW_SECCOMP_ADD(getrlimit);
	LSW_SECCOMP_ADD(geteuid);
	LSW_SECCOMP_ADD(getgid);
	LSW_SECCOMP_ADD(getrandom);
	LSW_SECCOMP_ADD(getuid);
	LSW_SECCOMP_ADD(ioctl);
	LSW_SECCOMP_ADD(mmap);
	LSW_SECCOMP_ADD(lseek);
	LSW_SECCOMP_ADD(munmap);
	LSW_SECCOMP_ADD(mprotect);
	LSW_SECCOMP_ADD(newfstatat);
	LSW_SECCOMP_ADD(open);
	LSW_SECCOMP_ADD(openat);
	LSW_SECCOMP_ADD(pipe2);
	LSW_SECCOMP_ADD(poll);
	LSW_SECCOMP_ADD(prctl);
	LSW_SECCOMP_ADD(read);
	LSW_SECCOMP_ADD(readlink);
	LSW_SECCOMP_ADD(recvfrom);
	LSW_SECCOMP_ADD(rt_sigaction);
	LSW_SECCOMP_ADD(rt_sigprocmask);
	LSW_SECCOMP_ADD(sendto);
	LSW_SECCOMP_ADD(setsockopt);
	LSW_SECCOMP_ADD(set_robust_list);
	LSW_SECCOMP_ADD(set_tid_address);
	LSW_SECCOMP_ADD(sigreturn);
	LSW_SECCOMP_ADD(socket);
	LSW_SECCOMP_ADD(socketcall);
	LSW_SECCOMP_ADD(socketpair);
	LSW_SECCOMP_ADD(stat);
	LSW_SECCOMP_ADD(statfs);
	LSW_SECCOMP_ADD(sysinfo);
	LSW_SECCOMP_ADD(uname);
	LSW_SECCOMP_ADD(waitpid);
	LSW_SECCOMP_ADD(write);

#ifdef USE_EFENCE
	LSW_SECCOMP_ADD(madvise);
#endif

	int rc = seccomp_load(ctx);
	if (rc < 0) {
		seccomp_release(ctx);
		fatal(PLUTO_EXIT_SECCOMP_FAIL, logger, -rc, "seccomp_load() failed!");
	}
}
#endif

PRINTF_LIKE(4)
static void fprint_conn(FILE *file,
			const struct starter_conn *conn,
			const char *alias,
			const char *fmt, ...)
{
	if (alias != NULL) {
		fprintf(file, "alias %s ", alias);
	}
	fprintf(file, "conn %s: ", conn->name);
	va_list ap;
	va_start(ap, fmt);
	vfprintf(file, fmt, ap);
	va_end(ap);
	fprintf(file, "\n");
}

static void add_conn(struct starter_conn *conn,
		     const char *autostart,
		     bool dry_run,
		     enum yn_options async,
		     const char *alias/*possibly-NULL*/,
		     const char *ctlsocket, int *exit_status,
		     struct logger *logger,
		     enum whack_noise noise)
{
	/* found name or alias */
	if (conn->state == STATE_ADDED) {
		fprint_conn(stderr, conn, alias, "already added");
		return;
	}

	if (conn->state == STATE_FAILED) {
		fprint_conn(stderr, conn, alias, "did not load properly");
		return;
	}

	/* force (or clear) autostart; caller's checked it is sane */
	if (verbose) {
		const char *conn_autostart = conn->values[KWS_AUTO].string;
		if (conn_autostart == NULL) {
			if (autostart != NULL) {
				fprint_conn(stderr, conn, alias, "setting auto=%s",
					    autostart);
			}
		} else if (autostart == NULL) {
			fprint_conn(stderr, conn, alias, "clearing auto=%s",
				    conn_autostart);
		} else if (!streq(conn_autostart, autostart)) {
			fprint_conn(stderr, conn, alias, "overriding auto=%s with auto=%s",
				    conn_autostart, autostart);
		}
	}

	pfreeany(conn->values[KWS_AUTO].string);
	conn->values[KWS_AUTO].string = clone_str(autostart, "auto");

	if (verbose) {
		fprintf(stdout, "  sending to pluto");
		fprintf(stdout, "\n");
	}

	int status = starter_whack_add_conn(ctlsocket, conn, logger,
					    dry_run, async,
					    noise);

	/* don't loose existing status */
	if (status != 0) {
		(*exit_status) = status;
	}
	conn->state = STATE_ADDED;
}

static bool find_and_add_conn_by_name(const char *connname,
				      const char *autostart,
				      bool dry_run,
				      enum yn_options async,
				      struct starter_config *cfg,
				      const char *ctlsocket,
				      int *exit_status,
				      struct logger *logger,
				      enum whack_noise noise)
{
	/* find first name match, if any */
	struct starter_conn *conn = NULL;
	TAILQ_FOREACH(conn, &cfg->conns, link)  {
		if (streq(conn->name, connname)) {
			add_conn(conn, autostart, dry_run, async,
				 /*alias*/NULL, ctlsocket,
				 exit_status, logger, noise);
			return true;
		}
	}

	return false; /* not-found */
}

static bool find_and_add_conn_by_alias(const char *connname,
				       const char *autostart,
				       bool dry_run,
				       enum yn_options async,
				       struct starter_config *cfg,
				       const char *ctlsocket,
				       int *exit_status,
				       struct logger *logger,
				       enum whack_noise noise)
{
	bool found = false;

	struct starter_conn *conn = NULL;
	TAILQ_FOREACH(conn, &cfg->conns, link) {
		if (lsw_alias_cmp(connname,
				  conn->values[KWS_CONNALIAS].string)) {
			add_conn(conn, autostart,
				 dry_run, async,
				 connname, ctlsocket, exit_status, logger, noise);
			found = true;
		}
	}

	return found; /* not-found */
}

enum opt {
	OPT_DRY_RUN = 'n',
	OPT_DEBUG = 256,
	OPT_HELP,
	OPT_CONFIG,
	OPT_VERBOSE,
	OPT_QUIET,
	OPT_AUTO,
	OPT_AUTOALL,
	OPT_CTLSOCKET,
	OPT_CHECKCONFIG,
	OPT_ASYNC,
};

const struct option optarg_options[] =
{
	{ OPT("help"), no_argument, NULL, OPT_HELP, },
	{ OPT("checkconfig"), no_argument, NULL, OPT_CHECKCONFIG, },
	{ OPT("auto", "<auto>"), required_argument, NULL, OPT_AUTO, },
	{ OPT("autoall"), no_argument, NULL, OPT_AUTOALL, },
	{ REPLACE_OPT("addall", "autoall", "2.9"), no_argument, NULL, OPT_AUTOALL, }, /* alias, backwards compat */

	HEADING_OPT("  Load alternate 'ipsec.conf' file:"),
	{ OPT("config", "<ipsec.conf>"), required_argument, NULL, OPT_CONFIG, },

	HEADING_OPT("  Display more details:"),
	{ OPT("debug", "help|<debug-flags>"), optional_argument, NULL, OPT_DEBUG, },
	{ OPT("verbose"), no_argument, NULL, OPT_VERBOSE, },
	{ OPT("quiet"), no_argument, NULL, OPT_QUIET, },
	{ OPT("dry-run"), no_argument, NULL, OPT_DRY_RUN, },

	HEADING_OPT("  Override default pluto socket:"),
	{ OPT("ctlsocket", "<socketfile>"), required_argument, NULL, OPT_CTLSOCKET, },
	{ REPLACE_OPT("ctlbase", "ctlsocket", "3.22"), required_argument, NULL, OPT_CTLSOCKET, }, /* backwards compatibility */

	ASYNC_OPTS,

	/* obsoleted, eat and ignore for compatibility */
	{ IGNORE_OPT("defaultroute", "3.8"), required_argument, NULL, 0, },
	{ IGNORE_OPT("defaultroutenexthop", "3.8"), required_argument, NULL, 0, },
	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
	struct logger *logger = tool_logger(argc, argv);

	bool autoall = false;
	const char *autostart = AUTOSTART_UNSET; /*aka 0*/
	bool checkconfig = false;
	const char *configfile = NULL;
	int exit_status = 0;
	const char *ctlsocket = DEFAULT_CTL_SOCKET;
	enum whack_noise noise = NOISY_WHACK;
	bool dry_run = false;
	enum yn_options async = 0;

#if 0
	/* efence settings */
	extern int EF_PROTECT_BELOW;
	extern int EF_PROTECT_FREE;

	EF_PROTECT_BELOW = 1;
	EF_PROTECT_FREE = 1;
#endif

	while (true) {

		int c = optarg_getopt(logger, argc, argv);
		if (c < 0) {
			break;
		}

		switch ((enum opt)c) {
		case OPT_HELP:
			optarg_usage("ipsec add", "<connection-name> ...",
				     "By default, 'add' will load <connection-name> into pluto.\n");

		case OPT_AUTO:
		{
			/* force autostart, if reasonable */
			enum autostart opt_autostart = optarg_sparse(logger, AUTOSTART_UNSET, &autostart_names);
			switch (opt_autostart) {
			case AUTOSTART_UNSET:
			case AUTOSTART_ADD:
			case AUTOSTART_IGNORE:
				optarg_fatal(logger, "--auto=%s invalid", optarg);
				/* no-return */
			case AUTOSTART_KEEP:
			case AUTOSTART_ROUTE:
			case AUTOSTART_ONDEMAND:
			case AUTOSTART_UP:
				/* sure ... */
				break;
			}
			autostart = optarg;
			continue;
		}

		case OPT_AUTOALL:
			autoall = true;
			continue;

		case OPT_VERBOSE:
			optarg_verbose(logger, LEMPTY);
			continue;

		case OPT_DEBUG:
			optarg_debug(OPTARG_DEBUG_YES);
			continue;

		case OPT_QUIET:
			noise = QUIET_WHACK;
			continue;

		case OPT_CHECKCONFIG:
			checkconfig = true;
			continue;

		case OPT_CONFIG:
			configfile = optarg;
			continue;

		case OPT_CTLSOCKET:
			ctlsocket = optarg;
			continue;

		case OPT_DRY_RUN:
			dry_run = true;
			continue;

		case OPT_ASYNC:
			async = optarg_yn(logger, YN_YES);
			continue;

		}

		bad_case(c);
	}

	/* if nothing to add, then complain */
	if (optind == argc &&
	    !autoall &&
	    !checkconfig) {
		llog(RC_LOG, logger, "nothing to do, see --help");
		exit(1);
	}

	if (configfile == NULL) {
		configfile = IPSEC_CONF;
	}
	if (verbose > 0) {
		printf("opening file: %s\n", configfile);
	}

	struct starter_config *cfg = confread_load(configfile, false, logger, verbose);
	if (cfg == NULL) {
		llog(RC_LOG, logger, "loading config file '%s' failed", configfile);
		exit(3);
	}

	PASSERT(logger, cfg != NULL);

	if (checkconfig) {
		/* call is NO-OP when checkconfig */
		confread_free(cfg);
		free_config_setup();
		exit(0);
	}

#ifdef USE_SECCOMP
	enum seccomp_mode seccomp = config_setup_option(KBF_SECCOMP);
	switch (seccomp) {
	case SECCOMP_ENABLED:
		init_seccomp(SCMP_ACT_KILL, logger);
		break;
	case SECCOMP_TOLERANT:
		init_seccomp(SCMP_ACT_ERRNO(EACCES), logger);
		break;
	case SECCOMP_DISABLED:
		break;
	default:
		bad_case(seccomp);
	}
#endif

	if (autoall) {
		if (verbose > 0) {
			printf("loading all conns according to their auto= settings\n");
		}

		if (async == 0) {
			async = YN_YES;
		}

		/*
		 * Load all conns marked as auto=add or better.
		 * First, do the auto=route and auto=add conns to quickly
		 * get routes in place, then do auto=start as these can be
		 * slower.
		 * This mimics behaviour of the old _plutoload
		 */
		if (verbose > 0)
			printf("  Step #1: Loading auto=add, auto=keep, auto=route, auto=up and auto=start connections\n");

		struct starter_conn *conn = NULL;
		TAILQ_FOREACH(conn, &cfg->conns, link) {
			enum autostart autostart = conn_auto(conn);
			switch (autostart) {
			case AUTOSTART_UNSET:
			case AUTOSTART_IGNORE:
#if 0
				if (verbose > 0) {
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

			if (verbose > 0) {
				printf("    %s\n", conn->name);
			}

			starter_whack_add_conn(ctlsocket, conn, logger,
					       dry_run, async, noise);
		}

		if (verbose > 0)
			printf("\n");

	} else {

		if (async == 0) {
			async = YN_NO;
		}

		/* load named conns, regardless of their state */
		for (int connum = optind; connum < argc; connum++) {
			const char *connname = argv[connum];

			if (verbose > 0) {
				fprintf(stdout, "loading conns matching %s:", connname);
				fprintf(stdout, "\n");

			}

			if (find_and_add_conn_by_name(connname, autostart,
						      dry_run, async,
						      cfg, ctlsocket,
						      &exit_status, logger, noise)) {
				continue;
			}

			/* We didn't find name; look for first alias */
			if (find_and_add_conn_by_alias(connname, autostart,
						       dry_run, async,
						       cfg, ctlsocket,
						       &exit_status, logger, noise)) {
				continue;
			}

			/* we found neither name nor alias */
			exit_status += RC_UNKNOWN_NAME; /* cause non-zero exit code */
			fprintf(stderr, "conn %s: not found (tried aliases)\n", connname);
		}
	}

	confread_free(cfg);
	free_config_setup();

	/*
	 * Only RC_ codes between RC_EXIT_FLOOR (RC_DUPNAME) and
	 * RC_EXIT_ROOF (RC_NEW_V1_STATE) are errors Some starter code
	 * above can also return -1 which is not a valid RC_ code
	 */
	if (exit_status > 0 && (exit_status < RC_EXIT_FLOOR || exit_status >= RC_EXIT_ROOF))
		exit_status = 0;
	exit(exit_status);
}
