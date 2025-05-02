/*
 * A program to read the configuration file and load a single conn
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012-2014 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2014 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2012-2013 Kim B. Heino <b@bbbs.net>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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
#include "sparse_names.h"
#include "ipsecconf/confread.h"
#include "ipsecconf/confwrite.h"
#include "ipsecconf/starterwhack.h"
#include "addr_lookup.h"	/* for resolve_default_route() */
#ifdef USE_DNSSEC
# include "dnssec.h"
#endif

#ifdef USE_SECCOMP
#include "lswseccomp.h"
#endif

#include "optarg.h"

/*
 * make options valid environment variables
 */
static char *environlize(const char *str)
{
	char *cpy = strndup(str, strlen(str));
	char *cur = cpy;
	while((cur = strchr(cur, '-')) != NULL) {
		*cur++ = '_';
	}
	return cpy;
}

/*
 * See if conn's left or right is %defaultroute and resolve it.
 *
 * XXX: why not let pluto resolve all this like it is already doing?
 * because of MOBIKE.
 */
static void resolve_default_routes(struct starter_conn *conn UNUSED, struct logger *logger)
{
	lset_t verbose_rc_flags = verbose ? (WHACK_STREAM|NO_PREFIX) : LEMPTY;
	resolve_default_route(&conn->end[LEFT_END], &conn->end[RIGHT_END], verbose_rc_flags, logger);
	resolve_default_route(&conn->end[RIGHT_END], &conn->end[LEFT_END], verbose_rc_flags, logger);
}

#ifdef USE_SECCOMP
static void init_seccomp_addconn(uint32_t def_action, struct logger *logger)
{
	scmp_filter_ctx ctx = seccomp_init(def_action);
	if (ctx == NULL) {
		fatal(PLUTO_EXIT_SECCOMP_FAIL, logger, "seccomp_init_addconn() failed!");
	}

	/*
	 * Because on bootup, addconn is started by pluto, any syscall
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
		fatal_errno(PLUTO_EXIT_SECCOMP_FAIL, logger, -rc,
			    "seccomp_load() failed!");
	}
}
#endif

static void add_conn(struct starter_conn *conn,
		     const char *p1, const char *p2, const char *p3,
		     const char *ctlsocket,
		     int *exit_status,
		     struct logger *logger)
{
	/* found name or alias */
	if (conn->state == STATE_ADDED) {
		fprintf(stderr, "\n%s%s%sconn %s already added\n",
			p1, p2, p3,
			conn->name);
		return;
	}

	if (conn->state == STATE_FAILED) {
		fprintf(stderr, "\n%s%s%sconn %s did not load properly\n",
			p1, p2, p3,
			conn->name);
		return;
	}

	if (!confread_validate_conn(conn, logger)) {
		fprintf(stderr, "\n%s%s%sconn %s did not validate\n",
			p1, p2, p3,
			conn->name);
		return;
	}

	/*
	 * Scrub AUTOSTART; conns will need to be
	 * started manually.
	 */
	enum autostart autostart = conn->values[KNCF_AUTO].option;
	if (autostart != AUTOSTART_UNSET &&
	    autostart != AUTOSTART_ADD) {
		if (verbose) {
			name_buf nb;
			printf("  overriding auto=%s with auto=add\n",
			       str_sparse_short(&autostart_names, autostart, &nb));
		}
		conn->values[KNCF_AUTO].option = AUTOSTART_ADD;
	}

	resolve_default_routes(conn, logger);
	int status = starter_whack_add_conn(ctlsocket, conn, logger);
	/* don't loose existing status */
	if (status != 0) {
		(*exit_status) = status;
	}
	conn->state = STATE_ADDED;
}

static bool find_and_add_conn_by_name(const char *connname,
				      struct starter_config *cfg,
				      const char *ctlsocket,
				      int *exit_status,
				      struct logger *logger)
{
	/* find first name match, if any */
	struct starter_conn *conn = NULL;
	TAILQ_FOREACH(conn, &cfg->conns, link)  {
		if (streq(conn->name, connname)) {
			add_conn(conn, "", "", "", ctlsocket, exit_status, logger);
			return true;
		}
	}

	return false; /* not-found */
}

static bool find_and_add_conn_by_alias(const char *connname,
				       struct starter_config *cfg,
				       const char *ctlsocket,
				       int *exit_status,
				       struct logger *logger)
{
	struct starter_conn *conn = NULL;
	TAILQ_FOREACH(conn, &cfg->conns, link) {
		if (lsw_alias_cmp(connname,
				  conn->values[KSCF_CONNALIAS].string)) {
			add_conn(conn, "alias: ", connname, " ", ctlsocket, exit_status, logger);
			return true;
		}
	}

	return false; /* not-found */
}

enum opt {
	OPT_HELP = 'h',
	OPT_CONFIG = 256,
	OPT_VERBOSE,
	OPT_DEBUG,
	OPT_AUTOALL,
	OPT_LISTALL,
	OPT_LISTADD,
	OPT_LISTROUTE,
	OPT_LISTSTART,
	OPT_LISTIGNORE,
	OPT_VARPREFIX,
	OPT_CTLSOCKET,
	OPT_CONFIGSETUP,
	OPT_LISTSTACK,
	OPT_CHECKCONFIG,
	OPT_NOEXPORT,
	OPT_NAME,
};

const struct option optarg_options[] =
{
	{ "config\0<file>", required_argument, NULL, OPT_CONFIG, },
	{ OPT("debug", "help|<debug-flags>"), optional_argument, NULL, OPT_DEBUG, },
	{ "verbose\0", no_argument, NULL, OPT_VERBOSE, },
	{ "autoall\0", no_argument, NULL, OPT_AUTOALL, },
	{ "addall\0", no_argument, NULL, OPT_AUTOALL, }, /* alias, backwards compat */
	{ "listall\0", no_argument, NULL, OPT_LISTALL, },
	{ "listadd\0", no_argument, NULL, OPT_LISTADD, },
	{ "listroute\0", no_argument, NULL, OPT_LISTROUTE, },
	{ "liststart\0", no_argument, NULL, OPT_LISTSTART, },
	{ "listignore\0", no_argument, NULL, OPT_LISTIGNORE, },
	{ "varprefix\0<prefix>", required_argument, NULL, OPT_VARPREFIX, },
	{ "ctlsocket\0<socketfile>", required_argument, NULL, OPT_CTLSOCKET, },
	{ "ctlbase\0>ctlsocket", required_argument, NULL, OPT_CTLSOCKET, }, /* backwards compatibility */
	{ "configsetup\0", no_argument, NULL, OPT_CONFIGSETUP, },
	{ "liststack\0", no_argument, NULL, OPT_LISTSTACK, },
	{ "checkconfig\0", no_argument, NULL, OPT_CHECKCONFIG, },
	{ "noexport\0", no_argument, NULL, OPT_NOEXPORT, },
	{ "help\0", no_argument, NULL, OPT_HELP, },
	/* obsoleted, eat and ignore for compatibility */
	{"defaultroute\0!", required_argument, NULL, 0, },
	{"defaultroutenexthop\0!", required_argument, NULL, 0, },
	{"name\0", required_argument, NULL, OPT_NAME, },
	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
	struct logger *logger = tool_logger(argc, argv);

	bool autoall = false;
	bool configsetup = false;
	bool checkconfig = false;
	const char *export = "export"; /* display export before the foo=bar or not */
	bool
		dolist = false,
		listadd = false,
		listroute = false,
		liststart = false,
		listignore = false,
		listall = false,
		liststack = false;
	const char *configfile = NULL;
	const char *varprefix = "";
	int exit_status = 0;
	const char *ctlsocket = DEFAULT_CTL_SOCKET;
	const char *name = NULL;

#if 0
	/* efence settings */
	extern int EF_PROTECT_BELOW;
	extern int EF_PROTECT_FREE;

	EF_PROTECT_BELOW = 1;
	EF_PROTECT_FREE = 1;
#endif

	/*
	 * NAME terminates argument list early.
	 */

	while (name == NULL) {

		int c = optarg_getopt(logger, argc, argv, "");
		if (c < 0) {
			break;
		}

		switch ((enum opt)c) {
		case OPT_HELP:
			optarg_usage("ipsec addconn", "[<names>]", "");

		case OPT_AUTOALL:
			autoall = true;
			continue;

		case OPT_VERBOSE:
			optarg_verbose(logger, LEMPTY);
			continue;

		case OPT_DEBUG:
			optarg_debug(OPTARG_DEBUG_YES);
			continue;

		case OPT_CONFIGSETUP:
			configsetup = true;
			continue;

		case OPT_CHECKCONFIG:
			checkconfig = true;
			continue;

		case OPT_NOEXPORT:
			export = "";
			continue;

		case OPT_CONFIG:
			configfile = optarg;
			continue;

		case OPT_CTLSOCKET:
			ctlsocket = optarg;
			continue;

		case OPT_LISTADD:
			listadd = true;
			dolist = true;
			continue;

		case OPT_LISTROUTE:
			listroute = true;
			dolist = true;
			continue;

		case OPT_LISTSTART:
			liststart = true;
			dolist = true;
			continue;

		case OPT_LISTSTACK:
			liststack = true;
			dolist = true;
			continue;

		case OPT_LISTIGNORE:
			listignore = true;
			dolist = true;
			continue;

		case OPT_LISTALL:
			listall = true;
			dolist = true;
			continue;

		case OPT_VARPREFIX:
			varprefix = optarg;
			continue;

		case OPT_NAME:
			name = optarg;
			continue;
		}

		bad_case(c);
	}

	/* if nothing to add, then complain */
	if (optind == argc && !autoall && !dolist && !configsetup &&
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

	struct starter_config *cfg;
	if (name != NULL) {
		if (configsetup) {
			llog(ERROR_STREAM, logger, "--conn %s conflicts with --configsetup", name);
			exit(1);
		}
		if (autoall) {
			llog(ERROR_STREAM, logger, "--conn %s conflicts with --autoall", name);
			exit(1);
		}
		cfg = confread_argv(name, argv, optind, logger);
		if (cfg == NULL) {
			llog(RC_LOG, logger, "parsing config arguments failed");
			exit(3);
		}
	} else {
		cfg = confread_load(configfile, configsetup, logger, verbose);
		if (cfg == NULL) {
			llog(RC_LOG, logger, "loading config file '%s' failed", configfile);
			exit(3);
		}
	}

	PASSERT(logger, cfg != NULL);

	if (checkconfig) {
		/* call is NO-OP when CONFIGSETUP */
		if (!confread_validate_conns(cfg, logger)) {
			/* already logged? */
			llog(RC_LOG, logger, "cannot validate config file '%s'", configfile);
			exit(3);
		}
		confread_free(cfg);
		exit(0);
	}

#ifdef USE_SECCOMP
	switch (cfg->setup[KBF_SECCOMP].option) {
		case SECCOMP_ENABLED:
			init_seccomp_addconn(SCMP_ACT_KILL, logger);
		break;
	case SECCOMP_TOLERANT:
		init_seccomp_addconn(SCMP_ACT_ERRNO(EACCES), logger);
		break;
	case SECCOMP_DISABLED:
		break;
	default:
		bad_case(cfg->setup[KBF_SECCOMP].option);
	}
#endif

#ifdef USE_DNSSEC
	unbound_sync_init(cfg->setup[KBF_DO_DNSSEC].option,
			  cfg->setup[KSF_PLUTO_DNSSEC_ROOTKEY_FILE].string,
			  cfg->setup[KSF_PLUTO_DNSSEC_ANCHORS].string,
			  logger);
#endif

	if (autoall) {
		if (verbose > 0)
			printf("loading all conns according to their auto= settings\n");

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
			enum autostart autostart = conn->values[KNCF_AUTO].option;
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
			case AUTOSTART_START:
				break;
			}

			if (!confread_validate_conn(conn, logger)) {
				llog(ERROR_STREAM, logger, "conn %s did not validaten",
				     conn->name);
				continue;
			}

			if (verbose > 0) {
				printf("    %s\n", conn->name);
			}

			resolve_default_routes(conn, logger);
			starter_whack_add_conn(ctlsocket, conn, logger);
		}

		/*
		 * We loaded all connections. Now tell pluto to
		 * listen, then route the conns and resolve default
		 * route.
		 *
		 * Any connections that orient and have +ROUTE will be
		 * routed.
		 */
		if (verbose > 0)
			printf("  Step #2: Listening which will then orient, route, up connections\n");

		starter_whack_listen(ctlsocket, logger);

		if (verbose > 0)
			printf("\n");

	} else if (name != NULL) {

		struct starter_conn *conn = TAILQ_FIRST(&cfg->conns);
		if (conn == NULL) {
			llog(ERROR_STREAM, logger, "no conn %s to load", name);
			exit(1);
		}
		if (!confread_validate_conn(conn, logger)) {
			llog(ERROR_STREAM, logger, "%s did not validate", conn->name);
			exit(1);
		}

		resolve_default_routes(conn, logger);
		exit_status = starter_whack_add_conn(ctlsocket, conn, logger);

	} else {

		/* load named conns, regardless of their state */
		if (verbose > 0) {
			printf("loading named conns:");
		}

		for (int connum = optind; connum < argc; connum++) {
			const char *connname = argv[connum];

			if (verbose > 0) {
				printf(" %s\n", connname);
			}

			if (find_and_add_conn_by_name(connname, cfg, ctlsocket,
						      &exit_status, logger)) {
				continue;
			}

			/* We didn't find name; look for first alias */
			if (find_and_add_conn_by_alias(connname, cfg, ctlsocket,
						       &exit_status, logger)) {
				continue;
			}

			/* we found neither name nor alias */
			exit_status += RC_UNKNOWN_NAME; /* cause non-zero exit code */
			fprintf(stderr, "conn '%s': not found (tried aliases)\n",
				connname);
		}
	}

	if (listall) {

		if (verbose > 0) {
			printf("listing all conns\n");
		}
		struct starter_conn *conn;
		TAILQ_FOREACH(conn, &cfg->conns, link) {
			printf("%s ", conn->name);
		}
		printf("\n");

	} else {

		if (listadd) {
			/* list all conns marked as auto=add */
			if (verbose > 0) {
				printf("listing all conns marked as auto=add\n");
			}
			struct starter_conn *conn;
			TAILQ_FOREACH(conn, &cfg->conns, link) {
				enum autostart autostart = conn->values[KNCF_AUTO].option;
				if (autostart == AUTOSTART_ADD) {
					printf("%s ", conn->name);
				}
			}
		}

		if (listroute) {
			/*
			 * list all conns marked as auto=route or start or
			 * better
			 */
			if (verbose > 0) {
				printf("listing all conns marked as auto=route and auto=up\n");
			}
			struct starter_conn *conn;
			TAILQ_FOREACH(conn, &cfg->conns, link) {
				enum autostart autostart = conn->values[KNCF_AUTO].option;
				if (autostart == AUTOSTART_UP ||
				    autostart == AUTOSTART_START ||
				    autostart == AUTOSTART_ROUTE ||
				    autostart == AUTOSTART_ONDEMAND) {
					printf("%s ", conn->name);
				}
			}
		}

		if (liststart && !listroute) {
			/* list all conns marked as auto=up */
			if (verbose > 0) {
				printf("listing all conns marked as auto=up\n");
			}
			struct starter_conn *conn;
			TAILQ_FOREACH(conn, &cfg->conns, link) {
				enum autostart autostart = conn->values[KNCF_AUTO].option;
				if (autostart == AUTOSTART_UP ||
				    autostart == AUTOSTART_START) {
					printf("%s ", conn->name);
				}
			}
		}

		if (listignore) {
			/* list all conns marked as auto=up */
			if (verbose > 0) {
				printf("listing all conns marked as auto=ignore\n");
			}
			struct starter_conn *conn;
			TAILQ_FOREACH(conn, &cfg->conns, link) {
				enum autostart autostart = conn->values[KNCF_AUTO].option;
				if (autostart == AUTOSTART_IGNORE ||
				    autostart == AUTOSTART_UNSET) {
					printf("%s ", conn->name);
				}
			}
			printf("\n");
		}
	}

	if (liststack) {
		const struct keyword_def *kd;
		for (kd = ipsec_conf_keywords; kd->keyname != NULL; kd++) {
			if (strstr(kd->keyname, "protostack")) {
				if (cfg->setup[kd->field].string) {
					printf("%s\n",
						cfg->setup[kd->field].string);
				} else {
					/* implicit default */
					printf("xfrm\n");
				}
			}
		}
		confread_free(cfg);
		exit(0);
	}

	if (configsetup) {
		const struct keyword_def *kd;

		printf("%s %sconfreadstatus=''\n", export, varprefix);
		printf("%s configfile='%s'\n", export, configfile);
		printf("%s ctlsocket='%s'\n", export, ctlsocket);
		for (kd = ipsec_conf_keywords; kd->keyname != NULL; kd++) {
			if ((kd->validity & kv_config) == 0)
				continue;

			/* don't print backwards compatible aliases */
			if ((kd->validity & kv_alias) != 0)
				continue;

			char *safe_kwname = environlize(kd->keyname);

			switch (kd->type) {
			case kt_string:
			case kt_filename:
			case kt_dirname:
			case kt_host:
				if (cfg->setup[kd->field].string) {
					printf("%s %s%s='%s'\n",
						export, varprefix, safe_kwname,
						cfg->setup[kd->field].string);
				}
				break;

			case kt_bool:
				printf("%s %s%s='%s'\n", export, varprefix,
					safe_kwname,
					bool_str(cfg->setup[kd->field].option));
				break;

			case kt_obsolete:
				break;

			default:
				if (cfg->setup[kd->field].option ||
					cfg->setup[kd->field].set) {
					printf("%s %s%s='%jd'\n",
						export, varprefix, safe_kwname,
						cfg->setup[kd->field].option);
				}
				break;
			}
			free(safe_kwname);
		}
		confread_free(cfg);
		exit(0);
	}

	confread_free(cfg);
#ifdef USE_DNSSEC
	unbound_ctx_free();
#endif
	/*
	 * Only RC_ codes between RC_EXIT_FLOOR (RC_DUPNAME) and
	 * RC_EXIT_ROOF (RC_NEW_V1_STATE) are errors Some starter code
	 * above can also return -1 which is not a valid RC_ code
	 */
	if (exit_status > 0 && (exit_status < RC_EXIT_FLOOR || exit_status >= RC_EXIT_ROOF))
		exit_status = 0;
	exit(exit_status);
}
