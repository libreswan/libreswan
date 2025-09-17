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
#include "ipsecconf/config_setup.h"
#include "ipsecconf/confread.h"
#include "ipsecconf/confwrite.h"
#include "ipsecconf/starterwhack.h"
#ifdef USE_DNSSEC
# include "dnssec.h"
#endif

#ifdef USE_SECCOMP
#include "seccomp_mode.h"
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

#ifdef USE_SECCOMP
static void init_seccomp_addconn(uint32_t def_action, struct logger *logger)
{
	scmp_filter_ctx ctx = seccomp_init(def_action);
	if (ctx == NULL) {
		fatal(PLUTO_EXIT_SECCOMP_FAIL, logger, /*no-errno*/0, "seccomp_init_addconn() failed!");
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

static void add_conn(struct starter_conn *conn, const char *alias/*possibly-NULL*/,
		     const char *ctlsocket, int *exit_status,
		     struct logger *logger)
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

	/*
	 * Scrub AUTOSTART; conns will need to be
	 * started manually.
	 */
	enum autostart autostart = conn->values[KNCF_AUTO].option;
	switch (autostart) {
	case AUTOSTART_UNSET:
	case AUTOSTART_ADD:
	case AUTOSTART_IGNORE:
	case AUTOSTART_KEEP:
		break;
	case AUTOSTART_START:
	case AUTOSTART_ROUTE:
	case AUTOSTART_ONDEMAND:
	case AUTOSTART_UP:
	{
		name_buf nb;
		fprint_conn(stderr, conn, alias, "overriding auto=%s with auto=add",
			    str_sparse_short(&autostart_names, autostart, &nb));
		conn->values[KNCF_AUTO].option = AUTOSTART_ADD;
	}

	}

	if (verbose) {
		fprintf(stdout, "  sending to pluto");
		fprintf(stdout, "\n");
	}

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
			add_conn(conn, NULL, ctlsocket, exit_status, logger);
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
	bool found = false;

	struct starter_conn *conn = NULL;
	TAILQ_FOREACH(conn, &cfg->conns, link) {
		if (lsw_alias_cmp(connname,
				  conn->values[KSCF_CONNALIAS].string)) {
			add_conn(conn, connname, ctlsocket, exit_status, logger);
			found = true;
		}
	}

	return found; /* not-found */
}

struct configsetup_options {
	const char *name;
	const char *export;
	const char *varprefix;
};

PRINTF_LIKE(3)
static void print_option(const struct configsetup_options po,
			 const char *kwname,
			 const char *fmt,
			 ...)
{
	if (strlen(po.name) > 0) {
		va_list ap;
		va_start(ap, fmt);
		vprintf(fmt, ap);
		va_end(ap);
		printf("\n");
		return;
	}
	if (strlen(po.export) > 0) {
		printf("%s ", po.export);
	}
	char *safe_kwname = environlize(kwname);
	printf("%s%s='", po.varprefix, safe_kwname);
	pfreeany(safe_kwname);
	va_list ap;
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("'\n");
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
	{ OPT("help"), no_argument, NULL, OPT_HELP, },
	{ OPT("checkconfig"), no_argument, NULL, OPT_CHECKCONFIG, },
	{ OPT("autoall"), no_argument, NULL, OPT_AUTOALL, },
	{ REPLACE_OPT("addall", "autoall", "2.9"), no_argument, NULL, OPT_AUTOALL, }, /* alias, backwards compat */

	HEADING_OPT("  Load alternate 'ipsec.conf' file:"),
	{ OPT("config", "<ipsec.conf>"), required_argument, NULL, OPT_CONFIG, },

	HEADING_OPT("  Display more details:"),
	{ OPT("debug", "help|<debug-flags>"), optional_argument, NULL, OPT_DEBUG, },
	{ OPT("verbose"), no_argument, NULL, OPT_VERBOSE, },

	HEADING_OPT("  Display content of 'ipsec.conf' 'conn' sections:"),
	{ OPT("listall"), no_argument, NULL, OPT_LISTALL, },
	{ OPT("listadd"), no_argument, NULL, OPT_LISTADD, },
	{ OPT("listroute"), no_argument, NULL, OPT_LISTROUTE, },
	{ OPT("liststart"), no_argument, NULL, OPT_LISTSTART, },
	{ OPT("listignore"), no_argument, NULL, OPT_LISTIGNORE, },

	HEADING_OPT("  Display content of 'ipsec.conf' 'config setup' section:"),
	{ OPT("liststack"), no_argument, NULL, OPT_LISTSTACK, },
	{ OPT("configsetup", "<option>"), optional_argument, NULL, OPT_CONFIGSETUP, },
	{ OPT("noexport"), no_argument, NULL, OPT_NOEXPORT, },
	{ OPT("varprefix", "<prefix>"), required_argument, NULL, OPT_VARPREFIX, },

	HEADING_OPT("  Override default pluto socket:"),
	{ OPT("ctlsocket", "<socketfile>"), required_argument, NULL, OPT_CTLSOCKET, },
	{ REPLACE_OPT("ctlbase", "ctlsocket", "3.22"), required_argument, NULL, OPT_CTLSOCKET, }, /* backwards compatibility */

	HEADING_OPT("  Specify connection on command line:"),
	{ OPT("name", "<connection-name>"), required_argument, NULL, OPT_NAME, },
	HEADING_OPT("\tleft=<ip>\n\tright=<ip>\n\t..."),

	/* obsoleted, eat and ignore for compatibility */
	{ IGNORE_OPT("defaultroute", "3.8"), required_argument, NULL, 0, },
	{ IGNORE_OPT("defaultroutenexthop", "3.8"), required_argument, NULL, 0, },
	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
	struct logger *logger = tool_logger(argc, argv);

	bool autoall = false;

	struct configsetup_options configsetup = {
		.name = NULL,
		.export = "export",
		.varprefix = "",
	};

	bool checkconfig = false;
	bool
		dolist = false,
		listadd = false,
		listroute = false,
		liststart = false,
		listignore = false,
		listall = false;
	bool opt_liststack = false;
	const char *configfile = NULL;
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
			optarg_usage("ipsec addconn", "<connection-name> ...",
				     "By default, 'addconn' will load <connection-name> into pluto.\n");

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
			configsetup.name = (optarg == NULL ? "" : optarg);
			continue;

		case OPT_CHECKCONFIG:
			checkconfig = true;
			continue;

		case OPT_NOEXPORT:
			configsetup.export = "";
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
			opt_liststack = true;
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
			configsetup.varprefix = optarg;
			continue;

		case OPT_NAME:
			name = optarg;
			continue;
		}

		bad_case(c);
	}

	/* if nothing to add, then complain */
	if (optind == argc && !autoall && !dolist &&
	    configsetup.name == NULL &&
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
		if (configsetup.name != NULL) {
			llog(ERROR_STREAM, logger, "--conn %s conflicts with --configsetup=%s",
			     name, configsetup.name);
			exit(1);
		}
		if (autoall) {
			llog(ERROR_STREAM, logger, "--conn %s conflicts with --autoall", name);
			exit(1);
		}
		cfg = confread_load_argv(configfile, name, argv, optind, logger, verbose);
		if (cfg == NULL) {
			llog(RC_LOG, logger, "parsing config arguments failed");
			exit(3);
		}
	} else {
		cfg = confread_load(configfile, (configsetup.name != NULL), logger, verbose);
		if (cfg == NULL) {
			llog(RC_LOG, logger, "loading config file '%s' failed", configfile);
			exit(3);
		}
	}

	PASSERT(logger, cfg != NULL);

	if (checkconfig) {
		/* call is NO-OP when checkconfig */
		confread_free(cfg);
		free_config_setup();
		exit(0);
	}

	const struct config_setup *oco = config_setup_singleton();

#ifdef USE_SECCOMP
	enum seccomp_mode seccomp = config_setup_option(oco, KBF_SECCOMP);
	switch (seccomp) {
	case SECCOMP_ENABLED:
		init_seccomp_addconn(SCMP_ACT_KILL, logger);
		break;
	case SECCOMP_TOLERANT:
		init_seccomp_addconn(SCMP_ACT_ERRNO(EACCES), logger);
		break;
	case SECCOMP_DISABLED:
		break;
	default:
		bad_case(seccomp);
	}
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

			if (verbose > 0) {
				printf("    %s\n", conn->name);
			}

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

		struct starter_conn *conn = TAILQ_LAST(&cfg->conns, conns_head);
		if (conn == NULL) {
			llog(ERROR_STREAM, logger, "no conn %s to load", name);
			exit(1);
		}

		exit_status = starter_whack_add_conn(ctlsocket, conn, logger);

	} else {

		/* load named conns, regardless of their state */
		for (int connum = optind; connum < argc; connum++) {
			const char *connname = argv[connum];

			if (verbose > 0) {
				fprintf(stdout, "loading conns matching %s:", connname);
				fprintf(stdout, "\n");

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
			fprintf(stderr, "conn %s: not found (tried aliases)\n", connname);
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

	if (opt_liststack) {
		const char *protostack = config_setup_string(oco, KSF_PROTOSTACK);
		if (pexpect(protostack != NULL)) {
			printf("%s\n", protostack);
		}
		confread_free(cfg);
		free_config_setup();
		exit(0);
	}

	if (configsetup.name != NULL) {

		if (strlen(configsetup.name) == 0) {
			print_option(configsetup, "confreadstatus", "%s", "");
			print_option(configsetup, "configfile", "%s", configfile);
			print_option(configsetup, "ctlsocket", "%s", ctlsocket);
		}

		for (enum config_setup_keyword kw = CONFIG_SETUP_KEYWORD_FLOOR;
		     kw < CONFIG_SETUP_KEYWORD_ROOF; kw++) {

			PASSERT(logger, kw < config_setup_keywords.len);
			const struct keyword_def *kd = &config_setup_keywords.item[kw];

			if (kd->keyname == NULL) {
				continue;
			}

			/* don't print backwards compatible aliases */
			if ((kd->validity & kv_alias) != 0) {
				continue;
			}

			/* only print --configsetup=NAME? */
			if (strlen(configsetup.name) > 0 &&
			    !strheq(configsetup.name, kd->keyname)) {
				continue;
			}

			switch (kd->type) {
			case kt_string:
			{
				const char *string = config_setup_string(oco, kd->field);
				if (string != NULL) {
					print_option(configsetup, kd->keyname, "%s", string);
				}
				break;
			}

			case kt_sparse_name:
			{
				uintmax_t option = config_setup_option(oco, kd->field);
				if (option != 0) {
					name_buf nb;
					print_option(configsetup, kd->keyname, "%s",
						     str_sparse_short(kd->sparse_names, option, &nb));
				}
				break;
			}

			case kt_seconds:
			{
				deltatime_t deltatime = config_setup_deltatime(oco, kd->field);
				if (deltatime.is_set) {
					print_option(configsetup, kd->keyname, "%jd", deltasecs(deltatime));
				}
				break;
			}

			case kt_obsolete:
				break;

			default:
			{
				uintmax_t option = config_setup_option(oco, kd->field);
				if (option != 0 ||
				    oco->values[kd->field].set) {
					print_option(configsetup, kd->keyname, "%jd", option);
				}
				break;
			}
			}

		}
		confread_free(cfg);
		free_config_setup();
		exit(0);
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
