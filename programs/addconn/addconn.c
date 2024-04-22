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
#include <getopt.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "lswlog.h"
#include "lswcdefs.h"	/* for UNUSED */
#include "lswalloc.h"
#include "lswtool.h"
#include "whack.h"
#include "ipsecconf/parser-controls.h"
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

static int verbose = 0;

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
	resolve_default_route(&conn->left, &conn->right, verbose_rc_flags, logger);
	resolve_default_route(&conn->right, &conn->left, verbose_rc_flags, logger);
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

static const char *usage_string = ""
	"Usage: addconn [--config file] [--ctlsocket socketfile]\n"
	"               [--varprefix prefix] [--noexport]\n"
	"               [--verbose]\n"
	"               [--configsetup]\n"
	"               [--liststack]\n"
	"               [--checkconfig]\n"
	"               [--autoall]\n"
	"               [--listall] [--listadd] [--listroute] [--liststart]\n"
	"               [--listignore]\n"
	"               names\n";

static void usage(void)
{
	/* print usage */
	fputs(usage_string, stderr);
	exit(10);
}

static const struct option longopts[] =
{
	{ "config", required_argument, NULL, 'C' },
	{ "debug", no_argument, NULL, 'D' },
	{ "verbose", no_argument, NULL, 'D' },
	{ "addall", no_argument, NULL, 'a' }, /* alias, backwards compat */
	{ "autoall", no_argument, NULL, 'a' },
	{ "listall", no_argument, NULL, 'A' },
	{ "listadd", no_argument, NULL, 'L' },
	{ "listroute", no_argument, NULL, 'r' },
	{ "liststart", no_argument, NULL, 's' },
	{ "listignore", no_argument, NULL, 'i' },
	{ "varprefix", required_argument, NULL, 'P' },
	{ "ctlsocket", required_argument, NULL, 'c' },
	{ "ctlbase", required_argument, NULL, 'c' }, /* backwards compatibility */
	{ "configsetup", no_argument, NULL, 'T' },
	{ "liststack", no_argument, NULL, 'S' },
	{ "checkconfig", no_argument, NULL, 'K' },
	{ "noexport", no_argument, NULL, 'N' },
	{ "help", no_argument, NULL, 'h' },
	/* obsoleted, eat and ignore for compatibility */
	{"defaultroute", required_argument, NULL, 'd'},
	{"defaultroutenexthop", required_argument, NULL, 'n'},

	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
	struct logger *logger = tool_logger(argc, argv);

	int opt;
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
	char *configfile = NULL;
	const char *varprefix = "";
	int exit_status = 0;
	struct starter_conn *conn = NULL;
	char *ctlsocket = clone_str(DEFAULT_CTL_SOCKET, "default control socket");

#if 0
	/* efence settings */
	extern int EF_PROTECT_BELOW;
	extern int EF_PROTECT_FREE;

	EF_PROTECT_BELOW = 1;
	EF_PROTECT_FREE = 1;
#endif
	while ((opt = getopt_long(argc, argv, "", longopts, 0)) != EOF) {
		switch (opt) {
		case 'h':
			/* usage: */
			usage();
			break;

		case 'a':
			autoall = true;
			break;

		case 'D':
			verbose++;
			lex_verbosity++;
			break;

		case 'T':
			configsetup = true;
			break;

		case 'K':
			checkconfig = true;
			break;

		case 'N':
			export = "";
			break;

		case 'C':
			configfile = clone_str(optarg, "config file name");
			break;

		case 'c':
			pfree(ctlsocket);
			ctlsocket = clone_str(optarg, "control socket");
			break;

		case 'L':
			listadd = true;
			dolist = true;
			break;

		case 'r':
			listroute = true;
			dolist = true;
			break;

		case 's':
			liststart = true;
			dolist = true;
			break;

		case 'S':
			liststack = true;
			dolist = true;
			break;

		case 'i':
			listignore = true;
			dolist = true;
			break;

		case 'A':
			listall = true;
			dolist = true;
			break;

		case 'P':
			varprefix = optarg;
			break;

		case 'd':
		case 'n':
			fprintf(stderr, "Warning: options --defaultroute and --defaultroutenexthop are obsolete and were ignored\n");
			break;

		default:
			usage();
		}
	}

	if (autoall) {
		/* pluto forks us, we might have to wait on it to create the socket */
		struct stat sb;
		int ws = 5; /* somewhat arbitrary */

		while (ws > 0) {
			int ret = stat(ctlsocket, &sb);

			if (ret == -1) {
				sleep(1);
			} else {
				break;
			}
			ws--;
		}
		if (ws == 0) {
			fprintf(stderr, "ipsec addconn: timeout waiting on pluto socket %s - aborted\n",
				ctlsocket);
			exit(3);
		}
	}

	/* if nothing to add, then complain */
	if (optind == argc && !autoall && !dolist && !configsetup &&
	    !checkconfig)
		usage();

	switch (verbose) {
	case 0:
	case 1:
		break;
	case 2:
		cur_debugging = DBG_ALL;
		break;
	case 3:
		cur_debugging = DBG_ALL|DBG_TMI;
		break;
	default: /*>=4*/
		cur_debugging = DBG_ALL|DBG_TMI;
		yydebug = true;
		break;
	}

	/* logged when true! */
	ldbg(logger, "debugging mode enabled");

	if (configfile == NULL) {
		configfile = clone_str(IPSEC_CONF, "default ipsec.conf file");
	}
	if (verbose > 0) {
		printf("opening file: %s\n", configfile);
	}

	struct starter_config *cfg = confread_load(configfile, configsetup, logger);
	if (cfg == NULL) {
		llog(RC_LOG, logger, "cannot load config file '%s'", configfile);
		exit(3);
	}

	if (checkconfig) {
		confread_free(cfg);
		exit(0);
	}

#ifdef USE_SECCOMP
	switch (cfg->setup.options[KBF_SECCOMP]) {
		case SECCOMP_ENABLED:
			init_seccomp_addconn(SCMP_ACT_KILL, logger);
		break;
	case SECCOMP_TOLERANT:
		init_seccomp_addconn(SCMP_ACT_ERRNO(EACCES), logger);
		break;
	case SECCOMP_DISABLED:
		break;
	default:
		bad_case(cfg->setup.options[KBF_SECCOMP]);
	}
#endif

#ifdef USE_DNSSEC
	unbound_sync_init(cfg->setup.options[KBF_DO_DNSSEC],
			  cfg->setup.strings[KSF_PLUTO_DNSSEC_ROOTKEY_FILE],
			  cfg->setup.strings[KSF_PLUTO_DNSSEC_ANCHORS],
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
			printf("  Pass #1: Loading auto=add, auto=keep, auto=route and auto=start connections\n");

		for (conn = cfg->conns.tqh_first; conn != NULL; conn = conn->link.tqe_next) {
			enum autostart autostart = conn->options[KNCF_AUTO];
			switch (autostart) {
			case AUTOSTART_UNSET:
			case AUTOSTART_IGNORE:
				break;
			case AUTOSTART_ADD:
			case AUTOSTART_ROUTE:
			case AUTOSTART_ONDEMAND:
			case AUTOSTART_KEEP:
			case AUTOSTART_UP:
			case AUTOSTART_START:
				if (verbose > 0)
					printf(" %s\n", conn->name);
				resolve_default_routes(conn, logger);
				starter_whack_add_conn(ctlsocket,
						       conn, logger);
				break;
			}
		}

		/*
		 * We loaded all connections. Now tell pluto to
		 * listen, then route the conns and resolve default
		 * route.
		 *
		 * Any connections that orient and have +ROUTE will be
		 * routed.
		 */
		starter_whack_listen(ctlsocket, logger);

		if (verbose > 0)
			/* handled by pluto */
			printf("  Pass #2: Routing auto=route connections\n");

		if (verbose > 0)
			printf("  Pass #3: Initiating auto=up connections\n");

		for (conn = cfg->conns.tqh_first; conn != NULL; conn = conn->link.tqe_next) {
			enum autostart autostart = conn->options[KNCF_AUTO];
			if (autostart == AUTOSTART_UP ||
			    autostart == AUTOSTART_START) {
				if (verbose > 0)
					printf(" %s", conn->name);
				starter_whack_initiate_conn(ctlsocket, conn, logger);
			}
		}

		if (verbose > 0)
			printf("\n");
	} else {
		/* load named conns, regardless of their state */
		int connum;

		if (verbose > 0)
			printf("loading named conns:");
		for (connum = optind; connum < argc; connum++) {
			const char *connname = argv[connum];

			const char *p1 = "";	/* message prefix components */
			const char *p2 = "";
			const char *p3 = "";

			if (verbose > 0)
				printf(" %s\n", connname);

			/* find first name match, if any */
			for (conn = cfg->conns.tqh_first;
			     conn != NULL && !streq(conn->name, connname);
			     conn = conn->link.tqe_next) {
			}

			if (conn == NULL) {
				/* We didn't find name; look for first alias */

				p1 = "alias: ";
				p2 = connname;
				p3 = " ";

				for (conn = cfg->conns.tqh_first;
				     conn != NULL;
				     conn = conn->link.tqe_next) {
					if (lsw_alias_cmp(connname,
						conn->strings[KSCF_CONNALIAS]))
					{
						break;
					}
				}
			}

			if (conn == NULL) {
				/* we found neither name nor alias */
				exit_status += RC_UNKNOWN_NAME; /* cause non-zero exit code */
				if (verbose > 0) {
					printf(" (notfound)\n");
				}
				fprintf(stderr, "conn '%s': not found (tried aliases)\n",
					connname);
			} else {
				/* found name or alias */
				if (conn->state == STATE_ADDED) {
					fprintf(stderr, "\n%s%s%sconn %s already added\n",
						p1, p2, p3,
						conn->name);
				} else if (conn->state == STATE_FAILED) {
					fprintf(stderr, "\n%s%s%sconn %s did not load properly\n",
						p1, p2, p3,
						conn->name);
				} else {
					resolve_default_routes(conn, logger);
					exit_status = starter_whack_add_conn(ctlsocket,
									     conn, logger);
					conn->state = STATE_ADDED;
				}
			}
		}
	}

	if (listall) {
		if (verbose > 0)
			printf("listing all conns\n");
		for (conn = cfg->conns.tqh_first;
			conn != NULL;
			conn = conn->link.tqe_next)
			printf("%s ", conn->name);
		printf("\n");
	} else {
		if (listadd) {
			if (verbose > 0)
				printf("listing all conns marked as auto=add\n");

			/* list all conns marked as auto=add */
			for (conn = cfg->conns.tqh_first;
				conn != NULL;
				conn = conn->link.tqe_next) {
				enum autostart autostart = conn->options[KNCF_AUTO];
				if (autostart == AUTOSTART_ADD)
					printf("%s ", conn->name);
			}
		}
		if (listroute) {
			if (verbose > 0)
				printf("listing all conns marked as auto=route and auto=up\n");

			/*
			 * list all conns marked as auto=route or start or
			 * better
			 */
			for (conn = cfg->conns.tqh_first;
				conn != NULL;
				conn = conn->link.tqe_next) {
				enum autostart autostart = conn->options[KNCF_AUTO];
				if (autostart == AUTOSTART_UP ||
				    autostart == AUTOSTART_START ||
				    autostart == AUTOSTART_ROUTE ||
				    autostart == AUTOSTART_ONDEMAND)
					printf("%s ", conn->name);
			}
		}

		if (liststart && !listroute) {
			if (verbose > 0)
				printf("listing all conns marked as auto=up\n");

			/* list all conns marked as auto=up */
			for (conn = cfg->conns.tqh_first;
				conn != NULL;
				conn = conn->link.tqe_next) {
				enum autostart autostart = conn->options[KNCF_AUTO];
				if (autostart == AUTOSTART_UP ||
				    autostart == AUTOSTART_START)
					printf("%s ", conn->name);
			}
		}

		if (listignore) {
			if (verbose > 0)
				printf("listing all conns marked as auto=ignore\n");

			/* list all conns marked as auto=up */
			for (conn = cfg->conns.tqh_first;
				conn != NULL;
				conn = conn->link.tqe_next) {
				enum autostart autostart = conn->options[KNCF_AUTO];
				if (autostart == AUTOSTART_IGNORE ||
				    autostart == AUTOSTART_UNSET)
					printf("%s ", conn->name);
			}
			printf("\n");
		}
	}

	if (liststack) {
		const struct keyword_def *kd;

		for (kd = ipsec_conf_keywords; kd->keyname != NULL; kd++) {
			if (strstr(kd->keyname, "protostack")) {
				if (cfg->setup.strings[kd->field]) {
					printf("%s\n",
						cfg->setup.strings[kd->field]);
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
				if (cfg->setup.strings[kd->field]) {
					printf("%s %s%s='%s'\n",
						export, varprefix, safe_kwname,
						cfg->setup.strings[kd->field]);
				}
				break;

			case kt_bool:
				printf("%s %s%s='%s'\n", export, varprefix,
					safe_kwname,
					bool_str(cfg->setup.options[kd->field]));
				break;

			case kt_obsolete:
				break;

			default:
				if (cfg->setup.options[kd->field] ||
					cfg->setup.options_set[kd->field]) {
					printf("%s %s%s='%jd'\n",
						export, varprefix, safe_kwname,
						cfg->setup.options[kd->field]);
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
	pfreeany(ctlsocket);
	pfreeany(configfile);
	/*
	 * Only RC_ codes between RC_EXIT_FLOOR (RC_DUPNAME) and
	 * RC_EXIT_ROOF (RC_NEW_V1_STATE) are errors Some starter code
	 * above can also return -1 which is not a valid RC_ code
	 */
	if (exit_status > 0 && (exit_status < RC_EXIT_FLOOR || exit_status >= RC_EXIT_ROOF))
		exit_status = 0;
	exit(exit_status);
}
