/*
 * A program to read the configuration file and load a single conn
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012-2014 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2014 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2012-2013 Kim B. Heino <b@bbbs.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/stat.h>
#include <limits.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#include <netinet/in.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>

#include <unistd.h>
#include <getopt.h>
#include <ctype.h>
#include <stdio.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <libreswan.h>
#include "sysdep.h"
#include "constants.h"
#include "lswalloc.h"
#include "lswconf.h"
#include "lswlog.h"
#include "whack.h"
#include "ipsecconf/confread.h"
#include "ipsecconf/confwrite.h"
#include "ipsecconf/starterlog.h"
#include "ipsecconf/starterwhack.h"
#include "ipsecconf/keywords.h"
#include "ipsecconf/parser-controls.h"
#include "ipsecconf/addr_lookup.h"

#ifdef USE_DNSSEC
# include "dnssec.h"
#endif

#ifdef HAVE_SECCOMP
# include <seccomp.h>
# define EXIT_SECCOMP_FAIL 8
#endif

const char *progname;
static int verbose = 0;


/*
 * See if conn's left or right is %defaultroute and resolve it.
 */
static
void resolve_defaultroute(struct starter_conn *conn)
{
	if (resolve_defaultroute_one(&conn->left, &conn->right, verbose != 0) == 1)
		resolve_defaultroute_one(&conn->left, &conn->right, verbose != 0);
	if (resolve_defaultroute_one(&conn->right, &conn->left, verbose != 0) == 1)
		resolve_defaultroute_one(&conn->right, &conn->left, verbose != 0);
}

#ifdef HAVE_SECCOMP
static
void init_seccomp_addconn(uint32_t def_action)
{
#define S_RULE_ADD(x) seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(x), 0)
	scmp_filter_ctx ctx = seccomp_init(def_action);
	int rc = 0;

	if (ctx == NULL) {
			printf("seccomp_init_addconn() failed!");
			exit(EXIT_SECCOMP_FAIL);
	}

	/*
	 * because on bootup, addconn is started by pluto, any syscall
	 * here MUST also appear in the syscall list for "main" inside pluto
	 */
	rc |= S_RULE_ADD(access);
	rc |= S_RULE_ADD(arch_prctl);
	rc |= S_RULE_ADD(brk);
	rc |= S_RULE_ADD(bind);
	rc |= S_RULE_ADD(clone);
	rc |= S_RULE_ADD(close);
	rc |= S_RULE_ADD(connect);
	rc |= S_RULE_ADD(epoll_create);
	rc |= S_RULE_ADD(epoll_ctl);
	rc |= S_RULE_ADD(epoll_wait);
	rc |= S_RULE_ADD(epoll_pwait);
	rc |= S_RULE_ADD(exit_group);
	rc |= S_RULE_ADD(fcntl);
	rc |= S_RULE_ADD(fstat);
	rc |= S_RULE_ADD(futex);
	rc |= S_RULE_ADD(getdents);
	rc |= S_RULE_ADD(getegid);
	rc |= S_RULE_ADD(getpid);
	rc |= S_RULE_ADD(getrlimit);
	rc |= S_RULE_ADD(geteuid);
	rc |= S_RULE_ADD(getgid);
	rc |= S_RULE_ADD(getrandom);
	rc |= S_RULE_ADD(getuid);
	rc |= S_RULE_ADD(ioctl);
	rc |= S_RULE_ADD(mmap);
	rc |= S_RULE_ADD(lseek);
	rc |= S_RULE_ADD(munmap);
	rc |= S_RULE_ADD(mprotect);
	rc |= S_RULE_ADD(open);
	rc |= S_RULE_ADD(openat);
	rc |= S_RULE_ADD(poll);
	rc |= S_RULE_ADD(prctl);
	rc |= S_RULE_ADD(read);
	rc |= S_RULE_ADD(readlink);
	rc |= S_RULE_ADD(recvfrom);
	rc |= S_RULE_ADD(rt_sigaction);
	rc |= S_RULE_ADD(rt_sigprocmask);
	rc |= S_RULE_ADD(sendto);
	rc |= S_RULE_ADD(setsockopt);
	rc |= S_RULE_ADD(set_robust_list);
	rc |= S_RULE_ADD(set_tid_address);
	rc |= S_RULE_ADD(socket);
	rc |= S_RULE_ADD(socketpair);
	rc |= S_RULE_ADD(statfs);
	rc |= S_RULE_ADD(uname);
	rc |= S_RULE_ADD(write);

	if (rc != 0) {
		printf("seccomp_rule_add() failed!");
		seccomp_release(ctx);
		exit(EXIT_SECCOMP_FAIL);
	}

	rc = seccomp_load(ctx);
	if (rc < 0) {
		printf("seccomp_load() failed!");
		seccomp_release(ctx);
		exit(EXIT_SECCOMP_FAIL);
	}
#undef S_RULE_ADD
}
#endif

static const char *usage_string = ""
	"Usage: addconn [--config file] [--rootdir dir] [--ctlsocket socketfile]\n"
	"               [--varprefix prefix] [--noexport]\n"
	"               [--verbose]\n"
	"               [--configsetup]\n"
	"               [--liststack]\n"
	"               [--checkconfig]\n"
	"               [--addall] [--autoall]\n"
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
	{ "addall", no_argument, NULL, 'a' },
	{ "autoall", no_argument, NULL, 'a' },
	{ "listall", no_argument, NULL, 'A' },
	{ "listadd", no_argument, NULL, 'L' },
	{ "listroute", no_argument, NULL, 'r' },
	{ "liststart", no_argument, NULL, 's' },
	{ "listignore", no_argument, NULL, 'i' },
	{ "varprefix", required_argument, NULL, 'P' },
	{ "ctlsocket", required_argument, NULL, 'c' },
	{ "ctlbase", required_argument, NULL, 'c' }, /* backwards compatibility */
	{ "rootdir", required_argument, NULL, 'R' },
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
	int opt;
	bool autoall = FALSE;
	int configsetup = 0;
	int checkconfig = 0;
	const char *export = "export"; /* display export before the foo=bar or not */
	bool
		dolist = FALSE,
		listadd = FALSE,
		listroute = FALSE,
		liststart = FALSE,
		listignore = FALSE,
		listall = FALSE,
		liststack = FALSE;
	char *configfile = NULL;
	const char *varprefix = "";
	int exit_status = 0;
	struct starter_conn *conn = NULL;
	const char *ctlsocket = NULL;
	bool resolvip = TRUE; /* default to looking up names */

#if 0
	/* efence settings */
	extern int EF_PROTECT_BELOW;
	extern int EF_PROTECT_FREE;

	EF_PROTECT_BELOW = 1;
	EF_PROTECT_FREE = 1;
#endif

	rootdir[0] = '\0';

	tool_init_log(argv[0]);

	while ((opt = getopt_long(argc, argv, "", longopts, 0)) != EOF) {
		switch (opt) {
		case 'h':
			/* usage: */
			usage();
			break;

		case 'a':
			autoall = TRUE;
			break;

		case 'D':
			verbose++;
			lex_verbosity++;
			break;

		case 'T':
			configsetup++;	/* ??? is this not idempotent? */
			break;

		case 'K':
			checkconfig++;	/* ??? is this not idempotent? */
			break;

		case 'N':
			export = "";
			break;

		case 'C':
			configfile = clone_str(optarg, "config file name");
			break;

		case 'c':
			ctlsocket = clone_str(optarg, "control socket");
			break;

		case 'L':
			listadd = TRUE;
			dolist = TRUE;
			break;

		case 'r':
			listroute = TRUE;
			dolist = TRUE;
			break;

		case 's':
			liststart = TRUE;
			dolist = TRUE;
			break;

		case 'S':
			liststack = TRUE;
			dolist = TRUE;
			break;

		case 'i':
			listignore = TRUE;
			dolist = TRUE;
			break;

		case 'A':
			listall = TRUE;
			dolist = TRUE;
			break;

		case 'P':
			varprefix = optarg;
			break;

		case 'R':
			printf("setting rootdir=%s\n", optarg);
			jam_str(rootdir, sizeof(rootdir), optarg);
			break;

		case 'd':
		case 'n':
			printf("Warning: options --defaultroute and --defaultroutenexthop are obsolete and were ignored\n");
			break;

		default:
			usage();
		}
	}

	/* if nothing to add, then complain */
	if (optind == argc && !autoall && !dolist && !configsetup &&
		!checkconfig)
		usage();

	if (verbose > 3) {
		yydebug = 1;
	}

	char *confdir = IPSEC_CONFDIR;

	if (configfile == NULL) {
		/* ??? see code clone in programs/readwriteconf/readwriteconf.c */
		configfile = alloc_bytes(strlen(confdir) +
					 sizeof("/ipsec.conf"),
					 "conf file");

		/* calculate default value for configfile */
		strcpy(configfile, confdir);	/* safe: see allocation above */
		if (configfile[0] != '\0' && configfile[strlen(configfile) - 1] != '/')
			strcat(configfile, "/");	/* safe: see allocation above */
		strcat(configfile, "ipsec.conf");	/* safe: see allocation above */
	}

	if (verbose)
		printf("opening file: %s\n", configfile);

	starter_use_log(verbose != 0, TRUE, verbose == 0);

	if (configsetup || checkconfig || dolist) {
		/* skip if we have no use for them... causes delays */
		resolvip = FALSE;
	}

	struct starter_config *cfg = NULL;

	{
		err_t err = NULL;

		cfg = confread_load(configfile, &err, resolvip, ctlsocket, configsetup);

		if (cfg == NULL) {
			fprintf(stderr, "cannot load config '%s': %s\n",
				configfile, err);
			exit(3);
		} else if (checkconfig) {
			confread_free(cfg);
			exit(0);
		}
	}

#ifdef HAVE_SECCOMP
	switch (cfg->setup.options[KBF_SECCOMP]) {
		case SECCOMP_ENABLED:
		init_seccomp_addconn(SCMP_ACT_KILL);
		break;
	case SECCOMP_TOLERANT:
		init_seccomp_addconn(SCMP_ACT_ERRNO(EACCES));
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
		cfg->setup.strings[KSF_PLUTO_DNSSEC_ANCHORS]);
#endif

	if (autoall) {
		if (verbose)
			printf("loading all conns according to their auto= settings\n");

		/*
		 * Load all conns marked as auto=add or better.
		 * First, do the auto=route and auto=add conns to quickly
		 * get routes in place, then do auto=start as these can be
		 * slower.
		 * This mimics behaviour of the old _plutoload
		 */
		if (verbose)
			printf("  Pass #1: Loading auto=add, auto=route and auto=start connections\n");

		for (conn = cfg->conns.tqh_first;
			conn != NULL;
			conn = conn->link.tqe_next) {
			if (conn->desired_state == STARTUP_ADD ||
				conn->desired_state == STARTUP_ONDEMAND ||
				conn->desired_state == STARTUP_START) {
				if (verbose)
					printf(" %s", conn->name);
				resolve_defaultroute(conn);
				starter_whack_add_conn(cfg, conn);
			}
		}

		/*
		 * We loaded all connections. Now tell pluto to listen,
		 * then route the conns and resolve default route.
		 */
		starter_whack_listen(cfg);

		if (verbose)
			printf("  Pass #2: Routing auto=route and auto=start connections\n");

		for (conn = cfg->conns.tqh_first;
			conn != NULL;
			conn = conn->link.tqe_next) {
			if (conn->desired_state == STARTUP_ADD ||
				conn->desired_state == STARTUP_ONDEMAND ||
				conn->desired_state == STARTUP_START) {
				if (verbose)
					printf(" %s", conn->name);
				resolve_defaultroute(conn);
				if (conn->desired_state == STARTUP_ONDEMAND ||
				    conn->desired_state == STARTUP_START) {
					starter_whack_route_conn(cfg, conn);
				}
			}
		}

		if (verbose)
			printf("  Pass #3: Initiating auto=start connections\n");

		for (conn = cfg->conns.tqh_first;
			conn != NULL;
			conn = conn->link.tqe_next) {
			if (conn->desired_state == STARTUP_START) {
				if (verbose)
					printf(" %s", conn->name);
				starter_whack_initiate_conn(cfg, conn);
			}
		}

		if (verbose)
			printf("\n");
	} else {
		/* load named conns, regardless of their state */
		int connum;

		if (verbose)
			printf("loading named conns:");
		for (connum = optind; connum < argc; connum++) {
			char *connname = argv[connum];

			if (verbose)
				printf(" %s", connname);
			for (conn = cfg->conns.tqh_first;
				conn != NULL;
				conn = conn->link.tqe_next) {
				if (streq(conn->name, connname)) {
					if (conn->state == STATE_ADDED) {
						printf("\nconn %s already added\n",
							conn->name);
					} else if (conn->state ==
						STATE_FAILED) {
						printf("\nconn %s did not load properly\n",
							conn->name);
					} else {
						resolve_defaultroute(conn);
						exit_status =
							starter_whack_add_conn(
								cfg,
								conn);
						conn->state = STATE_ADDED;
					}
					break;
				}
			}

			if (conn == NULL) {
				/*
				 * only if we don't find it, do we now look
				 * for aliases
				 */
				for (conn = cfg->conns.tqh_first;
					conn != NULL;
					conn = conn->link.tqe_next) {
					if (conn->strings_set[KSCF_CONNALIAS] &&
						lsw_alias_cmp(connname,
							conn->
							strings[KSCF_CONNALIAS]
							)) {
						if (conn->state ==
							STATE_ADDED) {
							printf("\nalias: %s conn %s already added\n",
								connname,
								conn->name);
						} else if (conn->state ==
							STATE_FAILED) {
							printf("\nalias: %s conn %s did not load properly\n",
								connname,
								conn->name);
						} else {
							resolve_defaultroute(
								conn);
							exit_status =
								starter_whack_add_conn(
									cfg,
									conn);
							conn->state =
								STATE_ADDED;
						}
						break;
					}
				}
			}

			if (conn == NULL) {
				exit_status++;
				if (!verbose) {
					printf("conn '%s': not found (tried aliases)\n",
						connname);
				} else {
					printf(" (notfound)\n");
				}
			}
		}
	}

	if (listall) {
		if (verbose)
			printf("listing all conns\n");
		for (conn = cfg->conns.tqh_first;
			conn != NULL;
			conn = conn->link.tqe_next)
			printf("%s ", conn->name);
		printf("\n");
	} else {
		if (listadd) {
			if (verbose)
				printf("listing all conns marked as auto=add\n");

			/* list all conns marked as auto=add */
			for (conn = cfg->conns.tqh_first;
				conn != NULL;
				conn = conn->link.tqe_next) {
				if (conn->desired_state == STARTUP_ADD)
					printf("%s ", conn->name);
			}
		}
		if (listroute) {
			if (verbose)
				printf("listing all conns marked as auto=route and auto=start\n");

			/*
			 * list all conns marked as auto=route or start or
			 * better
			 */
			for (conn = cfg->conns.tqh_first;
				conn != NULL;
				conn = conn->link.tqe_next) {
				if (conn->desired_state == STARTUP_START ||
					conn->desired_state == STARTUP_ONDEMAND)
					printf("%s ", conn->name);
			}
		}

		if (liststart && !listroute) {
			if (verbose)
				printf("listing all conns marked as auto=start\n");

			/* list all conns marked as auto=start */
			for (conn = cfg->conns.tqh_first;
				conn != NULL;
				conn = conn->link.tqe_next) {
				if (conn->desired_state == STARTUP_START)
					printf("%s ", conn->name);
			}
		}

		if (listignore) {
			if (verbose)
				printf("listing all conns marked as auto=ignore\n");

			/* list all conns marked as auto=start */
			for (conn = cfg->conns.tqh_first;
				conn != NULL;
				conn = conn->link.tqe_next) {
				if (conn->desired_state == STARTUP_IGNORE)
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
					printf("netkey\n");
				}
			}
		}
		confread_free(cfg);
		exit(0);
	}

	if (configsetup) {
		const struct keyword_def *kd;

		printf("%s %sconfreadstatus=''\n", export, varprefix);
		for (kd = ipsec_conf_keywords; kd->keyname != NULL; kd++) {
			if ((kd->validity & kv_config) == 0)
				continue;

			switch (kd->type) {
			case kt_string:
			case kt_filename:
			case kt_dirname:
			case kt_loose_enum:
				if (cfg->setup.strings[kd->field]) {
					printf("%s %s%s='%s'\n",
						export, varprefix, kd->keyname,
						cfg->setup.strings[kd->field]);
				}
				break;

			case kt_bool:
				printf("%s %s%s='%s'\n", export, varprefix,
					kd->keyname,
					bool_str(cfg->setup.options[kd->field]));
				break;

			case kt_list:
				printf("%s %s%s='",
					export, varprefix, kd->keyname);
				confwrite_list(stdout, "",
					cfg->setup.options[kd->field],
					kd);
				printf("'\n");
				break;

			case kt_obsolete:
				printf("# obsolete option '%s%s' ignored\n",
					varprefix, kd->keyname);
				break;

			default:
				if (cfg->setup.options[kd->field] ||
					cfg->setup.options_set[kd->field]) {
					printf("%s %s%s='%d'\n",
						export, varprefix, kd->keyname,
						cfg->setup.options[kd->field]);
				}
				break;
			}
		}
		confread_free(cfg);
		exit(0);
	}

	confread_free(cfg);
#ifdef USE_DNSSEC
	unbound_ctx_free();
#endif
	exit(exit_status);
}
