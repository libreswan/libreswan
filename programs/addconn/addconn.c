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
#include "ipsecconf/starterlog.h"
#include "ipsecconf/confread.h"
#include "ipsecconf/confwrite.h"
#include "ipsecconf/starterwhack.h"
#ifdef NETKEY_SUPPORT
#include "addr_lookup.h"
#endif

#ifdef USE_DNSSEC
# include "dnssec.h"
#endif

#ifdef HAVE_SECCOMP
#define LSW_SECCOMP_EXIT_FAIL 8
#include "lswseccomp.h"
#endif

const char *progname;
static int verbose = 0;


/*
 * See if conn's left or right is %defaultroute and resolve it.
 *
 * XXX: why not let pluto resolve all this like it is already doing?
 * because of MOBIKE.
 */
static void resolve_defaultroute(struct starter_conn *conn UNUSED)
{
#ifdef NETKEY_SUPPORT
	if (resolve_defaultroute_one(&conn->left, &conn->right, verbose != 0) == 1)
		resolve_defaultroute_one(&conn->left, &conn->right, verbose != 0);
	if (resolve_defaultroute_one(&conn->right, &conn->left, verbose != 0) == 1)
		resolve_defaultroute_one(&conn->right, &conn->left, verbose != 0);
#else /* !defined(NETKEY_SUPPORT) */
	fprintf(stderr, "addcon: without NETKEY, cannot resolve_defaultroute()\n");
	exit(7);	/* random code */
#endif
}

#ifdef HAVE_SECCOMP
static void init_seccomp_addconn(uint32_t def_action)
{
	scmp_filter_ctx ctx = seccomp_init(def_action);
	if (ctx == NULL) {
		fprintf(stderr, "seccomp_init_addconn() failed!");
		exit(LSW_SECCOMP_EXIT_FAIL);
	}

	/*
	 * Because on bootup, addconn is started by pluto, any syscall
	 * here MUST also appear in the syscall list for "main" inside
	 * pluto
	 */
	LSW_SECCOMP_ADD(ctx, access);
	LSW_SECCOMP_ADD(ctx, arch_prctl);
	LSW_SECCOMP_ADD(ctx, brk);
	LSW_SECCOMP_ADD(ctx, bind);
	LSW_SECCOMP_ADD(ctx, clone);
	LSW_SECCOMP_ADD(ctx, clock_gettime);
	LSW_SECCOMP_ADD(ctx, close);
	LSW_SECCOMP_ADD(ctx, connect);
	LSW_SECCOMP_ADD(ctx, epoll_create);
	LSW_SECCOMP_ADD(ctx, epoll_ctl);
	LSW_SECCOMP_ADD(ctx, epoll_wait);
	LSW_SECCOMP_ADD(ctx, epoll_pwait);
	LSW_SECCOMP_ADD(ctx, exit_group);
	LSW_SECCOMP_ADD(ctx, fcntl);
	LSW_SECCOMP_ADD(ctx, fstat);
	LSW_SECCOMP_ADD(ctx, futex);
	LSW_SECCOMP_ADD(ctx, getdents);
	LSW_SECCOMP_ADD(ctx, getegid);
	LSW_SECCOMP_ADD(ctx, getpid);
	LSW_SECCOMP_ADD(ctx, getrlimit);
	LSW_SECCOMP_ADD(ctx, geteuid);
	LSW_SECCOMP_ADD(ctx, getgid);
	LSW_SECCOMP_ADD(ctx, getrandom);
	LSW_SECCOMP_ADD(ctx, getuid);
	LSW_SECCOMP_ADD(ctx, ioctl);
	LSW_SECCOMP_ADD(ctx, mmap);
	LSW_SECCOMP_ADD(ctx, lseek);
	LSW_SECCOMP_ADD(ctx, munmap);
	LSW_SECCOMP_ADD(ctx, mprotect);
	LSW_SECCOMP_ADD(ctx, open);
	LSW_SECCOMP_ADD(ctx, openat);
	LSW_SECCOMP_ADD(ctx, poll);
	LSW_SECCOMP_ADD(ctx, prctl);
	LSW_SECCOMP_ADD(ctx, read);
	LSW_SECCOMP_ADD(ctx, readlink);
	LSW_SECCOMP_ADD(ctx, recvfrom);
	LSW_SECCOMP_ADD(ctx, rt_sigaction);
	LSW_SECCOMP_ADD(ctx, rt_sigprocmask);
	LSW_SECCOMP_ADD(ctx, sendto);
	LSW_SECCOMP_ADD(ctx, setsockopt);
	LSW_SECCOMP_ADD(ctx, set_robust_list);
	LSW_SECCOMP_ADD(ctx, set_tid_address);
	LSW_SECCOMP_ADD(ctx, sigreturn);
	LSW_SECCOMP_ADD(ctx, socket);
	LSW_SECCOMP_ADD(ctx, socketcall);
	LSW_SECCOMP_ADD(ctx, socketpair);
	LSW_SECCOMP_ADD(ctx, stat);
	LSW_SECCOMP_ADD(ctx, statfs);
	LSW_SECCOMP_ADD(ctx, uname);
	LSW_SECCOMP_ADD(ctx, waitpid);
	LSW_SECCOMP_ADD(ctx, write);

#ifdef USE_EFENCE
	LSW_SECCOMP_ADD(ctx, madvise);
#endif

	int rc = seccomp_load(ctx);
	if (rc < 0) {
		fprintf(stderr, "seccomp_load() failed!");
		seccomp_release(ctx);
		exit(LSW_SECCOMP_EXIT_FAIL);
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
	int opt;
	bool autoall = FALSE;
	bool configsetup = FALSE;
	bool checkconfig = FALSE;
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

#if 0
	/* efence settings */
	extern int EF_PROTECT_BELOW;
	extern int EF_PROTECT_FREE;

	EF_PROTECT_BELOW = 1;
	EF_PROTECT_FREE = 1;
#endif

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
			configsetup = TRUE;
			break;

		case 'K':
			checkconfig = TRUE;
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
			int ret = stat(ctlsocket == NULL ? DEFAULT_CTL_SOCKET :
				ctlsocket, &sb);

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

	if (verbose > 0)
		printf("opening file: %s\n", configfile);

	starter_use_log(verbose != 0, TRUE, verbose == 0);

	struct starter_config *cfg = NULL;

	{
		starter_errors_t errl = { NULL };

		cfg = confread_load(configfile, &errl, ctlsocket, configsetup);

		if (cfg == NULL) {
			fprintf(stderr, "cannot load config '%s': %s\n",
				configfile, errl.errors);
			pfreeany(errl.errors);
			exit(3);
		}
		if (errl.errors != NULL) {
			fprintf(stderr, "addconn, in config '%s', ignoring: %s\n",
				configfile, errl.errors);
			pfree(errl.errors);
		}
		if (checkconfig) {
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
			printf("  Pass #1: Loading auto=add, auto=route and auto=start connections\n");

		for (conn = cfg->conns.tqh_first; conn != NULL; conn = conn->link.tqe_next) {
			if (conn->desired_state == STARTUP_ADD ||
				conn->desired_state == STARTUP_ONDEMAND ||
				conn->desired_state == STARTUP_START)
			{
				if (verbose > 0)
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

		if (verbose > 0)
			printf("  Pass #2: Routing auto=route connections\n");

		for (conn = cfg->conns.tqh_first; conn != NULL; conn = conn->link.tqe_next) {
			if (conn->desired_state == STARTUP_ONDEMAND)
			{
				if (verbose > 0)
					printf(" %s", conn->name);
				if (conn->desired_state == STARTUP_ONDEMAND)
					starter_whack_route_conn(cfg, conn);
			}
		}

		if (verbose > 0)
			printf("  Pass #3: Initiating auto=start connections\n");

		for (conn = cfg->conns.tqh_first; conn != NULL; conn = conn->link.tqe_next) {
			if (conn->desired_state == STARTUP_START) {
				if (verbose > 0)
					printf(" %s", conn->name);
				starter_whack_initiate_conn(cfg, conn);
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
				printf(" %s", connname);

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
					resolve_defaultroute(conn);
					exit_status = starter_whack_add_conn(
						cfg, conn);
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
				if (conn->desired_state == STARTUP_ADD)
					printf("%s ", conn->name);
			}
		}
		if (listroute) {
			if (verbose > 0)
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
			if (verbose > 0)
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
			if (verbose > 0)
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
	/*
	 * Only RC_ codes between RC_DUPNAME and RC_NEW_STATE are errors
	 * Some starter code above can also return -1 which is not a valid RC_ code
	 */
	if (exit_status > 0 && (exit_status < RC_DUPNAME || exit_status >= RC_NEW_STATE))
		exit_status = 0;
	exit(exit_status);
}
