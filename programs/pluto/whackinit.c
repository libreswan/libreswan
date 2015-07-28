/* command interface to Pluto - initiate a connection only.
 * suitable for setuid use.
 *
 * Copyright (C) 2004 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010 Simon Deziel <simon@xelerance.com>
 * Copyright (C) 2010 Harald Jenny <harald@a-little-linux-box.at>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <assert.h>

#include <libreswan.h>
#include "socketwrapper.h"
#include "constants.h"
#include "lswlog.h"

#include "defs.h"
#include "whack.h"

static int setup_socket(void);

/**
 * Print the 'ipsec whackinit --help' message
 */
static void help(void)
{
	fprintf(stderr,
		"Usage:\n\n"
		"all forms:"
		" [--ctlbase <path>]"
		" [--label <string>]"
		"\n\n"
		"help: whack"
		" [--help]"
		" [--version]"
		"\n\n"
		"connection: whack"
		" whack"
		" (--initiate | --terminate)"
		" --name <connection_name>"
		" [--asynchronous]"
		" [--xauthname name]"
		" [--xauthpass pass]"
		"\n\n"
		"status: whack"
		" --status"
		"\n\n"
		"Libreswan %s\n",
		ipsec_version_code());
}

static const char *label = NULL;        /* --label operand, saved for diagnostics */

static const char *name = NULL;         /* --name operand, saved for diagnostics */

/** Print a string as a diagnostic, then exit whack unhappily
 *
 * @param mess The error message to print when exiting
 * @return NEVER
 */
static void diag(const char *mess) NEVER_RETURNS;

static void diag(const char *mess)
{
	if (mess != NULL) {
		fprintf(stderr, "whackinit error: ");
		if (label != NULL)
			fprintf(stderr, "%s ", label);
		if (name != NULL)
			fprintf(stderr, "\"%s\" ", name);
		fprintf(stderr, "%s\n", mess);
	}

	exit(RC_WHACK_PROBLEM);
}

/**
 * Conditially calls diag if ugh is set.
 * Prints second arg, if non-NULL, as quoted string
 *
 * @param ugh Error message
 * @param this Optional 2nd part of error message
 * @return void
 */
static void diagq(err_t ugh, const char *this)
{
	if (ugh != NULL) {
		if (this == NULL) {
			diag(ugh);
		} else {
			char buf[120]; /* arbitrary limit */

			snprintf(buf, sizeof(buf), "%s \"%s\"", ugh, this);
			diag(buf);
		}
	}
}

/**
 * complex combined operands return one of these enumerated values
 * Note: these become flags in an lset_t.  Since there are more than
 * 32, we partition them into:
 * - OPT_* options (most random options)
 * - LST_* options (list various internal data)
 * - DBGOPT_* option (DEBUG options)
 * - END_* options (End description options)
 * - CD_* options (Connection Description options)
 */
enum option_enums {
#   define OPT_FIRST    OPT_NAME
	OPT_NAME,

	OPT_INITIATE,
	OPT_TERMINATE,
	OPT_STATUS,
	OPT_TRAFFIC_STATUS,

	OPT_OPPO_HERE,
	OPT_OPPO_THERE,

	OPT_ASYNC,

	OPT_XAUTHNAME,
	OPT_XAUTHPASS,

#   define OPT_LAST OPT_ASYNC   /* last "normal" option */
};

/* Carve up space for result from getopt_long.
 * Stupidly, the only result is an int.
 * Numeric arg is bit immediately left of basic value.
 *
 */
#define OPTION_OFFSET   256     /* to get out of the way of letter options */
#define NUMERIC_ARG (1 << 9)    /* expect a numeric argument */
#define AUX_SHIFT   10          /* amount to shift for aux information */

static const struct option long_opts[] = {
#   define OO   OPTION_OFFSET
	/* name, has_arg, flag, val */

	{ "help", no_argument, NULL, 'h' },
	{ "version", no_argument, NULL, 'v' },
	{ "label", required_argument, NULL, 'l' },

	{ "name", required_argument, NULL, OPT_NAME + OO },

	{ "initiate", no_argument, NULL, OPT_INITIATE + OO },
	{ "terminate", no_argument, NULL, OPT_TERMINATE + OO },

	{ "status", no_argument, NULL, OPT_STATUS + OO },
	{ "trafficstatus", no_argument, NULL, OPT_TRAFFIC_STATUS + OO },
	{ "xauthname", required_argument, NULL, OPT_XAUTHNAME + OO },
	{ "xauthuser", required_argument, NULL, OPT_XAUTHNAME + OO },
	{ "xauthpass", required_argument, NULL, OPT_XAUTHPASS + OO },

#if 0
	/* maybe let users do this? */
	{ "oppohere", required_argument, NULL, OPT_OPPO_HERE + OO },
	{ "oppothere", required_argument, NULL, OPT_OPPO_THERE + OO },
#endif

	{ "asynchronous", no_argument, NULL, OPT_ASYNC + OO },

	/* list options */

#   undef OO
	{ 0, 0, 0, 0 }
};

struct sockaddr_un ctl_addr = { AF_UNIX, DEFAULT_CTLBASE CTL_SUFFIX };

/* helper variables and function to encode strings from whack message */

static char
	*next_str,
	*str_roof;

static bool pack_str(char **p)
{
	const char *s = *p == NULL ? "" : *p;   /* note: NULL becomes ""! */
	size_t len = strlen(s) + 1;

	if (str_roof - next_str < (ptrdiff_t)len) {
		return FALSE; /* fishy: no end found */
	} else {
		strcpy(next_str, s);
		next_str += len;
		*p = NULL; /* don't send pointers on the wire! */
		return TRUE;
	}
}

/* ??? bufsize must be PASS_MAX + 1 (documented in getpass(3)) */
static size_t get_secret(char *buf, size_t bufsize)
{
	const char *secret;
	size_t len;

	fflush(stdout);
	usleep(20000); /* give fflush time for flushing */
	/* ??? the function getpass(3) is obsolete! */
	secret = getpass("Enter passphrase: ");

	len = (secret == NULL? 0 : strlen(secret)) + 1;
	if (len > bufsize)
		len = bufsize;
	if (len > 0) {
		memcpy(buf, secret, len - 1);
		buf[len - 1] = '\0';
	}
	return len;
}

static int get_value(char *buf, size_t bufsize)
{
	int len;
	int try;

	fflush(stdout);
	usleep(20000); /* give fflush time for flushing - has to go through awk */

	try = 3;
	len = 0;
	while (try > 0 && len == 0) {
		fprintf(stderr, "Enter username:   ");

		memset(buf, 0, bufsize);

		if (fgets(buf, bufsize, stdin) != buf) {
			if (errno == 0) {
				fprintf(stderr,
					"Can not read password from standard in\n");
				exit(RC_WHACK_PROBLEM);
			} else {
				perror("fgets value");
				exit(RC_WHACK_PROBLEM);
			}
		}

		/* send the value to pluto, including \0, but fgets adds \n */
		len = strlen(buf);
		if (len == 0)
			fprintf(stderr, "answer was empty, retry\n");
	}
	if (len ==  0)
		exit(RC_WHACK_PROBLEM);

	return len;
}

static void send_reply(int sock, char *buf, ssize_t len)
{
	/* send the secret to pluto */
	if (write(sock, buf, len) != len) {
		int e = errno;

		fprintf(stderr, "whack: write() failed (%d %s)\n", e,
			strerror(e));
		exit(RC_WHACK_PROBLEM);
	}
}

static int setup_socket()
{
	int sock = safe_socket(AF_UNIX, SOCK_STREAM, 0);

#if 0
	/* send message to Pluto */
	if (access(ctl_addr.sun_path, R_OK | W_OK) < 0) {
		int e = errno;

		switch (e) {
		case EACCES:
			fprintf(stderr,
				"whack: no right to communicate with pluto (access(\"%s\"))\n",
				ctl_addr.sun_path);
			fprintf(stderr,
				"My uid: %d my euid: %d gid: %d egid: %d\n",
				getuid(), geteuid(), getgid(), getegid());
			break;
		case ENOENT:
			fprintf(stderr,
				"whack: Pluto is not running (no \"%s\")\n",
				ctl_addr.sun_path);
			break;
		default:
			fprintf(stderr,
				"whack: access(\"%s\") failed with %d %s\n",
				ctl_addr.sun_path, errno, strerror(e));
			break;
		}
		exit(RC_WHACK_PROBLEM);
	}
#endif

	if (sock == -1) {
		int e = errno;

		fprintf(stderr, "whack: socket() failed (%d %s)\n", e, strerror(
				e));
		exit(RC_WHACK_PROBLEM);
	}

	if (connect(sock, (struct sockaddr *)&ctl_addr,
		    offsetof(struct sockaddr_un,
			     sun_path) + strlen(ctl_addr.sun_path)) < 0) {
		int e = errno;

		switch (e) {
		case EACCES:
			fprintf(stderr,
				"whack: no right to communicate with pluto (access(\"%s\"))\n",
				ctl_addr.sun_path);
			fprintf(stderr,
				"My uid: %d my euid: %d gid: %d egid: %d\n",
				getuid(), geteuid(), getgid(), getegid());
			break;
		case ENOENT:
			fprintf(stderr,
				"whack: Pluto is not running (no \"%s\")\n",
				ctl_addr.sun_path);
			break;
		case ECONNREFUSED:
			fprintf(stderr,
				"whack: is Pluto running connect() for \"%s\" failed (%d %s)\n",
				ctl_addr.sun_path, e, strerror(e));
			break;
		default:
			fprintf(stderr,
				"whack: connect() for \"%s\" failed (%d %s)\n",
				ctl_addr.sun_path, e, strerror(e));
			break;
		}
		exit(RC_WHACK_PROBLEM);
	}

	/* give up all root priveledges, if we had any */
	setuid(getuid());

	/* give up any group priveledges, if we had any */
	setgid(getgid());

	return sock;
}

/* This is a hack for initiating ISAKMP exchanges. */
int main(int argc, char **argv)
{
	struct whack_message msg;
	lset_t
		opts_seen = LEMPTY,
		cd_seen = LEMPTY;

	char xauthname[128];
	char xauthpass[128];
	int xauthnamelen, xauthpasslen;
	bool gotxauthname = FALSE, gotxauthpass = FALSE;
	int sock;

	/* get socket, and then drop root */
	sock = setup_socket();

	/* check division of numbering space */
	assert(OPT_LAST - OPT_FIRST < (sizeof cd_seen * BITS_PER_BYTE));

	zero(&msg);	/* ??? pointer fields might not be NULLed */

	clear_end(&msg.right);  /* left set from this after --to */

	msg.name = NULL;
	msg.keyid = NULL;
	msg.keyval.ptr = NULL;
	msg.esp = NULL;
	msg.ike = NULL;
	msg.pfsgroup = NULL;

#ifdef HAVE_LABELED_IPSEC
	msg.policy_label = NULL;
#endif

	msg.modecfg_domain = NULL;
	msg.modecfg_banner = NULL;

	msg.sa_ike_life_seconds = OAKLEY_ISAKMP_SA_LIFETIME_DEFAULT;
	msg.sa_ipsec_life_seconds = PLUTO_SA_LIFE_DURATION_DEFAULT;
	msg.sa_rekey_margin = SA_REPLACEMENT_MARGIN_DEFAULT;
	msg.sa_rekey_fuzz = SA_REPLACEMENT_FUZZ_DEFAULT;
	msg.sa_keying_tries = SA_REPLACEMENT_RETRIES_DEFAULT;

	msg.addr_family = AF_INET;
	msg.tunnel_addr_family = AF_INET;

	for (;; ) {
		int long_index;
		unsigned long opt_whole; /* numeric argument for some flags */

		/* Note: we don't like the way short options get parsed
		 * by getopt_long, so we simply pass an empty string as
		 * the list.  It could be "hp:d:c:o:eatfs" "NARXPECK".
		 */
		int c = getopt_long(argc, argv, "", long_opts,
				    &long_index) - OPTION_OFFSET;
		int aux = 0;

		/* decode a numeric argument, if expected */
		if (0 <= c) {
			if (c & NUMERIC_ARG) {
				c -= NUMERIC_ARG;
				if (ttoul(optarg, 0, 0, &opt_whole) != NULL)
					diagq("badly formed numeric argument",
					      optarg);
			}
			if (c >= (1 << AUX_SHIFT)) {
				aux = c >> AUX_SHIFT;
				c -= aux << AUX_SHIFT;
			}
		}

		/* per-class option processing */
		if (0 <= c && c < OPT_LAST) {
			/* OPT_* options get added opts_seen.
			 * Reject repeated options (unless later code intervenes).
			 */
			lset_t f = LELEM(c);

			if (opts_seen & f)
				diagq("duplicated flag",
				      long_opts[long_index].name);
			opts_seen |= f;
		}

		/* Note: "break"ing from switch terminates loop.
		 * most cases should end with "continue".
		 */
		switch (c) {
		case EOF - OPTION_OFFSET: /* end of flags */
			break;

		case 0 - OPTION_OFFSET: /* long option already handled */
			continue;

		case ':' - OPTION_OFFSET:       /* diagnostic already printed by getopt_long */
		case '?' - OPTION_OFFSET:       /* diagnostic already printed by getopt_long */
			diag(NULL);             /* print no additional diagnostic, but exit sadly */
			break;                  /* not actually reached */

		case 'h' - OPTION_OFFSET:       /* --help */
			help();
			return 0;               /* GNU coding standards say to stop here */

		case 'v' - OPTION_OFFSET:       /* --version */
		{
			printf("%s\n", ipsec_version_string());
		}
			return 0;               /* GNU coding standards say to stop here */

		case 'l' - OPTION_OFFSET:       /* --label <string> */
			label = optarg;         /* remember for diagnostics */
			continue;

		/* the rest of the options combine in complex ways */
		case OPT_NAME: /* --name <connection-name> */
			name = optarg;
			msg.name = optarg;
			continue;

		case OPT_INITIATE: /* --initiate */
			msg.whack_initiate = TRUE;
			continue;

		case OPT_TERMINATE: /* --terminate */
			msg.whack_terminate = TRUE;
			continue;

		case OPT_STATUS: /* --status */
			msg.whack_status = TRUE;
			continue;

		case OPT_STATUS: /* --trafficstatus */
			msg.whack_traffic_status = TRUE;
			continue;

#if 0
		/* hmm */
		case OPT_OPPO_HERE: /* --oppohere <ip-address> */
			tunnel_af_used_by = long_opts[long_index].name;
			diagq(ttoaddr(optarg, 0, msg.tunnel_addr_family,
				      &msg.oppo_my_client), optarg);
			if (isanyaddr(&msg.oppo_my_client))
				diagq("0.0.0.0 or 0::0 isn't a valid client address",
					optarg);
			continue;

		case OPT_OPPO_THERE: /* --oppohere <ip-address> */
			tunnel_af_used_by = long_opts[long_index].name;
			diagq(ttoaddr(optarg, 0, msg.tunnel_addr_family,
				      &msg.oppo_peer_client), optarg);
			if (isanyaddr(&msg.oppo_peer_client))
				diagq("0.0.0.0 or 0::0 isn't a valid client address",
					optarg);
			continue;
#endif

		case OPT_ASYNC:
			msg.whack_async = TRUE;
			continue;

		case OPT_XAUTHNAME:
			{
				char *p = jam_str(xauthname, sizeof(xauthname), optarg);

				xauthnamelen = p - xauthname + 1;
				gotxauthname = TRUE;
			}
			continue;

		case OPT_XAUTHPASS:
			{
				char *p = jam_str(xauthpass, sizeof(xauthpass), optarg);

				xauthpasslen = p - xauthpass + 1;
				gotxauthpass = TRUE;
			}
			continue;

		default:
			assert(FALSE); /* unknown return value */
		}
		break;
	}

	if (optind != argc) {
		/* If you see this message unexpectedly, perhaps the
		 * case for the previous option ended with "break"
		 * instead of "continue"
		 */
		diagq("unexpected argument", argv[optind]);
	}

	/* For each possible form of the command, figure out if an argument
	 * suggests whether that form was intended, and if so, whether all
	 * required information was supplied.
	 */

#if 0
	/* check opportunistic initiation simulation request */
	switch (opts_seen & (LELEM(OPT_OPPO_HERE) | LELEM(OPT_OPPO_THERE))) {
	case LELEM(OPT_OPPO_HERE):
	case LELEM(OPT_OPPO_THERE):
		diag("--oppohere and --oppothere must be used together");
	/*NOTREACHED*/
	case LELEM(OPT_OPPO_HERE) | LELEM(OPT_OPPO_THERE):
		msg.whack_oppo_initiate = TRUE;
		if (LIN(cd_seen,
			LELEM(CD_TUNNELIPV4 -
			      CD_FIRST) | LELEM(CD_TUNNELIPV6 - CD_FIRST)))
			opts_seen &= ~LELEM(OPT_CD);
		break;
	}
#endif

	/* decide whether --name is mandatory or forbidden */
	if (LELEM(OPT_INITIATE) | LELEM(OPT_TERMINATE)) {
		if (!LHAS(opts_seen, OPT_NAME))
			diag("missing --name <connection_name>");
	} else if (!msg.whack_options) {
		if (LHAS(opts_seen, OPT_NAME))
			diag("no reason for --name");
	}

	if (!(msg.whack_initiate || msg.whack_terminate ||
	      msg.whack_status|msg.whack_traffic_status))
		diag("no action specified; try --help for hints");

	/* pack strings for inclusion in message */
	next_str = msg.string;
	str_roof = &msg.string[sizeof(msg.string)];

	if (!pack_str(&msg.name) ||                             /* string  1 */
	    str_roof - next_str < (ptrdiff_t)msg.keyval.len)    /* chunk (sort of string 5) */
		diag("too many bytes of strings to fit in message to pluto");

	memcpy(next_str, msg.keyval.ptr, msg.keyval.len);
	msg.keyval.ptr = NULL;
	next_str += msg.keyval.len;

	msg.magic = ((opts_seen & ~(LELEM(OPT_STATUS)))) != LEMPTY ||
		    msg.whack_options ?
		    WHACK_MAGIC : WHACK_BASIC_MAGIC;

	{
		int exit_status = 0;
		ssize_t len = next_str - (char *)&msg;

		if (write(sock, &msg, len) != len) {
			int e = errno;

			fprintf(stderr, "whack: write() failed (%d %s)\n", e, strerror(
					e));
			exit(RC_WHACK_PROBLEM);
		}

		/* for now, just copy reply back to stdout */

		{
			char buf[4097]; /* arbitrary limit on log line length */
			char *be = buf;

			for (;; ) {
				char *ls = buf;
				ssize_t rl =
					read(sock, be,
					     (buf + sizeof(buf) - 1) - be);

				if (rl < 0) {
					int e = errno;

					fprintf(stderr,
						"whack: read() failed (%d %s)\n", e,
						strerror(e));
					exit(RC_WHACK_PROBLEM);
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

					le++; /* include NL in line */
					write(STDOUT_FILENO, ls, le - ls);

					/* figure out prefix number
					 * and how it should affect our exit status
					 */
					/*
					 * we don't generally use strtoul but
					 * in this case, its failure mode
					 * (0 for nonsense) is probably OK.
					 */
					{
						unsigned long s = strtoul(ls,
									  NULL,
									  10);

						switch (s) {
						case RC_COMMENT:
						case RC_LOG:
							/* ignore */
							break;
						case RC_SUCCESS:
							/* be happy */
							exit_status = 0;
							break;

						case RC_ENTERSECRET:
							if (!gotxauthpass) {
								xauthpasslen =
									get_secret(xauthpass,
										sizeof(xauthpass));
							}
							send_reply(sock,
								   xauthpass,
								   xauthpasslen);
							break;

						case RC_XAUTHPROMPT:
							if (!gotxauthname) {
								xauthnamelen =
									get_value(xauthname,
										sizeof(xauthname));
							}
							send_reply(sock,
								   xauthname,
								   xauthnamelen);
							break;

						default:
							/* pass through */
							exit_status = s;
							break;
						}
					}
					ls = le;
				}
			}
		}
		return exit_status;
	}
}
