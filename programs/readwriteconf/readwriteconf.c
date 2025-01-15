/*
 * This program reads a configuration file and then writes it out
 * again to stdout.
 * That's not that useful in practice, but it helps a lot in debugging.
 *
 * Copyright (C) 2006 Michael Richardson <mcr@xelerance.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdbool.h>
#include <string.h>

#include "err.h"
#include "lswtool.h"
#include "lswalloc.h"
#include "lswconf.h"
#include "lswlog.h"
#include "ipsecconf/confread.h"
#include "ipsecconf/confwrite.h"
#include "ipsecconf/parser-controls.h"
#include "optarg.h"

static void usage(void)
{
	/* print usage */
	printf("Usage: %s [--config <file>] [--nosetup] [--debug] [--rootdir <dir>] [--rootdir2 <dir2>] [--conn conn_name]\n",
		progname);
	exit(0);
}


/*
 * XXX: the letters below are meaningless as getopt_long() isn't
 * passing in an option string.
 */

enum opt {
	OPT_EOF = -1,
	OPT_VERBOSE = 256,
	OPT_DEBUG,
};

const struct option long_opts[] =
{
	{ "config",              required_argument, NULL, 'C' },
	{ "conn",                required_argument, NULL, 'c' },
	{ "debug",               no_argument, NULL, OPT_DEBUG, },
	{ "verbose",             no_argument, NULL, OPT_VERBOSE, },
	{ "rootdir",             required_argument, NULL, 'R' },
	{ "rootdir2",            required_argument, NULL, 'S' },
	{ "nosetup",             no_argument, NULL, 'n' },
	{ "help",                no_argument, NULL, 'h' },
	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
	struct logger *logger = tool_logger(argc, argv);

	int opt;
	char *configfile = NULL;
	struct starter_conn *conn = NULL;
	char *name = NULL;
	bool setup = true;

	rootdir[0] = '\0';
	rootdir2[0] = '\0';

	while ((opt = getopt_long(argc, argv, "", long_opts, 0)) != EOF) {
		switch (opt) {
		case 'h':
			/* usage: */
			usage();
			break;

		case 'n':
			setup = false;
			break;

		case OPT_VERBOSE:
			optarg_verbose(LEMPTY);
			break;
		case OPT_DEBUG:
			optarg_debug(/*enable*/true);
			break;

		case 'C':
			configfile = clone_str(optarg, "config file name");
			break;

		case 'R':
			printf("#setting rootdir=%s\n", optarg);
			jam_str(rootdir, sizeof(rootdir), optarg);
			break;

		case 'S':
			printf("#setting rootdir2=%s\n", optarg);
			jam_str(rootdir2, sizeof(rootdir2), optarg);
			break;
		case 'c':
			name = optarg;
			break;
		case '?':
			exit(5);
		default:
			fprintf(stderr, "%s: getopt returned %d\n", progname, opt);
			exit(6);
		}
	}

	if (optind != argc) {
		fprintf(stderr, "%s: unexpected arguments\n", progname);
		exit(4);
	}

	/* update fields dependent on VERBOSE */
	yydebug = (verbose >= 4);
	lex_verbosity = verbose;

	/* logged when true */
	ldbg(logger, "debugging mode enabled");

	if (configfile == NULL) {
		configfile = clone_str(IPSEC_CONF, "default ipsec.conf file");
	}
	if (verbose > 0) {
		printf("opening file: %s\n", configfile);
	}

	struct starter_config *cfg = confread_load(configfile, false,
						   0, NULL, logger);
	if (cfg == NULL) {
		llog(RC_LOG, logger, "cannot load config file '%s'", configfile);
		exit(3);
	}

	/* load all conns marked as auto=add or better */
	if (verbose) {
		for (conn = cfg->conns.tqh_first;
		     conn != NULL;
		     conn = conn->link.tqe_next)
				printf("#conn %s loaded\n", conn->name);
	}

	confwrite(cfg, stdout, setup, name, verbose);
	confread_free(cfg);
	pfreeany(configfile);
	exit(0);
}
