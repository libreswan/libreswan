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
#include <stdbool.h>
#include <string.h>

#include "err.h"
#include "lswtool.h"
#include "lswalloc.h"
#include "lswconf.h"
#include "lswlog.h"
#include "ipsecconf/confread.h"
#include "ipsecconf/confwrite.h"
#include "optarg.h"

/*
 * XXX: the letters below are meaningless as getopt_long() isn't
 * passing in an option string.
 */

enum opt {
	OPT_VERBOSE = 256,
	OPT_DEBUG,
	OPT_CONFIG = 'C',
	OPT_CONN = 'c',
	OPT_HELP = 'h',
	OPT_NOSETUP = 'n',
};

const struct option optarg_options[] =
{
	{ "config\0<file>",      required_argument, NULL, OPT_CONFIG },
	{ "conn\0<conn-name>",   required_argument, NULL, OPT_CONN },
	{ OPT("debug", "help|<debug-flags>"), optional_argument, NULL, OPT_DEBUG, },
	{ "verbose\0",           no_argument, NULL, OPT_VERBOSE, },
	{ "rootdir"METAOPT_OBSOLETE, no_argument, NULL, 0, },
	{ "rootdir2"METAOPT_OBSOLETE, no_argument, NULL, 0, },
	{ "nosetup",             no_argument, NULL, OPT_NOSETUP },
	{ "help",                no_argument, NULL, OPT_HELP },
	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
	struct logger *logger = tool_logger(argc, argv);

	char *configfile = NULL;
	struct starter_conn *conn = NULL;
	char *name = NULL;
	bool setup = true;

	while (true) {
		int c = optarg_getopt(logger, argc, argv, "");
		if (c < 0) {
			break;
		}

		switch ((enum opt)c) {

		case OPT_HELP:
			/* usage: */
			optarg_usage(argv[0], "", "");

		case OPT_NOSETUP:
			setup = false;
			continue;

		case OPT_VERBOSE:
			optarg_verbose(logger, LEMPTY);
			continue;
		case OPT_DEBUG:
			optarg_debug(OPTARG_DEBUG_YES);
			continue;

		case OPT_CONFIG:
			configfile = clone_str(optarg, "config file name");
			continue;

		case OPT_CONN:
			name = optarg;
			continue;
		}

		bad_case(c);
	}

	if (optind != argc) {
		fprintf(stderr, "%s: unexpected arguments\n", progname);
		exit(4);
	}

	/* logged when true */
	ldbg(logger, "debugging mode enabled");

	if (configfile == NULL) {
		configfile = clone_str(IPSEC_CONF, "default ipsec.conf file");
	}
	if (verbose > 0) {
		printf("opening file: %s\n", configfile);
	}

	struct starter_config *cfg = confread_load(configfile, false, logger, verbose);
	if (cfg == NULL) {
		llog(RC_LOG, logger, "cannot load config file '%s'", configfile);
		exit(3);
	}

	if (!confread_validate_conns(cfg, logger)) {
		/* already logged? */
		llog(RC_LOG, logger, "cannot validate config file '%s'", configfile);
		exit(3);
	}

	/* load all conns marked as auto=add or better */
	if (verbose) {
		TAILQ_FOREACH(conn, &cfg->conns, link) {
			printf("#conn %s loaded\n", conn->name);
		}
	}

	confwrite(cfg, stdout, setup, name, verbose);
	confread_free(cfg);
	pfreeany(configfile);
	exit(0);
}
