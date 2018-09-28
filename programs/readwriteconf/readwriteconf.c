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
#include "ipsecconf/starterlog.h"

static int verbose = 0;

static void usage(void)
{
	/* print usage */
	printf("Usage: %s [--config <file>] [--nosetup] [--debug] [--rootdir <dir>] [--rootdir2 <dir2>] [--conn conn_name]\n",
		progname);
	exit(0);
}


static const struct option longopts[] =
{
	{ "config",              required_argument, NULL, 'C' },
	{ "conn",                required_argument, NULL, 'c' },
	{ "debug",               no_argument, NULL, 'D' },
	{ "verbose",             no_argument, NULL, 'D' },
	{ "rootdir",             required_argument, NULL, 'R' },
	{ "rootdir2",            required_argument, NULL, 'S' },
	{ "nosetup",             no_argument, NULL, 'n' },
	{ "help",                no_argument, NULL, 'h' },
	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
	tool_init_log(argv[0]);

	int opt;
	struct starter_config *cfg = NULL;
	char *confdir = NULL;
	char *configfile = NULL;
	struct starter_conn *conn = NULL;
	char *name = NULL;
	bool setup = true;

	rootdir[0] = '\0';
	rootdir2[0] = '\0';

	while ((opt = getopt_long(argc, argv, "", longopts, 0)) != EOF) {
		switch (opt) {
		case 'h':
			/* usage: */
			usage();
			break;

		case 'n':
			setup = false;
			break;

		case 'D':
			verbose++;
			lex_verbosity++;
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

	/* find config file */
	if (confdir == NULL)
		confdir = IPSEC_CONFDIR;

	if (configfile == NULL) {
		/* ??? see code clone in programs/addconn/addconn.c */
		configfile = alloc_bytes(strlen(confdir) +
					 sizeof("/ipsec.conf"),
					 "conf file");

		/* calculate default value for configfile */
		strcpy(configfile, confdir);	/* safe: see allocation above */
		if (configfile[0] != '\0' && configfile[strlen(configfile) - 1] != '/')
			strcat(configfile, "/");	/* safe: see allocation above */
		strcat(configfile, "ipsec.conf");	/* safe: see allocation above */
	}

	if (verbose > 3) {
		yydebug = 1;
	}

	if (verbose)
		printf("opening file: %s\n", configfile);

	starter_use_log(verbose != 0, true, verbose == 0);

	starter_errors_t errl = { NULL };
	cfg = confread_load(configfile, &errl, NULL, false);

	if (cfg == NULL) {
		fprintf(stderr, "%s: config file \"%s\" cannot be loaded: %s\n",
			progname, configfile, errl.errors);
		pfreeany(errl.errors);
		exit(3);
	}
	if (errl.errors != NULL) {
		fprintf(stderr, "%s: config file \"%s\", ignoring: %s\n",
			progname, configfile, errl.errors);
		pfree(errl.errors);
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
	exit(0);
}
