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
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <asm/types.h>
#include <sys/types.h>
#include <sys/ioctl.h>
/* #include <linux/netdevice.h> */
#include <net/if.h>
/* #include <linux/types.h> */ /* new */
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

/* #include <sys/socket.h> */

#include <netinet/in.h>
#include <arpa/inet.h>
/* #include <linux/ip.h> */
#include <netdb.h>

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
#include "ipsecconf/confread.h"
#include "ipsecconf/confwrite.h"
#include "ipsecconf/starterlog.h"
#include "ipsecconf/files.h"
#include "ipsecconf/starterwhack.h"
#include "ipsecconf/parser-controls.h"

char *progname;
static int verbose = 0;

static void usage(void)
{
	/* print usage */
	printf("Usage: %s [--config <file>] [--debug] [--rootdir <dir>] [--rootdir2 <dir2>]\n",
		progname);
	exit(0);
}


static const struct option longopts[] =
{
	{ "config",              required_argument, NULL, 'C' },
	{ "debug",               no_argument, NULL, 'D' },
	{ "verbose",             no_argument, NULL, 'D' },
	{ "rootdir",             required_argument, NULL, 'R' },
	{ "rootdir2",            required_argument, NULL, 'S' },
	{ "help",                no_argument, NULL, 'h' },
	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
	int opt = 0;
	struct starter_config *cfg = NULL;
	err_t err = NULL;
	char *confdir = NULL;
	char *configfile = NULL;
	struct starter_conn *conn = NULL;

	progname = argv[0];
	rootdir[0] = '\0';
	rootdir2[0] = '\0';

	tool_init_log();

	while ((opt = getopt_long(argc, argv, "", longopts, 0)) != EOF) {
		switch (opt) {
		case 'h':
			/* usage: */
			usage();
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
		case '?':
			exit(5);
		default:
			fprintf(stderr, "%s: getopt returned %d\n", progname, opt);
			exit(6);
		}
	}

	if (optind != argc) {
		fprintf(stderr,"%s: unexpected arguments\n",
			progname);
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

	starter_use_log(verbose != 0, TRUE, verbose == 0);

	cfg = confread_load(configfile, &err, FALSE, NULL, FALSE);

	if (cfg == NULL) {
		fprintf(stderr, "%s: config file \"%s\" cannot be loaded: %s\n",
			progname, configfile, err);
		exit(3);
	}

	/* load all conns marked as auto=add or better */
	for (conn = cfg->conns.tqh_first;
	     conn != NULL;
	     conn = conn->link.tqe_next)
		printf("#conn %s loaded\n", conn->name);

	confwrite(cfg, stdout);
	confread_free(cfg);
	exit(0);
}
