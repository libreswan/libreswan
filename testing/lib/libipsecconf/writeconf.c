/*
 * This test writes a configuration file from internal state.
 *
 * Copyright (C) 2009 Michael Richardson <mcr@sandelman.ca>
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

char *progname;
static int verbose = 0;
int warningsarefatal = 0;

static const char *usage_string = ""
				  "Usage: writeconf\n";

static void usage(void)
{
	/* print usage */
	fputs(usage_string, stderr);
	exit(10);
}

extern char rootdir[PATH_MAX];          /* when evaluating paths, prefix this to them */
extern char rootdir2[PATH_MAX];         /* when evaluating paths, prefix this to them */

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
	tool_init_log();
	starter_use_log(verbose != 0, TRUE, verbose == 0);

	cfg = (struct starter_config *)malloc(sizeof(struct starter_config));
	if (cfg == NULL) {
		fprintf(stderr, "can't allocate mem in %s\n", progname);
		exit(10);
	}

	/**
	 * Set default values
	 */
	ipsecconf_default_values(cfg);

	conn = alloc_add_conn(cfg, "mytestconn", &err);

	conn->connalias = xstrdup("anotheralias");

	conn->options[KBF_DPDDELAY] = 60;
	conn->options_set[KBF_DPDDELAY] = 1;

	conn->policy = POLICY_ENCRYPT | POLICY_PFS | POLICY_COMPRESS;

	conn->left.rsakey1 = "0sabcdabcdabcd";
	conn->left.rsakey2 = "0s23489234ba28934243";
	conn->left.cert = "/my/cert/file";
	ttoaddr("192.168.2.102", 0, AF_INET, &conn->left.sourceip);

	ttoaddr("192.168.1.101", 0, AF_INET, &conn->left.addr);
	conn->left.addr_family = AF_INET;
	conn->left.addrtype   = KH_IPADDR;

	conn->right.addrtype  = KH_DEFAULTROUTE;

	confwrite(cfg, stdout);

	exit(0);
}

void exit_tool(int x)
{
	exit(x);
}
