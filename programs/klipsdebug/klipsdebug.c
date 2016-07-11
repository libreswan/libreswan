/*
 * control KLIPS debugging options
 * Copyright (C) 1996  John Ioannidis.
 * Copyright (C) 1998, 1999, 2000, 2001  Richard Guy Briggs <rgb@freeswan.org>
 *                                 2001  Michael Richardson <mcr@freeswan.org>
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
#include <linux/types.h> /* new */
#include <string.h>
#include <errno.h>
#include <sys/wait.h>
#include <stdlib.h>     /* system() */
#include <sys/stat.h>   /* open() */
#include <fcntl.h>      /* open() */
#include <stdio.h>
#include <getopt.h>

#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <unistd.h>
#include <libreswan.h>
#if 0
#include <linux/autoconf.h>     /* CONFIG_IPSEC_PFKEYv2 */
#endif

/* permanently turn it on since netlink support has been disabled */
#include <signal.h>
#include <libreswan/pfkeyv2.h>
#include <libreswan/pfkey.h>
#include "libreswan/pfkey_debug.h"

#include "socketwrapper.h"
#include "lswlog.h"
#include "libreswan/radij.h"
#include "libreswan/ipsec_encap.h"
#ifndef CONFIG_KLIPS_DEBUG
#define CONFIG_KLIPS_DEBUG
#endif /* CONFIG_KLIPS_DEBUG */
#include "libreswan/ipsec_tunnel.h"

#include <stdio.h>
#include <getopt.h>

#include "lsw_select.h"
#include "lswlog.h"
__u32 bigbuf[1024];
char *program_name;

int pfkey_sock;
uint32_t pfkey_seq = 0;

char copyright[] =
	"Copyright (C) 1999 Henry Spencer, Richard Guy Briggs, D. Hugh Redelmeier,\n\
	Sandy Harris, Angelos D. Keromytis, John Ioannidis.\n\
\n\
   This program is free software; you can redistribute it and/or modify it\n\
   under the terms of the GNU General Public License as published by the\n\
   Free Software Foundation; either version 2 of the License, or (at your\n\
   option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.\n\
\n\
   This program is distributed in the hope that it will be useful, but\n\
   WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY\n\
   or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License\n\
   (file COPYING in the distribution) for more details.\n";

static void usage(char * arg)
{
	fprintf(stdout,
		"usage: %s {--set|--clear} {tunnel|tunnel-xmit|netlink|xform|eroute|spi|radij|esp|ah|rcv|pfkey|ipcomp|verbose}\n",
		arg);
	fprintf(stdout, "       %s {--all|--none}\n", arg);
	fprintf(stdout, "       %s --help\n", arg);
	fprintf(stdout, "       %s --version\n", arg);
	fprintf(stdout, "       %s\n", arg);
	fprintf(stdout, "        [ --debug ] is optional to any %s command\n",
		arg);
	fprintf(stdout,
		"        [ --label <label> ] is optional to any %s command.\n",
		arg);
	exit(1);
}

static const struct option longopts[] =
{
	{ "set", 1, 0, 's' },
	{ "clear", 1, 0, 'c' },
	{ "all", 0, 0, 'a' },
	{ "none", 0, 0, 'n' },
	{ "help", 0, 0, 'h' },
	{ "version", 0, 0, 'v' },
	{ "label", 1, 0, 'l' },
	{ "debug", 0, 0, 'd' },
	{ 0, 0, 0, 0 }
};

int main(int argc, char **argv)
{
/*	int fd; */
	unsigned char action = 0;
	int c;

	int error = 0;
	int argcount = argc;
	int em_db_tn, em_db_nl, em_db_xf, em_db_er, em_db_sp;
	int em_db_rj, em_db_es, em_db_ah, em_db_rx, em_db_ky;
	int em_db_gz, em_db_vb;

	struct sadb_ext *extensions[K_SADB_EXT_MAX + 1];
	struct sadb_msg *pfkey_msg;

	em_db_tn = em_db_nl = em_db_xf = em_db_er = em_db_sp = 0;
	em_db_rj = em_db_es = em_db_ah = em_db_rx = em_db_ky = 0;
	em_db_gz = em_db_vb = 0;

	program_name = argv[0];

	while ((c = getopt_long(argc, argv, "" /*"s:c:anhvl:+:d"*/,
				longopts, 0)) != EOF) {
		switch (c) {
		case 'd':
			pfkey_lib_debug = PF_KEY_DEBUG_PARSE_MAX;
			argcount--;
			break;
		case 's':
			if (action) {
				fprintf(stderr,
					"%s: Only one of '--set', '--clear', '--all' or '--none' options permitted.\n",
					program_name);
				exit(1);
			}
			action = 's';
			em_db_tn = em_db_nl = em_db_xf = em_db_er = em_db_sp =
									    0;
			em_db_rj = em_db_es = em_db_ah = em_db_rx = em_db_ky =
									    0;
			em_db_gz = em_db_vb = 0;
			if (streq(optarg, "all")) {
				em_db_tn = em_db_nl = em_db_xf = em_db_er =
					em_db_sp = -1;
				em_db_rj = em_db_es = em_db_ah = em_db_rx =
					em_db_ky = -1;
				em_db_gz = -1;
				em_db_vb = 0;
			} else if (streq(optarg, "tunnel")) {
				em_db_tn = -1L;
			} else if (streq(optarg, "tncfg")) {
				em_db_tn = DB_TN_REVEC;
			} else if (streq(optarg, "xmit") ||
				   streq(optarg, "tunnel-xmit")) {
				em_db_tn = DB_TN_XMIT;
			} else if (streq(optarg, "netlink")) {
				em_db_nl = -1L;
			} else if (streq(optarg, "xform")) {
				em_db_xf = -1L;
			} else if (streq(optarg, "eroute")) {
				em_db_er = -1L;
			} else if (streq(optarg, "spi")) {
				em_db_sp = -1L;
			} else if (streq(optarg, "radij")) {
				em_db_rj = -1L;
			} else if (streq(optarg, "esp")) {
				em_db_es = -1L;
			} else if (streq(optarg, "ah")) {
				em_db_ah = -1L;
			} else if (streq(optarg, "rcv")) {
				em_db_rx = -1L;
			} else if (streq(optarg, "pfkey")) {
				em_db_ky = -1L;
			} else if (streq(optarg, "comp")) {
				em_db_gz = -1L;
			} else if (streq(optarg, "verbose")) {
				em_db_vb = -1L;
			} else {
				fprintf(stdout,
					"%s: unknown set argument '%s'\n",
					program_name, optarg);
				usage(program_name);
			}
			em_db_nl |= 1 << (sizeof(em_db_nl) * 8 - 1);
			break;
		case 'c':
			if (action) {
				fprintf(stderr,
					"%s: Only one of '--set', '--clear', '--all' or '--none' options permitted.\n",
					program_name);
				exit(1);
			}
			em_db_tn = em_db_nl = em_db_xf = em_db_er =
				em_db_sp = -1;
			em_db_rj = em_db_es = em_db_ah = em_db_rx =
				em_db_ky = -1;
			em_db_gz = em_db_vb = -1;

			action = 'c';
			if (streq(optarg, "all")) {
				em_db_tn = em_db_nl = em_db_xf = em_db_er =
					em_db_sp = 0;
				em_db_rj = em_db_es = em_db_ah = em_db_rx =
					em_db_ky = 0;
				em_db_gz = em_db_vb = 0;
			} else if (streq(optarg, "tunnel")) {
				em_db_tn = 0;
			} else if (streq(optarg, "tunnel-xmit") ||
				   streq(optarg, "xmit")) {
				em_db_tn = ~DB_TN_XMIT;
			} else if (streq(optarg, "netlink")) {
				em_db_nl = 0;
			} else if (streq(optarg, "xform")) {
				em_db_xf = 0;
			} else if (streq(optarg, "eroute")) {
				em_db_er = 0;
			} else if (streq(optarg, "spi")) {
				em_db_sp = 0;
			} else if (streq(optarg, "radij")) {
				em_db_rj = 0;
			} else if (streq(optarg, "esp")) {
				em_db_es = 0;
			} else if (streq(optarg, "ah")) {
				em_db_ah = 0;
			} else if (streq(optarg, "rcv")) {
				em_db_rx = 0;
			} else if (streq(optarg, "pfkey")) {
				em_db_ky = 0;
			} else if (streq(optarg, "comp")) {
				em_db_gz = 0;
			} else if (streq(optarg, "verbose")) {
				em_db_vb = 0;
			} else {
				fprintf(stdout,
					"%s: unknown clear argument '%s'\n",
					program_name, optarg);
				usage(program_name);
			}
			em_db_nl &= ~(1 << (sizeof(em_db_nl) * 8 - 1));
			break;
		case 'a':
			if (action) {
				fprintf(stderr,
					"%s: Only one of '--set', '--clear', '--all' or '--none' options permitted.\n",
					program_name);
				exit(1);
			}
			action = 'a';
			em_db_tn = em_db_nl = em_db_xf = em_db_er =
				em_db_sp = -1;
			em_db_rj = em_db_es = em_db_ah = em_db_rx =
				em_db_ky = -1;
			em_db_gz = -1;
			em_db_vb = 0;
			break;
		case 'n':
			if (action) {
				fprintf(stderr,
					"%s: Only one of '--set', '--clear', '--all' or '--none' options permitted.\n",
					program_name);
				exit(1);
			}
			action = 'n';
			em_db_tn = em_db_nl = em_db_xf = em_db_er =
				em_db_sp = 0;
			em_db_rj = em_db_es = em_db_ah = em_db_rx =
				em_db_ky = 0;
			em_db_gz = em_db_vb = 0;
			break;
		case 'h':
		case '?':
			usage(program_name);
			exit(1);
		case 'v':
			fprintf(stdout, "klipsdebug (Libreswan %s)\n",
				ipsec_version_code());
			fputs(copyright, stdout);
			exit(0);
		case 'l':
		{
			static const char combine_fmt[] = "%s --label %s";
			size_t room = strlen(argv[0]) +
					  sizeof(combine_fmt) +
					  strlen(optarg);

			program_name = malloc(room);
			snprintf(program_name, room, combine_fmt,
				argv[0],
				optarg);
			argcount -= 2;
			break;
		}
		default:
			fprintf(stdout, "%s: unknown option '%s'\n",
				program_name, argv[optind]);
			break;
		}
	}

	if (argcount == 1) {
		int ret = system("cat /proc/net/ipsec_klipsdebug");
		exit(ret != -1 && WIFEXITED(ret) ? WEXITSTATUS(ret) : 1);
	}

	if (!action)
		usage(program_name);

	if ((pfkey_sock = safe_socket(PF_KEY, SOCK_RAW, PF_KEY_V2) ) < 0) {
		fprintf(stderr,
			"%s: Trouble opening PF_KEY family socket with error: ",
			program_name);
		switch (errno) {
		case ENOENT:
			fprintf(stderr,
				"device does not exist.  See libreswan installation procedure.\n");
			break;
		case EACCES:
			fprintf(stderr, "access denied.  ");
			if (getuid() == 0)
				fprintf(stderr,
					"Check permissions.  Should be 600.\n");


			else
				fprintf(stderr,
					"You must be root to open this file.\n");


			break;
		case EUNATCH:
			fprintf(stderr,
				"Netlink not enabled OR KLIPS not loaded.\n");
			break;
		case ENODEV:
			fprintf(stderr, "KLIPS not loaded or enabled.\n");
			break;
		case EBUSY:
			fprintf(stderr,
				"KLIPS is busy.  Most likely a serious internal error occured in a previous command.  Please report as much detail as possible to development team.\n");
			break;
		case EINVAL:
			fprintf(stderr,
				"Invalid argument, KLIPS not loaded or check kernel log messages for specifics.\n");
			break;
		case ENOBUFS:
			fprintf(stderr, "No kernel memory to allocate SA.\n");
			break;
		case ESOCKTNOSUPPORT:
			fprintf(stderr,
				"Algorithm support not available in the kernel.  Please compile in support.\n");
			break;
		case EEXIST:
			fprintf(stderr,
				"SA already in use.  Delete old one first.\n");
			break;
		case ENXIO:
			fprintf(stderr,
				"SA does not exist.  Cannot delete.\n");
			break;
		case EAFNOSUPPORT:
			fprintf(stderr, "KLIPS not loaded or enabled.\n");
			break;
		default:
			fprintf(stderr,
				"Unknown file open error %d.  Please report as much detail as possible to development team.\n",
				errno);
		}
		exit(1);
	}

	pfkey_extensions_init(extensions);

	if ((error = pfkey_msg_hdr_build(&extensions[0],
					 SADB_X_DEBUG,
					 0,
					 0,
					 ++pfkey_seq,
					 getpid()))) {
		fprintf(stderr,
			"%s: Trouble building message header, error=%d.\n",
			program_name, error);
		pfkey_extensions_free(extensions);
		exit(1);
	}

	if ((error = pfkey_x_debug_build(&extensions[SADB_X_EXT_DEBUG],
					 em_db_tn,
					 em_db_nl,
					 em_db_xf,
					 em_db_er,
					 em_db_sp,
					 em_db_rj,
					 em_db_es,
					 em_db_ah,
					 em_db_rx,
					 em_db_ky,
					 em_db_gz,
					 em_db_vb))) {
		fprintf(stderr,
			"%s: Trouble building message header, error=%d.\n",
			program_name, error);
		pfkey_extensions_free(extensions);
		exit(1);
	}

	if ((error = pfkey_msg_build(&pfkey_msg, extensions, EXT_BITS_IN))) {
		fprintf(stderr,
			"%s: Trouble building pfkey message, error=%d.\n",
			program_name, error);
		pfkey_extensions_free(extensions);
		pfkey_msg_free(&pfkey_msg);
		exit(1);
	}

	if ((error = write(pfkey_sock,
			   pfkey_msg,
			   pfkey_msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN)) !=
	    (ssize_t)(pfkey_msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN)) {
		fprintf(stderr,
			"%s: pfkey write failed, tried to write %u octets, returning %d with errno=%d.\n",
			program_name,
			(unsigned)(pfkey_msg->sadb_msg_len *
				   IPSEC_PFKEYv2_ALIGN),
			error,
			errno);
		pfkey_extensions_free(extensions);
		pfkey_msg_free(&pfkey_msg);
		switch (errno) {
		case EACCES:
			fprintf(stderr, "access denied.  ");
			if (getuid() == 0)
				fprintf(stderr,
					"Check permissions.  Should be 600.\n");


			else
				fprintf(stderr,
					"You must be root to open this file.\n");


			break;
		case EUNATCH:
			fprintf(stderr,
				"Netlink not enabled OR KLIPS not loaded.\n");
			break;
		case EBUSY:
			fprintf(stderr,
				"KLIPS is busy.  Most likely a serious internal error occured in a previous command.  Please report as much detail as possible to development team.\n");
			break;
		case EINVAL:
			fprintf(stderr,
				"Invalid argument, check kernel log messages for specifics.\n");
			break;
		case ENODEV:
			fprintf(stderr, "KLIPS not loaded or enabled.\n");
			fprintf(stderr, "No device?!?\n");
			break;
		case ENOBUFS:
			fprintf(stderr, "No kernel memory to allocate SA.\n");
			break;
		case ESOCKTNOSUPPORT:
			fprintf(stderr,
				"Algorithm support not available in the kernel.  Please compile in support.\n");
			break;
		case EEXIST:
			fprintf(stderr,
				"SA already in use.  Delete old one first.\n");
			break;
		case ENOENT:
			fprintf(stderr,
				"device does not exist.  See libreswan installation procedure.\n");
			break;
		case ENXIO:
			fprintf(stderr,
				"SA does not exist.  Cannot delete.\n");
			break;
		case ENOSPC:
			fprintf(stderr,
				"no room in kernel SAref table.  Cannot process request.\n");
			break;
		case ESPIPE:
			fprintf(stderr,
				"kernel SAref table internal error.  Cannot process request.\n");
			break;
		default:
			fprintf(stderr,
				"Unknown socket write error %d.  Please report as much detail as possible to development team.\n",
				errno);
		}
		exit(1);
	}

	if (pfkey_msg) {
		pfkey_extensions_free(extensions);
		pfkey_msg_free(&pfkey_msg);
	}

	(void) close(pfkey_sock);  /* close the socket */
	exit(0);
}
