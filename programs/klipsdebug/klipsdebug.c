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

char klipsdebug_c_version[] = "RCSID $Id: klipsdebug.c,v 1.58 2005/08/18 14:04:39 ken Exp $";


#include <sys/types.h>
#include <linux/types.h> /* new */
#include <string.h>
#include <errno.h>
#include <sys/wait.h>
#include <stdlib.h> /* system(), strtoul() */
#include <sys/stat.h> /* open() */
#include <fcntl.h> /* open() */
#include <stdio.h>
#include <getopt.h>

#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>



#include <unistd.h>
#include <openswan.h>
#if 0
#include <linux/autoconf.h>	/* CONFIG_IPSEC_PFKEYv2 */
#endif

/* permanently turn it on since netlink support has been disabled */
#include <signal.h>
#include <openswan/pfkeyv2.h>
#include <openswan/pfkey.h>

#include "oswlog.h"
#include "openswan/radij.h"
#include "openswan/ipsec_encap.h"
#ifndef CONFIG_KLIPS_DEBUG
#define CONFIG_KLIPS_DEBUG
#endif /* CONFIG_KLIPS_DEBUG */
#include "openswan/ipsec_tunnel.h"

__u32 bigbuf[1024];
char *program_name;

int pfkey_sock;
fd_set pfkey_socks;
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

static void
usage(char * arg)
{
	fprintf(stdout, "usage: %s {--set|--clear} {tunnel|tunnel-xmit|netlink|xform|eroute|spi|radij|esp|ah|rcv|pfkey|ipcomp|verbose}\n", arg);
	fprintf(stdout, "       %s {--all|--none}\n", arg);
	fprintf(stdout, "       %s --help\n", arg);
	fprintf(stdout, "       %s --version\n", arg);
	fprintf(stdout, "       %s\n", arg);
	fprintf(stdout, "        [ --debug ] is optional to any %s command\n", arg);
	fprintf(stdout, "        [ --label <label> ] is optional to any %s command.\n", arg);
	exit(1);
}

static struct option const longopts[] =
{
	{"set", 1, 0, 's'},
	{"clear", 1, 0, 'c'},
	{"all", 0, 0, 'a'},
	{"none", 0, 0, 'n'},
	{"help", 0, 0, 'h'},
	{"version", 0, 0, 'v'},
	{"label", 1, 0, 'l'},
	{"optionsfrom", 1, 0, '+'},
	{"debug", 0, 0, 'd'},
	{0, 0, 0, 0}
};

int
main(int argc, char **argv)
{
/*	int fd; */
	unsigned char action = 0;
	int c, previous = -1;
	
	int debug = 0;
	int error = 0;
	int argcount = argc;
	int em_db_tn, em_db_nl, em_db_xf, em_db_er, em_db_sp;
	int em_db_rj, em_db_es, em_db_ah, em_db_rx, em_db_ky;
	int em_db_gz, em_db_vb;

	struct sadb_ext *extensions[SADB_EXT_MAX + 1];
	struct sadb_msg *pfkey_msg;
	
	em_db_tn=em_db_nl=em_db_xf=em_db_er=em_db_sp=0;
	em_db_rj=em_db_es=em_db_ah=em_db_rx=em_db_ky=0;
	em_db_gz=em_db_vb=0;


	program_name = argv[0];

	while((c = getopt_long(argc, argv, ""/*"s:c:anhvl:+:d"*/, longopts, 0)) != EOF) {
		switch(c) {
		case 'd':
			debug = 1;
			pfkey_lib_debug = PF_KEY_DEBUG_PARSE_MAX;
			argcount--;
			break;
		case 's':
			if(action) {
				fprintf(stderr, "%s: Only one of '--set', '--clear', '--all' or '--none' options permitted.\n",
					program_name);
				exit(1);
			}
			action = 's';
			em_db_tn=em_db_nl=em_db_xf=em_db_er=em_db_sp=0;
			em_db_rj=em_db_es=em_db_ah=em_db_rx=em_db_ky=0;
			em_db_gz=em_db_vb=0;
			if(strcmp(optarg, "tunnel") == 0) {
				em_db_tn = -1L;
			} else if(strcmp(optarg, "tncfg") == 0) {
			        em_db_tn = DB_TN_REVEC;
			} else if(strcmp(optarg, "tunnel-xmit") == 0) {
				em_db_tn = DB_TN_XMIT;
			} else if(strcmp(optarg, "netlink") == 0) {
				em_db_nl = -1L;
			} else if(strcmp(optarg, "xform") == 0) {
				em_db_xf = -1L;
			} else if(strcmp(optarg, "eroute") == 0) {
				em_db_er = -1L;
			} else if(strcmp(optarg, "spi") == 0) {
				em_db_sp = -1L;
			} else if(strcmp(optarg, "radij") == 0) {
				em_db_rj = -1L;
			} else if(strcmp(optarg, "esp") == 0) {
				em_db_es = -1L;
			} else if(strcmp(optarg, "ah") == 0) {
				em_db_ah = -1L;
			} else if(strcmp(optarg, "rcv") == 0) {
				em_db_rx = -1L;
			} else if(strcmp(optarg, "pfkey") == 0) {
				em_db_ky = -1L;
			} else if(strcmp(optarg, "comp") == 0) {
				em_db_gz = -1L;
			} else if(strcmp(optarg, "verbose") == 0) {
				em_db_vb = -1L;
			} else {
				usage(program_name);
			}
			em_db_nl |= 1 << (sizeof(em_db_nl) * 8 -1);
			break;
		case 'c':
			if(action) {
				fprintf(stderr, "%s: Only one of '--set', '--clear', '--all' or '--none' options permitted.\n",
					program_name);
				exit(1);
			}
			em_db_tn=em_db_nl=em_db_xf=em_db_er=em_db_sp=-1;
			em_db_rj=em_db_es=em_db_ah=em_db_rx=em_db_ky=-1;
			em_db_gz=em_db_vb=-1;

			action = 'c';
			if(strcmp(optarg, "tunnel") == 0) {
				em_db_tn = 0;
			} else if(strcmp(optarg, "tunnel-xmit") == 0
				  || strcmp(optarg, "xmit") == 0) {
				em_db_tn = ~DB_TN_XMIT;
			} else if(strcmp(optarg, "netlink") == 0) {
				em_db_nl = 0;
			} else if(strcmp(optarg, "xform") == 0) {
				em_db_xf = 0;
			} else if(strcmp(optarg, "eroute") == 0) {
				em_db_er = 0;
			} else if(strcmp(optarg, "spi") == 0) {
				em_db_sp = 0;
			} else if(strcmp(optarg, "radij") == 0) {
				em_db_rj = 0;
			} else if(strcmp(optarg, "esp") == 0) {
				em_db_es = 0;
			} else if(strcmp(optarg, "ah") == 0) {
				em_db_ah = 0;
			} else if(strcmp(optarg, "rcv") == 0) {
				em_db_rx = 0;
			} else if(strcmp(optarg, "pfkey") == 0) {
				em_db_ky = 0;
			} else if(strcmp(optarg, "comp") == 0) {
				em_db_gz = 0;
			} else if(strcmp(optarg, "verbose") == 0) {
				em_db_vb = 0;
			} else {
				usage(program_name);
			}
			em_db_nl &= ~(1 << (sizeof(em_db_nl) * 8 -1));
			break;
		case 'a':
			if(action) {
				fprintf(stderr, "%s: Only one of '--set', '--clear', '--all' or '--none' options permitted.\n",
					program_name);
				exit(1);
			}
			action = 'a';
			em_db_tn=em_db_nl=em_db_xf=em_db_er=em_db_sp=-1;
			em_db_rj=em_db_es=em_db_ah=em_db_rx=em_db_ky=-1;
			em_db_gz=-1;
			em_db_vb= 0;
			break;
		case 'n':
			if(action) {
				fprintf(stderr, "%s: Only one of '--set', '--clear', '--all' or '--none' options permitted.\n",
					program_name);
				exit(1);
			}
			action = 'n';
			em_db_tn=em_db_nl=em_db_xf=em_db_er=em_db_sp=0;
			em_db_rj=em_db_es=em_db_ah=em_db_rx=em_db_ky=0;
			em_db_gz=em_db_vb=0;
			break;
		case 'h':
		case '?':
			usage(program_name);
			exit(1);
		case 'v':
			fprintf(stdout, "klipsdebug (Linux FreeS/WAN %s) %s\n",
				ipsec_version_code(), klipsdebug_c_version);
			fputs(copyright, stdout);
			exit(0);
		case 'l':
			program_name = malloc(strlen(argv[0])
					      + 10 /* update this when changing the sprintf() */
					      + strlen(optarg));
			sprintf(program_name, "%s --label %s",
				argv[0],
				optarg);
			argcount -= 2;
			break;
		case '+': /* optionsfrom */
			optionsfrom(optarg, &argc, &argv, optind, stderr);
			/* no return on error */
			break;
		default:
			break;
		}
		previous = c;
	}

	if(argcount == 1) {
		int ret = system("cat /proc/net/ipsec_klipsdebug");
		exit(ret != -1 && WIFEXITED(ret) ? WEXITSTATUS(ret) : 1);
	}

	if(!action) {
		usage(program_name);
	}

	if((pfkey_sock = socket(PF_KEY, SOCK_RAW, PF_KEY_V2) ) < 0) {
		fprintf(stderr, "%s: Trouble opening PF_KEY family socket with error: ",
			program_name);
		switch(errno) {
		case ENOENT:
			fprintf(stderr, "device does not exist.  See FreeS/WAN installation procedure.\n");
			break;
		case EACCES:
			fprintf(stderr, "access denied.  ");
			if(getuid() == 0) {
				fprintf(stderr, "Check permissions.  Should be 600.\n");
			} else {
				fprintf(stderr, "You must be root to open this file.\n");
			}
			break;
		case EUNATCH:
			fprintf(stderr, "Netlink not enabled OR KLIPS not loaded.\n");
			break;
		case ENODEV:
			fprintf(stderr, "KLIPS not loaded or enabled.\n");
			break;
		case EBUSY:
			fprintf(stderr, "KLIPS is busy.  Most likely a serious internal error occured in a previous command.  Please report as much detail as possible to development team.\n");
			break;
		case EINVAL:
			fprintf(stderr, "Invalid argument, KLIPS not loaded or check kernel log messages for specifics.\n");
			break;
		case ENOBUFS:
			fprintf(stderr, "No kernel memory to allocate SA.\n");
			break;
		case ESOCKTNOSUPPORT:
			fprintf(stderr, "Algorithm support not available in the kernel.  Please compile in support.\n");
			break;
		case EEXIST:
			fprintf(stderr, "SA already in use.  Delete old one first.\n");
			break;
		case ENXIO:
			fprintf(stderr, "SA does not exist.  Cannot delete.\n");
			break;
		case EAFNOSUPPORT:
			fprintf(stderr, "KLIPS not loaded or enabled.\n");
			break;
		default:
			fprintf(stderr, "Unknown file open error %d.  Please report as much detail as possible to development team.\n", errno);
		}
		exit(1);
	}

	pfkey_extensions_init(extensions);

	if((error = pfkey_msg_hdr_build(&extensions[0],
					SADB_X_DEBUG,
					0,
					0,
					++pfkey_seq,
					getpid()))) {
		fprintf(stderr, "%s: Trouble building message header, error=%d.\n",
			program_name, error);
		pfkey_extensions_free(extensions);
		exit(1);
	}
	
	if((error = pfkey_x_debug_build(&extensions[SADB_X_EXT_DEBUG],
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
		fprintf(stderr, "%s: Trouble building message header, error=%d.\n",
			program_name, error);
		pfkey_extensions_free(extensions);
		exit(1);
	}
	
	if((error = pfkey_msg_build(&pfkey_msg, extensions, EXT_BITS_IN))) {
		fprintf(stderr, "%s: Trouble building pfkey message, error=%d.\n",
			program_name, error);
		pfkey_extensions_free(extensions);
		pfkey_msg_free(&pfkey_msg);
		exit(1);
	}
	
	if((error = write(pfkey_sock,
			  pfkey_msg,
			  pfkey_msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN)) !=
	   (ssize_t)(pfkey_msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN)) {
		fprintf(stderr,
			"%s: pfkey write failed, tried to write %u octets, returning %d with errno=%d.\n",
			program_name,
			(unsigned)(pfkey_msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN),
			error,
			errno);
		pfkey_extensions_free(extensions);
		pfkey_msg_free(&pfkey_msg);
		switch(errno) {
		case EACCES:
			fprintf(stderr, "access denied.  ");
			if(getuid() == 0) {
				fprintf(stderr, "Check permissions.  Should be 600.\n");
			} else {
				fprintf(stderr, "You must be root to open this file.\n");
			}
			break;
		case EUNATCH:
			fprintf(stderr, "Netlink not enabled OR KLIPS not loaded.\n");
			break;
		case EBUSY:
			fprintf(stderr, "KLIPS is busy.  Most likely a serious internal error occured in a previous command.  Please report as much detail as possible to development team.\n");
			break;
		case EINVAL:
			fprintf(stderr, "Invalid argument, check kernel log messages for specifics.\n");
			break;
		case ENODEV:
			fprintf(stderr, "KLIPS not loaded or enabled.\n");
			fprintf(stderr, "No device?!?\n");
			break;
		case ENOBUFS:
			fprintf(stderr, "No kernel memory to allocate SA.\n");
			break;
		case ESOCKTNOSUPPORT:
			fprintf(stderr, "Algorithm support not available in the kernel.  Please compile in support.\n");
			break;
		case EEXIST:
			fprintf(stderr, "SA already in use.  Delete old one first.\n");
			break;
		case ENOENT:
			fprintf(stderr, "device does not exist.  See FreeS/WAN installation procedure.\n");
			break;
		case ENXIO:
			fprintf(stderr, "SA does not exist.  Cannot delete.\n");
			break;
		case ENOSPC:
			fprintf(stderr, "no room in kernel SAref table.  Cannot process request.\n");
			break;
		case ESPIPE:
			fprintf(stderr, "kernel SAref table internal error.  Cannot process request.\n");
			break;
		default:
			fprintf(stderr, "Unknown socket write error %d.  Please report as much detail as possible to development team.\n", errno);
		}
		exit(1);
	}

	if(pfkey_msg) {
		pfkey_extensions_free(extensions);
		pfkey_msg_free(&pfkey_msg);
	}

	(void) close(pfkey_sock);  /* close the socket */
	exit(0);
}
/*
 * $Log: klipsdebug.c,v $
 * Revision 1.58  2005/08/18 14:04:39  ken
 * Patch from mt@suse.de to avoid GCC warnings with system() calls
 *
 * Revision 1.57  2005/07/08 02:56:38  paul
 * gcc4 fixes that were not commited because vault was down
 *
 * Revision 1.56  2004/07/10 19:12:35  mcr
 * 	CONFIG_IPSEC -> CONFIG_KLIPS.
 *
 * Revision 1.57  2004/02/24 18:20:31  mcr
 * 	s/CONFIG_IPSEC/CONFIG_KLIPS/
 *
 * Revision 1.56  2004/01/27 16:32:15  mcr
 * 	added debugging option for "tncfg" only.
 *
 * Revision 1.55  2004/01/18 18:04:44  mcr
 * 	changed "tunnel-xmit" debug flag to just be "xmit".
 * 	(also setting is accepted as an aka)
 *
 * Revision 1.54  2003/12/05 16:44:16  mcr
 * 	patches to avoid ipsec_netlink.h, which has been obsolete for
 * 	some time now.
 *
 * Revision 1.53  2003/09/10 00:01:27  mcr
 * 	fixes for gcc 3.3 from Matthias Bethke <Matthias.Bethke@gmx.net>
 *
 * Revision 1.52  2003/01/30 02:33:07  rgb
 *
 * Added ENOSPC for no room in SAref table and ESPIPE for SAref internal error.
 *
 * Revision 1.51  2002/10/04 03:52:46  dhr
 *
 * gcc3 now enforces C restriction on placement of labels
 *
 * Revision 1.50  2002/09/20 05:02:15  rgb
 * Cleaned up pfkey_lib_debug usage.
 *
 * Revision 1.49  2002/07/25 18:59:23  rgb
 * Fixed ia64 complaint.
 *
 * Revision 1.48  2002/07/23 02:58:58  rgb
 * Fixed "opening" speeling mistake.
 *
 * Revision 1.47  2002/04/24 07:55:32  mcr
 * 	#include patches and Makefiles for post-reorg compilation.
 *
 * Revision 1.46  2002/04/24 07:35:39  mcr
 * Moved from ./klips/utils/klipsdebug.c,v
 *
 * Revision 1.45  2002/03/08 21:44:04  rgb
 * Update for all GNU-compliant --version strings.
 *
 * Revision 1.44  2001/11/23 07:23:14  mcr
 * 	pulled up klips2 Makefile and pf_key code.
 *
 * Revision 1.43  2001/11/22 05:44:01  henry
 * new version stuff
 *
 * Revision 1.42.2.1  2001/10/13 18:22:21  mcr
 * 	usage string was missing "netlink" and "pf_key" debug options.
 *
 * Revision 1.42  2001/09/07 22:24:07  rgb
 * Added EAFNOSUPPORT socket open error code in case KLIPS is not loaded.
 *
 * Revision 1.41  2001/06/14 19:35:14  rgb
 * Update copyright date.
 *
 * Revision 1.40  2001/05/21 02:02:54  rgb
 * Eliminate 1-letter options.
 *
 * Revision 1.39  2001/05/16 05:07:19  rgb
 * Fixed --label option in KLIPS manual utils to add the label to the
 * command name rather than replace it in error text.
 * Fix 'print table' non-option in KLIPS manual utils to deal with --label
 * and --debug options.
 *
 * Revision 1.38  2000/10/11 03:56:54  rgb
 * Initialise verbose field to zero on --all.
 *
 * Revision 1.37  2000/10/11 03:48:44  henry
 * add a couple of overlooked parameters to a call
 *
 * Revision 1.36  2000/10/10 20:10:19  rgb
 * Added support for debug_ipcomp and debug_verbose to klipsdebug.
 *
 * Revision 1.35  2000/09/08 19:16:51  rgb
 * Change references from DEBUG_IPSEC to CONFIG_IPSEC_DEBUG.
 * Removed all references to CONFIG_IPSEC_PFKEYv2.
 *
 * Revision 1.34  2000/08/27 01:48:30  rgb
 * Update copyright.
 *
 * Revision 1.33  2000/07/26 03:41:46  rgb
 * Changed all printf's to fprintf's.  Fixed tncfg's usage to stderr.
 *
 * Revision 1.32  2000/06/28 05:53:09  rgb
 * Mention that netlink is obsolete.
 *
 * Revision 1.31  2000/06/21 16:51:27  rgb
 * Added no additional argument option to usage text.
 *
 * Revision 1.30  2000/03/16 06:40:49  rgb
 * Hardcode PF_KEYv2 support.
 *
 * Revision 1.29  2000/01/21 06:23:34  rgb
 * Added pfkeyv2 support to completely avoid netlink.
 * Added --debug switch to command line.
 * Changed name of debug switch bitfield pointer to avoid name
 * conflict with command line debug switch.
 *
 * Revision 1.28  2000/01/13 08:10:38  rgb
 * Added finer-grained 'tunnel-xmit' switch for debugging.
 *
 * Revision 1.27  1999/12/07 18:28:34  rgb
 * Added headers to silence fussy compilers.
 * Converted local functions to static to limit scope.
 * Removed unused cruft.
 * Changed types to unsigned to quiet compiler.
 * Changed printf type from Lx to x to quiet compiler.
 *
 * Revision 1.26  1999/11/25 09:07:59  rgb
 * Comment out unused variable.
 *
 * Revision 1.25  1999/11/23 23:06:26  rgb
 * Sort out pfkey and freeswan headers, putting them in a library path.
 *
 * Revision 1.24  1999/06/10 16:11:15  rgb
 * Add autoconf to use pfkey.
 * Add argc==1 to use /proc/net/ipsec_klipsdebug output.
 * Add error return code description for ECONNREFUSED.
 *
 * Revision 1.23  1999/05/05 22:02:34  rgb
 * Add a quick and dirty port to 2.2 kernels by Marc Boucher <marc@mbsi.ca>.
 *
 * Revision 1.22  1999/04/29 15:26:15  rgb
 * Add pfkey debugging support.
 *
 * Revision 1.21  1999/04/15 15:37:27  rgb
 * Forward check changes from POST1_00 branch.
 *
 * Revision 1.15.2.2  1999/04/13 20:55:45  rgb
 * Add experimental 'getdebug'.
 *
 * Revision 1.15.2.1  1999/03/30 17:01:37  rgb
 * Make main() return type explicit.
 *
 * Revision 1.20  1999/04/12 01:27:10  henry
 * Eric Young waived his advertising clause
 *
 * Revision 1.19  1999/04/11 01:24:53  henry
 * tidy up --version, add copyright notice
 *
 * Revision 1.18  1999/04/11 00:12:08  henry
 * GPL boilerplate
 *
 * Revision 1.17  1999/04/06 04:54:38  rgb
 * Fix/Add RCSID Id: and Log: bits to make PHMDs happy.  This includes
 * patch shell fixes.
 *
 * Revision 1.16  1999/03/17 15:40:54  rgb
 * Make explicit main() return type of int.
 *
 * Revision 1.15  1999/01/22 06:35:19  rgb
 * 64-bit clean-up.
 * Added algorithm switch code.
 *
 * Revision 1.14  1998/11/12 21:08:04  rgb
 * Add --label option to identify caller from scripts.
 *
 * Revision 1.13  1998/10/31 06:35:16  rgb
 * Fixed up comments in #endif directives.
 *
 * Revision 1.12  1998/10/22 06:36:22  rgb
 * Added freeswan.h inclusion.
 *
 * Revision 1.11  1998/10/09 18:47:30  rgb
 * Add 'optionfrom' to get more options from a named file.
 *
 * Revision 1.10  1998/10/09 04:35:31  rgb
 * Changed help output from stderr to stdout.
 * Changed error messages from stdout to stderr.
 * Deleted old commented out cruft.
 *
 * Revision 1.9  1998/08/28 03:13:05  rgb
 * Tidy up old cruft.
 *
 * Revision 1.8  1998/08/05 22:24:45  rgb
 * Change includes to accomodate RH5.x
 *
 * Revision 1.7  1998/07/29 21:36:37  rgb
 * Converted to long option names.
 *
 * Revision 1.6  1998/07/14 18:23:11  rgb
 * Remove unused skbuff header.
 *
 * Revision 1.5  1998/07/09 18:14:10  rgb
 * Added error checking to IP's and keys.
 * Made most error messages more specific rather than spamming usage text.
 * Added more descriptive kernel error return codes and messages.
 * Converted all spi translations to unsigned.
 * Removed all invocations of perror.
 *
 * Revision 1.4  1998/05/27 18:48:21  rgb
 * Adding --help and --version directives.
 *
 * Revision 1.3  1998/05/18 21:19:09  rgb
 * Added options for finer control of debugging switches.
 *
 * Revision 1.2  1998/05/12 02:26:27  rgb
 * Fixed compile errors with IPSEC_DEBUG shut off in the kernel config.
 *
 * Revision 1.1  1998/04/23 21:07:34  rgb
 * Added a userspace utility to change klips kernelspace debug switches.
 *
 * Revision 1.1.1.1  1998/04/08 05:35:09  henry
 * RGB's ipsec-0.8pre2.tar.gz ipsec-0.8
 *
 * Revision 0.3  1996/11/20 14:51:32  ji
 * Fixed problems with #include paths.
 * Changed (incorrect) references to ipsp into ipsec.
 *
 * Revision 0.2  1996/11/08 15:46:29  ji
 * First limited release.
 *
 *
 */
