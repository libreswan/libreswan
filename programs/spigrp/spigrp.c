/*
 * SA grouping
 * Copyright (C) 1996  John Ioannidis.
 * Copyright (C) 1997, 1998, 1999, 2000, 2001  Richard Guy Briggs.
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

char spigrp_c_version[] = "RCSID $Id: spigrp.c,v 1.50.2.1 2005/08/18 14:04:51 ken Exp $";


#include <sys/types.h>
#include <linux/types.h> /* new */
#include <string.h>
#include <errno.h>
#include <sys/stat.h> /* open() */
#include <fcntl.h> /* open() */
#include <sys/wait.h>
#include <stdlib.h> /* system(), strtoul() */

#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>
/* #include <linux/ip.h> */

#include <unistd.h>
#include <stdio.h>
#include <netdb.h>
#include <openswan.h>
#if 0
#include <linux/autoconf.h>	/* CONFIG_IPSEC_PFKEYv2 */
#endif

#include <signal.h>
#include <pfkeyv2.h>
#include <pfkey.h>

#include "openswan/radij.h"
#include "openswan/ipsec_encap.h"
#include "openswan/ipsec_ah.h"


char *program_name;

int pfkey_sock;
fd_set pfkey_socks;
uint32_t pfkey_seq = 0;
 
struct said_af {
 	int af;
 	ip_said said;
}; /* to store the given saids and their address families in an array */
 /* XXX: Note that we do *not* check if the address families of all SAID?s are the same.
  *      This can make it possible to group SAs for IPv4 addresses with SAs for
  *      IPv6 addresses (perhaps some kind of IPv4-over-secIPv6 or vice versa).
  *      Do not know, if this is a bug or feature */

static void
usage(char *s)
{
	fprintf(stdout, "usage: Note: position of options and arguments is important!\n");
	fprintf(stdout, "usage: %s [ --debug ] [ --label <label> ] af1 dst1 spi1 proto1 [ af2 dst2 spi2 proto2 [ af3 dst3 spi3 proto3 [ af4 dst4 spi4 proto4 ] ] ]\n", s);
	fprintf(stdout, "usage: %s [ --debug ] [ --label <label> ] --said <SA1> [ <SA2> [ <SA3> [ <SA4> ] ] ]\n", s);
	fprintf(stdout, "usage: %s --help\n", s);
	fprintf(stdout, "usage: %s --version\n", s);
	fprintf(stdout, "usage: %s\n", s);
	fprintf(stdout, "        [ --debug ] is optional to any %s command.\n", s);
	fprintf(stdout, "        [ --label <label> ] is optional to any %s command.\n", s);
}

	
int
main(int argc, char **argv)
{
	int i, nspis;
	char *endptr;
	int said_opt = 0;

	const char* error_s = NULL;
	char ipaddr_txt[ADDRTOT_BUF];
	int debug = 0;
	int j;
	struct said_af said_af_array[4];

	int error = 0;

	struct sadb_ext *extensions[SADB_EXT_MAX + 1];
	struct sadb_msg *pfkey_msg;
#if 0
	ip_address pfkey_address_s_ska;
#endif
	
	program_name = argv[0];
	for(i = 0; i < 4; i++) {
		memset(&said_af_array[i], 0, sizeof(struct said_af));
	}

        if(argc > 1 && strcmp(argv[1], "--debug") == 0) {
		debug = 1;
		if(debug) {
			fprintf(stdout, "\"--debug\" option requested.\n");
		}
		argv += 1;
		argc -= 1;
		pfkey_lib_debug = PF_KEY_DEBUG_PARSE_MAX;
        }

	if(debug) {
		fprintf(stdout, "argc=%d (%d incl. --debug option).\n",
			argc,
			argc + 1);
	}

        if(argc > 1 && strcmp(argv[1], "--label") == 0) {
		if(argc > 2) {
			program_name = malloc(strlen(argv[0])
					      + 10 /* update this when changing the sprintf() */
					      + strlen(argv[2]));
			sprintf(program_name, "%s --label %s",
				argv[0],
				argv[2]);
			if(debug) {
				fprintf(stdout, "using \"%s\" as a label.\n", program_name);
			}
			argv += 2;
			argc -= 2;
		} else {
			fprintf(stderr, "%s: --label option requires an argument.\n",
				program_name);
			exit(1);
		}
        }
  
	if(debug) {
		fprintf(stdout, "...After check for --label option.\n");
	}

	if(argc == 1) {
		int ret = system("cat /proc/net/ipsec_spigrp");
		exit(ret != -1 && WIFEXITED(ret) ? WEXITSTATUS(ret) : 1);
	}

	if(debug) {
		fprintf(stdout, "...After check for no option to print /proc/net/ipsec_spigrp.\n");
	}

        if(strcmp(argv[1], "--help") == 0) {
		if(debug) {
			fprintf(stdout, "\"--help\" option requested.\n");
		}
                usage(program_name);
                exit(1);
        }

	if(debug) {
		fprintf(stdout, "...After check for --help option.\n");
	}

        if(strcmp(argv[1], "--version") == 0) {
		if(debug) {
			fprintf(stdout, "\"--version\" option requested.\n");
		}
                fprintf(stderr, "%s, %s\n", program_name, spigrp_c_version);
                exit(1);
        }

	if(debug) {
		fprintf(stdout, "...After check for --version option.\n");
	}

        if(strcmp(argv[1], "--said") == 0) {
		if(debug) {
			fprintf(stdout, "processing %d args with --said flag.\n", argc);
		}
		said_opt = 1;
        }
	
	if(debug) {
		fprintf(stdout, "...After check for --said option.\n");
	}

	if(said_opt) {
		if (argc < 3 /*|| argc > 5*/) {
			fprintf(stderr, "expecting 3 or more args with --said, got %d.\n", argc);
			usage(program_name);
                	exit(1);
		}
		nspis = argc - 2;
	} else {
		if ((argc < 5) || (argc > 17) || ((argc % 4) != 1)) {
			fprintf(stderr, "expecting 5 or more args without --said, got %d.\n", argc);
			usage(program_name);
                	exit(1);
		}
		nspis = argc / 4;
	}

	if(debug) {
		fprintf(stdout, "processing %d nspis.\n", nspis);
	}

	for(i = 0; i < nspis; i++) {
		if(debug) {
			fprintf(stdout, "processing spi #%d.\n", i);
		}

		if(said_opt) {
			error_s = ttosa((const char *)argv[i+2], 0, (ip_said*)&(said_af_array[i].said));
			if(error_s != NULL) {
				fprintf(stderr, "%s: Error, %s converting --sa argument:%s\n",
					program_name, error_s, argv[i+2]);
				exit (1);
			}
			said_af_array[i].af = addrtypeof(&(said_af_array[i].said.dst));
			if(debug) {
				addrtot(&said_af_array[i].said.dst, 0, ipaddr_txt, sizeof(ipaddr_txt));
				fprintf(stdout, "said[%d].dst=%s.\n", i, ipaddr_txt);
			}
		} else {
			if(!strcmp(argv[i*4+4], "ah")) {
				said_af_array[i].said.proto = SA_AH;
			}
			if(!strcmp(argv[i*4+4], "esp")) {
				said_af_array[i].said.proto = SA_ESP;
			}
			if(!strcmp(argv[i*4+4], "tun")) {
				said_af_array[i].said.proto = SA_IPIP;
			}
			if(!strcmp(argv[i*4+4], "comp")) {
				said_af_array[i].said.proto = SA_COMP;
			}
			if(said_af_array[i].said.proto == 0) {
				fprintf(stderr, "%s: Badly formed proto: %s\n",
					program_name, argv[i*4+4]);
				exit(1);
			}
			said_af_array[i].said.spi = htonl(strtoul(argv[i*4+3], &endptr, 0));
			if(!(endptr == argv[i*4+3] + strlen(argv[i*4+3]))) {
				fprintf(stderr, "%s: Badly formed spi: %s\n",
					program_name, argv[i*4+3]);
				exit(1);
			}
			if(!strcmp(argv[i*4+1], "inet")) {
				said_af_array[i].af = AF_INET;
			}
			if(!strcmp(argv[i*4+1], "inet6")) {
				said_af_array[i].af = AF_INET6;
			}
			if((said_af_array[i].af != AF_INET) && (said_af_array[i].af != AF_INET6)) {
				fprintf(stderr, "%s: Address family %s not supported\n",
					program_name, argv[i*4+1]);
				exit(1);
			}
			error_s = ttoaddr(argv[i*4+2], 0, said_af_array[i].af, &(said_af_array[i].said.dst));
			if(error_s != NULL) {
				fprintf(stderr, "%s: Error, %s converting %dth address argument:%s\n",
					program_name, error_s, i, argv[i*4+2]);
				exit (1);
			}
		}
		if(debug) {
			fprintf(stdout, "SA %d contains: ", i+1);
			fprintf(stdout, "\n");
			fprintf(stdout, "proto = %d\n", said_af_array[i].said.proto);
			fprintf(stdout, "spi = %08x\n", said_af_array[i].said.spi);
			addrtot(&said_af_array[i].said.dst, 0, ipaddr_txt, sizeof(ipaddr_txt));
			fprintf(stdout, "edst = %s\n", ipaddr_txt);
		}
	}	

	if(debug) {
		fprintf(stdout, "Opening pfkey socket.\n");
	}

	if((pfkey_sock = socket(PF_KEY, SOCK_RAW, PF_KEY_V2) ) < 0) {
		fprintf(stderr, "%s: Trouble opening PF_KEY family socket with error: ",
			program_name);
		switch(errno) {
		case ENOENT:
			fprintf(stderr, "ipsec# device does not exist.  See Openswan installation procedure.\n");
			break;
		case EACCES:
			fprintf(stderr, "access denied.  ");
			if(getuid() == 0) {
				fprintf(stderr, "Check permissions, they should be set to 600.\n");
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

	for(i = 0; i < (((nspis - 1) < 2) ? 1 : (nspis - 1)); i++) {
		if(debug) {
			fprintf(stdout, "processing %dth pfkey message.\n", i);
		}

		pfkey_extensions_init(extensions);
		for(j = 0; j < ((nspis == 1) ? 1 : 2); j++) {
			if(debug) {
				fprintf(stdout, "processing %dth said of %dth pfkey message.\n", j, i);
			}

			/* Build an SADB_X_GRPSA message to send down. */
			/* It needs <base, SA, SA2, address(D,D2) > minimum. */
			if(!j) {
				if((error = pfkey_msg_hdr_build(&extensions[0],
								SADB_X_GRPSA,
								proto2satype(said_af_array[i].said.proto),
								0,
								++pfkey_seq,
								getpid()))) {
					fprintf(stderr, "%s: Trouble building message header, error=%d.\n",
						program_name, error);
					pfkey_extensions_free(extensions);
					exit(1);
				}
			} else {
				if(debug) {
					fprintf(stdout, "setting x_satype proto=%d satype=%d\n",
						said_af_array[i+j].said.proto,
						proto2satype(said_af_array[i+j].said.proto)
						);
				}

				if((error = pfkey_x_satype_build(&extensions[SADB_X_EXT_SATYPE2],
								 proto2satype(said_af_array[i+j].said.proto)
					))) {
					fprintf(stderr, "%s: Trouble building message header, error=%d.\n",
						program_name, error);
					pfkey_extensions_free(extensions);
					exit(1);
				}
			}

			if((error = pfkey_sa_build(&extensions[!j ? SADB_EXT_SA : SADB_X_EXT_SA2],
						   !j ? SADB_EXT_SA : SADB_X_EXT_SA2,
						   said_af_array[i+j].said.spi, /* in network order */
						   0,
						   0,
						   0,
						   0,
						   0))) {
				fprintf(stderr, "%s: Trouble building sa extension, error=%d.\n",
					program_name, error);
				pfkey_extensions_free(extensions);
				exit(1);
			}
			
#if 0
			if(!j) {
				anyaddr(said_af_array[i].af, &pfkey_address_s_ska); /* Is the address family correct ?? */
				if((error = pfkey_address_build(&extensions[SADB_EXT_ADDRESS_SRC],
								SADB_EXT_ADDRESS_SRC,
								0,
								0,
								sockaddrof(&pfkey_address_s_ska)))) {
					addrtot(&pfkey_address_s_ska, 0, ipaddr_txt, sizeof(ipaddr_txt));
					fprintf(stderr, "%s: Trouble building address_s extension (%s), error=%d.\n",
						program_name, ipaddr_txt, error);
					pfkey_extensions_free(extensions);
					exit(1);
				}
			}
#endif			
			if((error = pfkey_address_build(&extensions[!j ? SADB_EXT_ADDRESS_DST : SADB_X_EXT_ADDRESS_DST2],
							!j ? SADB_EXT_ADDRESS_DST : SADB_X_EXT_ADDRESS_DST2,
							0,
							0,
							sockaddrof(&said_af_array[i+j].said.dst)))) {
				addrtot(&said_af_array[i+j].said.dst,
					0, ipaddr_txt, sizeof(ipaddr_txt));
				fprintf(stderr, "%s: Trouble building address_d extension (%s), error=%d.\n",
					program_name, ipaddr_txt, error);
				pfkey_extensions_free(extensions);
				exit(1);
			}
			
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
			fprintf(stderr, "%s: pfkey write failed, returning %d with errno=%d.\n",
				program_name, error, errno);
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
	}

	(void) close(pfkey_sock);  /* close the socket */
	exit(0);
}
/*
 * $Log: spigrp.c,v $
 * Revision 1.50.2.1  2005/08/18 14:04:51  ken
 * Patch from mt@suse.de to avoid GCC warnings with system() calls
 *
 * Revision 1.50  2005/07/08 02:56:38  paul
 * gcc4 fixes that were not commited because vault was down
 *
 * Revision 1.49  2004/04/18 23:16:02  ken
 * Change FreeS/WAN -> Openswan
 *
 * Revision 1.48  2004/04/06 10:21:29  mcr
 * 	freeswan->openswan changes
 *
 * Revision 1.47  2003/12/05 16:44:23  mcr
 * 	patches to avoid ipsec_netlink.h, which has been obsolete for
 * 	some time now.
 *
 * Revision 1.46  2003/09/10 00:01:42  mcr
 * 	fixes for gcc 3.3 from Matthias Bethke <Matthias.Bethke@gmx.net>
 *
 * Revision 1.45  2003/01/30 02:33:07  rgb
 *
 * Added ENOSPC for no room in SAref table and ESPIPE for SAref internal error.
 *
 * Revision 1.44  2002/09/20 05:02:15  rgb
 * Cleaned up pfkey_lib_debug usage.
 *
 * Revision 1.43  2002/04/24 07:55:32  mcr
 * 	#include patches and Makefiles for post-reorg compilation.
 *
 * Revision 1.42  2002/04/24 07:35:41  mcr
 * Moved from ./klips/utils/spigrp.c,v
 *
 * Revision 1.41  2002/03/08 21:44:05  rgb
 * Update for all GNU-compliant --version strings.
 *
 * Revision 1.40  2001/10/02 17:17:17  rgb
 * Check error return for all "tto*" calls and report errors.  This, in
 * conjuction with the fix to "tto*" will detect AF not set.
 *
 * Revision 1.39  2001/09/07 22:24:42  rgb
 * Added EAFNOSUPPORT socket open error code in case KLIPS is not loaded.
 *
 * Revision 1.38  2001/06/14 19:35:15  rgb
 * Update copyright date.
 *
 * Revision 1.37  2001/05/16 05:07:20  rgb
 * Fixed --label option in KLIPS manual utils to add the label to the
 * command name rather than replace it in error text.
 * Fix 'print table' non-option in KLIPS manual utils to deal with --label
 * and --debug options.
 *
 * Revision 1.36  2001/01/23 20:24:12  rgb
 * Fix comment to reflect reality that src is not needed for grouping.
 *
 * Revision 1.35  2000/09/17 18:56:48  rgb
 * Added IPCOMP support.
 *
 * Revision 1.34  2000/09/16 04:56:32  rgb
 * Added Svenning's ipcomp patch.
 *
 * Revision 1.33  2000/09/12 22:36:45  rgb
 * Gerhard's IPv6 support.
 *
 * Revision 1.32  2000/09/08 19:17:31  rgb
 * Removed all references to CONFIG_IPSEC_PFKEYv2.
 *
 * Revision 1.31  2000/08/27 01:46:52  rgb
 * Update copyright dates and remove no longer used resolve_ip().
 *
 * Revision 1.30  2000/06/21 16:51:27  rgb
 * Added no additional argument option to usage text.
 *
 * Revision 1.29  2000/06/20 22:37:24  rgb
 * Fixed bug in no-arg invocation that caused a core-dump when it should
 * have printed out /proc/net/ipsec_spigrp.
 * Added debug statements.
 *
 * Revision 1.28  2000/03/16 06:40:50  rgb
 * Hardcode PF_KEYv2 support.
 *
 * Revision 1.27  2000/01/25 14:38:52  rgb
 * Fixed variable declaration bug so it will compile with pfkey off.
 *
 * Revision 1.26  2000/01/22 23:22:47  rgb
 * Use new function proto2satype().
 *
 * Revision 1.25  2000/01/21 09:42:32  rgb
 * Replace resolve_ip() with atoaddr() from freeswanlib.
 *
 * Revision 1.24  2000/01/21 06:25:51  rgb
 * Added pfkeyv2 support to completely avoid netlink.
 * Added --debug switch to command line.
 * Added --said processing to command line.
 *
 * Revision 1.23  1999/12/07 18:30:26  rgb
 * Added headers to silence fussy compilers.
 * Converted local functions to static to limit scope.
 * Removed unused cruft.
 * Converted main() to prototyped declaration.
 *
 * Revision 1.22  1999/11/25 09:09:43  rgb
 * Comment out unused variables.
 * Clarified assignment in conditional with parens.
 *
 * Revision 1.21  1999/11/23 23:06:27  rgb
 * Sort out pfkey and freeswan headers, putting them in a library path.
 *
 * Revision 1.20  1999/10/16 00:27:14  rgb
 * Removed cruft.
 *
 * Revision 1.19  1999/04/15 15:37:28  rgb
 * Forward check changes from POST1_00 branch.
 *
 * Revision 1.15.2.2  1999/04/13 20:58:10  rgb
 * Add argc==1 --> /proc/net/ipsec_*.
 *
 * Revision 1.15.2.1  1999/03/30 17:01:36  rgb
 * Make main() return type explicit.
 *
 * Revision 1.18  1999/04/11 00:12:09  henry
 * GPL boilerplate
 *
 * Revision 1.17  1999/04/06 04:54:39  rgb
 * Fix/Add RCSID Id: and Log: bits to make PHMDs happy.  This includes
 * patch shell fixes.
 *
 * Revision 1.16  1999/03/17 15:40:54  rgb
 * Make explicit main() return type of int.
 *
 * Revision 1.15  1999/01/28 23:20:49  rgb
 * Replace hard-coded numbers in macros and code with meaningful values
 * automatically generated from sizeof() and offsetof() to further the
 * goal of platform independance.
 *
 * Revision 1.14  1999/01/22 06:36:46  rgb
 * 64-bit clean-up.
 *
 * Revision 1.13  1998/11/12 21:08:04  rgb
 * Add --label option to identify caller from scripts.
 *
 * Revision 1.12  1998/10/26 01:28:38  henry
 * use SA_* protocol names, not IPPROTO_*, to avoid compile problems
 *
 * Revision 1.11  1998/10/25 02:47:09  rgb
 * Fix bug in size of stucture passed in from user space for grpspi command.
 * Added debugging code to find spigrp stucture size mismatch bug.
 * Convert switch to loop for more efficient coding and redundant code elimination.
 *
 * Revision 1.10  1998/10/19 18:58:56  rgb
 * Added inclusion of freeswan.h.
 * a_id structure implemented and used: now includes protocol.
 *
 * Revision 1.9  1998/10/09 04:36:32  rgb
 * Changed help output from stderr to stdout.
 * Avoid use of argv[0] after first use.
 *
 * Revision 1.8  1998/08/05 22:24:45  rgb
 * Change includes to accomodate RH5.x
 *
 * Revision 1.7  1998/07/29 21:43:17  rgb
 * Convert to 0x-prefixed spis.
 * Support dns lookups for hostnames.
 *
 * Revision 1.6  1998/07/14 18:24:05  rgb
 * Remove unused skbuff header.
 *
 * Revision 1.5  1998/07/09 18:14:11  rgb
 * Added error checking to IP's and keys.
 * Made most error messages more specific rather than spamming usage text.
 * Added more descriptive kernel error return codes and messages.
 * Converted all spi translations to unsigned.
 * Removed all invocations of perror.
 *
 * Revision 1.4  1998/06/30 18:04:32  rgb
 * Fix compiler warning: couldn't find 'struct option' prototype.
 *
 * Revision 1.3  1998/05/27 18:48:20  rgb
 * Adding --help and --version directives.
 *
 * Revision 1.2  1998/05/18 21:14:16  rgb
 * Modifications to be able to ungroup spi's.
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
