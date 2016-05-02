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

#include <sys/types.h>
#include <linux/types.h> /* new */
#include <string.h>
#include <errno.h>
#include <sys/stat.h>   /* open() */
#include <fcntl.h>      /* open() */
#include <sys/wait.h>
#include <stdlib.h>     /* system(), strtoul() */

#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>
/* #include <linux/ip.h> */

#include <unistd.h>
#include <stdio.h>
#include <netdb.h>
#include <libreswan.h>
#if 0
#include <linux/autoconf.h>     /* CONFIG_IPSEC_PFKEYv2 */
#endif

#include "constants.h"
#include "lswlog.h"

#include <signal.h>
#include <libreswan/pfkeyv2.h>
#include <libreswan/pfkey.h>
#include "libreswan/pfkey_debug.h"
#include "pfkey_help.h"

#include "libreswan/radij.h"
#include "libreswan/ipsec_encap.h"
#include "libreswan/ipsec_ah.h"

#include "lsw_select.h"

char *progname;

int pfkey_sock;
uint32_t pfkey_seq = 0;

/* to store the given saids and their address families in an array */
/* XXX: Note that we do *not* check if the address families of all SAID?s are the same.
 *      This can make it possible to group SAs for IPv4 addresses with SAs for
 *      IPv6 addresses (perhaps some kind of IPv4-over-secIPv6 or vice versa).
 *      Do not know, if this is a bug or feature
 */
struct said_af {
	int af;
	ip_said said;
};

static void usage(char *s)
{
	fprintf(stdout,
		"usage: Note: position of options and arguments is important!\n");
	fprintf(stdout,
		"usage: %s [ --debug ] [ --label <label> ] af1 dst1 spi1 proto1 [ af2 dst2 spi2 proto2 [ af3 dst3 spi3 proto3 [ af4 dst4 spi4 proto4 ] ] ]\n",
		s);
	fprintf(stdout,
		"usage: %s [ --debug ] [ --label <label> ] --said <SA1> [ <SA2> [ <SA3> [ <SA4> ] ] ]\n",
		s);
	fprintf(stdout, "usage: %s --help\n", s);
	fprintf(stdout, "usage: %s --version\n", s);
	fprintf(stdout, "usage: %s\n", s);
	fprintf(stdout, "        [ --debug ] is optional to any %s command.\n",
		s);
	fprintf(stdout,
		"        [ --label <label> ] is optional to any %s command.\n",
		s);
}

int debug = 0;

int main(int argc, char **argv)
{
	int i, nspis;
	int said_opt = 0;

	const char *error_s = NULL;
	int j;
	struct said_af said_af_array[4];

	int error = 0;
	struct stat sts;

	struct sadb_ext *extensions[K_SADB_EXT_MAX + 1];
	struct sadb_msg *pfkey_msg;

#if 0
	ip_address pfkey_address_s_ska;
#endif

	progname = argv[0];
	zero(&said_af_array);	/* OK: no pointer fields */

	if (argc > 1 && streq(argv[1], "--debug")) {
		debug = 1;
		if (debug)
			fprintf(stdout, "\"--debug\" option requested.\n");
		argv += 1;
		argc -= 1;
		pfkey_lib_debug = PF_KEY_DEBUG_PARSE_MAX;
	}

	if (debug) {
		fprintf(stdout, "argc=%d (%d incl. --debug option).\n",
			argc,
			argc + 1);
	}

	if (argc > 1 && streq(argv[1], "--label")) {
		if (argc > 2) {
			static const char combine_fmt[] = "%s --label %s";
			size_t room = strlen(argv[0]) +
					  sizeof(combine_fmt) +
					  strlen(optarg);

			progname = malloc(room);
			snprintf(progname, room, combine_fmt,
				argv[0],
				argv[2]);
			if (debug)
				fprintf(stdout, "using \"%s\" as a label.\n",
					progname);
			argv += 2;
			argc -= 2;
		} else {
			fprintf(stderr,
				"%s: --label option requires an argument.\n",
				progname);
			exit(1);
		}
	}

	if (debug)
		fprintf(stdout, "...After check for --label option.\n");

	if (stat("/proc/net/pfkey", &sts) == 0) {
		fprintf(stderr,
			"%s: NETKEY does not use the ipsec spigrp command. Use 'ip xfrm' instead.\n",
			progname);
		exit(1);
	}

	if (argc == 1) {
		int ret = 1;
		if ((stat("/proc/net/ipsec_spigrp", &sts)) != 0) {
			fprintf(stderr,
				"%s: No spigrp - no IPsec support in kernel (are the modules loaded?)\n",
				progname);
		} else {
			ret = system("cat /proc/net/ipsec_spigrp");
			ret = ret != -1 &&
			      WIFEXITED(ret) ? WEXITSTATUS(ret) : 1;
		}
		exit(ret);
	}

	if (debug)
		fprintf(stdout,
			"...After check for no option to print /proc/net/ipsec_spigrp.\n");


	if (streq(argv[1], "--help")) {
		if (debug)
			fprintf(stdout, "\"--help\" option requested.\n");
		usage(progname);
		exit(1);
	}

	if (debug)
		fprintf(stdout, "...After check for --help option.\n");

	if (streq(argv[1], "--version")) {
		if (debug)
			fprintf(stdout, "\"--version\" option requested.\n");
		fprintf(stderr, "%s, %s\n", progname, ipsec_version_code());
		exit(1);
	}

	if (debug)
		fprintf(stdout, "...After check for --version option.\n");

	if (streq(argv[1], "--said")) {
		if (debug) {
			fprintf(stdout,
				"processing %d args with --said flag.\n",
				argc);
		}
		said_opt = 1;
	}

	if (debug)
		fprintf(stdout, "...After check for --said option.\n");

	if (said_opt) {
		if (argc < 3 /*|| argc > 5*/) {
			fprintf(stderr,
				"expecting 3 or more args with --said, got %d.\n",
				argc);
			usage(progname);
			exit(1);
		}
		nspis = argc - 2;
	} else {
		if ((argc < 5) || (argc > 17) || ((argc % 4) != 1)) {
			fprintf(stderr,
				"expecting 5 or more args without --said, got %d.\n",
				argc);
			usage(progname);
			exit(1);
		}
		nspis = argc / 4;
	}

	if (debug)
		fprintf(stdout, "processing %d nspis.\n", nspis);

	for (i = 0; i < nspis; i++) {
		if (debug)
			fprintf(stdout, "processing spi #%d.\n", i);

		if (said_opt) {
			error_s = ttosa((const char *)argv[i + 2], 0,
					(ip_said*)&(said_af_array[i].said));
			if (error_s != NULL) {
				fprintf(stderr,
					"%s: Error, %s converting --sa argument:%s\n",
					progname, error_s, argv[i + 2]);
				exit(1);
			}
			said_af_array[i].af =
				addrtypeof(&(said_af_array[i].said.dst));
			if (debug) {
				ipstr_buf b;

				fprintf(stdout, "said[%d].dst=%s.\n", i,
					ipstr(&said_af_array[i].said.dst, &b));
			}
		} else {
			/*
			 * decode four args from i * 4 + 1
			 * +0: address family
			 * +1: IP address
			 * +2: SPI
			 * +3: proto
			 */
			char **p = &argv[i * 4 + 1];

			/* address family */
			if (streq(p[0], "inet")) {
				said_af_array[i].af = AF_INET;
			} else if (streq(p[0], "inet6")) {
				said_af_array[i].af = AF_INET6;
			} else {
				fprintf(stderr,
					"%s: Address family %s not supported\n",
					progname, p[0]);
				exit(1);
			}

			/* IP address */
			{
				err_t error_s = ttoaddr(p[1], 0,
						  said_af_array[i].af,
						  &(said_af_array[i].said.dst));

				if (error_s != NULL) {
					fprintf(stderr,
						"%s: Error, %s converting %dth address argument:%s\n",
						progname, error_s, i, p[1]);
					exit(1);
				}
			}

			/* SPI */
			{
				unsigned long spi;
				err_t ugh = ttoulb(p[2], 0, 0, 0xFFFFFFFFul, &spi);

				if (ugh != NULL) {
					fprintf(stderr, "%s: Badly formed spi: %s \"%s\"\n",
						progname, ugh, p[2]);
					exit(1);
				}
				said_af_array[i].said.spi = htonl(spi);
			}

			/* proto */
			if (streq(p[3], "ah")) {
				said_af_array[i].said.proto = SA_AH;
			} else if (streq(p[3], "esp")) {
				said_af_array[i].said.proto = SA_ESP;
			} else if (streq(p[3], "tun")) {
				said_af_array[i].said.proto = SA_IPIP;
			} else if (streq(p[3], "comp")) {
				said_af_array[i].said.proto = SA_COMP;
			} else {
				fprintf(stderr, "%s: Badly formed proto: %s\n",
					progname, p[3]);
				exit(1);
			}
		}
		if (debug) {
			ipstr_buf b;

			fprintf(stdout, "SA %d contains: ", i + 1);
			fprintf(stdout, "\n");
			fprintf(stdout, "proto = %d\n",
				said_af_array[i].said.proto);
			fprintf(stdout, "spi = %08x\n",
				said_af_array[i].said.spi);
			fprintf(stdout, "edst = %s\n", ipstr(&said_af_array[i].said.dst, &b));
		}
	}

	if (debug)
		fprintf(stdout, "Opening pfkey socket.\n");

	pfkey_sock = pfkey_open_sock_with_error();
	if (pfkey_sock < 0)
		exit(1);

	for (i = 0; i < (((nspis - 1) < 2) ? 1 : (nspis - 1)); i++) {
		if (debug)
			fprintf(stdout, "processing %dth pfkey message.\n", i);


		pfkey_extensions_init(extensions);
		for (j = 0; j < ((nspis == 1) ? 1 : 2); j++) {
			if (debug) {
				fprintf(stdout,
					"processing %dth said of %dth pfkey message.\n", j,
					i);
			}

			/* Build an SADB_X_GRPSA message to send down. */
			/* It needs <base, SA, SA2, address(D,D2) > minimum. */
			if (j == 0) {
				if ((error = pfkey_msg_hdr_build(&extensions[0],
								 K_SADB_X_GRPSA,
								 proto2satype(
									 said_af_array
									 [i].
									 said.
									 proto),
								 0,
								 ++pfkey_seq,
								 getpid()))) {
					fprintf(stderr,
						"%s: Trouble building message header, error=%d.\n",
						progname, error);
					pfkey_extensions_free(extensions);
					exit(1);
				}
			} else {
				if (debug) {
					fprintf(stdout,
						"setting x_satype proto=%d satype=%d\n",
						said_af_array[i + j].said.proto,
						proto2satype(said_af_array[i +
									   j].
							     said.proto)
						);
				}

				if ((error = pfkey_x_satype_build(&extensions[
									  K_SADB_X_EXT_SATYPE2
								  ],
								  proto2satype(
									  said_af_array
									  [i +
									   j].
									  said.
									  proto)
								  ))) {
					fprintf(stderr,
						"%s: Trouble building message header, error=%d.\n",
						progname, error);
					pfkey_extensions_free(extensions);
					exit(1);
				}
			}

			if ((error = pfkey_sa_build(&extensions[!j ?
								K_SADB_EXT_SA :
								K_SADB_X_EXT_SA2
						    ],
						    !j ? K_SADB_EXT_SA :
						    K_SADB_X_EXT_SA2,
						    said_af_array[i +
								  j].said.spi,  /* in network order */
						    0,
						    0,
						    0,
						    0,
						    0))) {
				fprintf(stderr,
					"%s: Trouble building sa extension, error=%d.\n",
					progname, error);
				pfkey_extensions_free(extensions);
				exit(1);
			}

#if 0
			if (j == 0) {
				anyaddr(said_af_array[i].af,
					&pfkey_address_s_ska);                      /* Is the address family correct ?? */
				if ((error = pfkey_address_build(&extensions[
									 K_SADB_EXT_ADDRESS_SRC
								 ],
								 K_SADB_EXT_ADDRESS_SRC,
								 0,
								 0,
								 sockaddrof(&
									    pfkey_address_s_ska))))
				{
					ipstr_buf b;

					fprintf(stderr,
						"%s: Trouble building address_s extension (%s), error=%d.\n",
						progname, ipstr(&pfkey_address_s_ska, &b), error);
					pfkey_extensions_free(extensions);
					exit(1);
				}
			}
#endif

			{
				uint16_t x = j == 0 ? SADB_EXT_ADDRESS_DST : SADB_X_EXT_ADDRESS_DST2;

				error = pfkey_address_build(
					&extensions[x], x, 0, 0,
					sockaddrof(&said_af_array[i + j].said.dst));
			}

			if (error) {
				ipstr_buf b;

				fprintf(stderr,
					"%s: Trouble building address_d extension (%s), error=%d.\n",
					progname,
					ipstr(&said_af_array[i + j].said.dst, &b),
					error);
				pfkey_extensions_free(extensions);
				exit(1);
			}

		}

		if ((error = pfkey_msg_build(&pfkey_msg, extensions,
					     EXT_BITS_IN))) {
			fprintf(stderr,
				"%s: Trouble building pfkey message, error=%d.\n",
				progname, error);
			pfkey_extensions_free(extensions);
			pfkey_msg_free(&pfkey_msg);
			exit(1);
		}

		if ((error = write(pfkey_sock,
				   pfkey_msg,
				   pfkey_msg->sadb_msg_len *
				   IPSEC_PFKEYv2_ALIGN)) !=
		    (ssize_t)(pfkey_msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN)) {
			fprintf(stderr,
				"%s: pfkey write failed, returning %d with errno=%d.\n",
				progname, error, errno);
			pfkey_extensions_free(extensions);
			pfkey_msg_free(&pfkey_msg);
			pfkey_write_error(error, errno);
		}

		if (pfkey_msg) {
			pfkey_extensions_free(extensions);
			pfkey_msg_free(&pfkey_msg);
		}
	}

	(void) close(pfkey_sock);  /* close the socket */
	exit(0);
}
