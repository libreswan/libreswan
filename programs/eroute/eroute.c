/*
 * manipulate eroutes
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
#include <sys/wait.h>
#include <stdlib.h> /* system() */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netdb.h>

#include <unistd.h>
#include <libreswan.h>

#include <stdio.h>
#include <getopt.h>

#include <signal.h>
#include <libreswan/pfkeyv2.h>
#include <libreswan/pfkey.h>

#include "constants.h"
#include "libreswan/radij.h"
#include "libreswan/ipsec_encap.h"
#include "lswlog.h"
#include "pfkey_help.h"
#include "libreswan/pfkey_debug.h"

#include "lsw_select.h"

char *progname;
static char me[] = "ipsec eroute";

static char *eroute_af_opt, *said_af_opt, *edst_opt, *spi_opt, *proto_opt, *said_opt,
*dst_opt, *src_opt;
static char *transport_proto_opt, *src_port_opt, *dst_port_opt;
static int action_type = 0;

static int pfkey_sock;
static uint32_t pfkey_seq = 0;

#define EMT_IFADDR      1               /* set enc if addr */
#define EMT_SETSPI      2               /* Set SPI properties */
#define EMT_DELSPI      3               /* Delete an SPI */
#define EMT_GRPSPIS     4               /* Group SPIs (output order)  */
#define EMT_SETEROUTE   5               /* set an extended route */
#define EMT_DELEROUTE   6               /* del an extended route */
#define EMT_TESTROUTE   7               /* try to find route, print to console */
#define EMT_SETDEBUG    8               /* set debug level if active */
#define EMT_UNGRPSPIS   9               /* UnGroup SPIs (output order)  */
#define EMT_CLREROUTE   10              /* clear the extended route table */
#define EMT_CLRSPIS     11              /* clear the spi table */
#define EMT_REPLACEROUTE        12      /* set an extended route */
#define EMT_GETDEBUG    13              /* get debug level if active */
#define EMT_INEROUTE    14              /* set incoming policy for IPIP on a chain */
#define EMT_INREPLACEROUTE      15      /* replace incoming policy for IPIP on a chain */

static void usage(char *arg)
{
	fprintf(stdout,
		"usage: %s --{add,addin,replace,replacein} --eraf <inet | inet6> --src <src>/<srcmaskbits>|<srcmask> --dst <dst>/<dstmaskbits>|<dstmask> [ --transport-proto <protocol> ] [ --src-port <source-port> ] [ --dst-port <dest-port> ] <SA>\n",
		arg);
	fprintf(stdout,
		"            where <SA> is '--af <inet | inet6> --edst <edst> --spi <spi> --proto <proto>'\n");
	fprintf(stdout, "                       OR '--said <said>'\n");
	fprintf(stdout,
		"                       OR '--said <%%passthrough | %%passthrough4 | %%passthrough6 | %%drop | %%reject | %%trap | %%hold | %%pass>'.\n");
	fprintf(stdout,
		"       %s --del --eraf <inet | inet6>--src <src>/<srcmaskbits>|<srcmask> --dst <dst>/<dstmaskbits>|<dstmask> [ --transport-proto <protocol> ] [ --src-port <source-port> ] [ --dst-port <dest-port> ]\n",
		arg);
	fprintf(stdout, "       %s --clear\n", arg);
	fprintf(stdout, "       %s --help\n", arg);
	fprintf(stdout, "       %s --version\n", arg);
	fprintf(stdout, "       %s\n", arg);
	fprintf(stdout, "        [ --debug ] is optional to any %s command.\n",
		arg);
	fprintf(stdout,
		"        [ --label <label> ] is optional to any %s command.\n",
		arg);
	exit(1);
}

static const struct option longopts[] =
{
	{ "dst", 1, 0, 'D' },
	{ "src", 1, 0, 'S' },
	{ "eraf", 1, 0, 'f' },
	{ "add", 0, 0, 'a' },
	{ "addin", 0, 0, 'A' },
	{ "replace", 0, 0, 'r' },
	{ "replacein", 0, 0, 'E' },
	{ "clear", 0, 0, 'c' },
	{ "del", 0, 0, 'd' },
	{ "af", 1, 0, 'i' },
	{ "edst", 1, 0, 'e' },
	{ "proto", 1, 0, 'p' },
	{ "transport-proto", 1, 0, 'P' },
	{ "src-port", 1, 0, 'Q' },
	{ "dst-port", 1, 0, 'R' },
	{ "help", 0, 0, 'h' },
	{ "spi", 1, 0, 's' },
	{ "said", 1, 0, 'I' },
	{ "version", 0, 0, 'v' },
	{ "label", 1, 0, 'l' },
	{ "debug", 0, 0, 'g' },
	{ 0, 0, 0, 0 }
};

/* outside of main, so that test cases can enable it */
int debug = 0;

int main(int argc, char **argv)
{
	unsigned long u;	/* for ttoulb */
	int c;
	const char *error_s;

	int error = 0;

	struct sadb_ext *extensions[K_SADB_EXT_MAX + 1];
	struct sadb_msg *pfkey_msg;
	ip_address pfkey_address_s_ska;
	/*struct sockaddr_in pfkey_address_d_ska;*/
	ip_address pfkey_address_sflow_ska;
	ip_address pfkey_address_dflow_ska;
	ip_address pfkey_address_smask_ska;
	ip_address pfkey_address_dmask_ska;

	int transport_proto = 0;
	int src_port = 0;
	int dst_port = 0;
	ip_said said;
	ip_subnet s_subnet, d_subnet;
	int eroute_af = 0;
	int said_af = 0;
	int sa_flags = 0;

	int argcount = argc;

	progname = argv[0];

	zero(&pfkey_address_s_ska);
	zero(&pfkey_address_sflow_ska);
	zero(&pfkey_address_dflow_ska);
	zero(&pfkey_address_smask_ska);
	zero(&pfkey_address_dmask_ska);
	zero(&said);
	zero(&s_subnet);
	zero(&d_subnet);

	eroute_af_opt = said_af_opt = edst_opt = spi_opt = proto_opt =
		said_opt = dst_opt = src_opt = NULL;

	while ((c = getopt_long(argc, argv,
				"" /*"acdD:e:i:hprs:S:f:vl:+:g"*/,
				longopts,
				0)) != EOF) {
		switch (c) {
		case 'g':
			debug = 1;
			pfkey_lib_debug = PF_KEY_DEBUG_PARSE_MAX;
			argcount--;
			break;
		case 'a':
			if (action_type != 0) {
				fprintf(stderr,
					"%s: Only one of '--add', '--addin', '--replace', '--replacein', '--clear', or '--del' options permitted.\n",
					progname);
				exit(1);
			}
			action_type = EMT_SETEROUTE;
			break;
		case 'A':
			if (action_type != 0) {
				fprintf(stderr,
					"%s: Only one of '--add', '--addin', '--replace', '--replacein', '--clear', or '--del' options permitted.\n",
					progname);
				exit(1);
			}
			action_type = EMT_INEROUTE;
			break;
		case 'r':
			if (action_type != 0) {
				fprintf(stderr,
					"%s: Only one of '--add', '--addin', '--replace', '--replacein', '--clear', or '--del' options permitted.\n",
					progname);
				exit(1);
			}
			action_type = EMT_REPLACEROUTE;
			break;
		case 'E':
			if (action_type != 0) {
				fprintf(stderr,
					"%s: Only one of '--add', '--addin', '--replace', '--replacein', '--clear', or '--del' options permitted.\n",
					progname);
				exit(1);
			}
			action_type = EMT_INREPLACEROUTE;
			break;
		case 'c':
			if (action_type != 0) {
				fprintf(stderr,
					"%s: Only one of '--add', '--addin', '--replace', '--clear', or '--del' options permitted.\n",
					progname);
				exit(1);
			}
			action_type = EMT_CLREROUTE;
			break;
		case 'd':
			if (action_type != 0) {
				fprintf(stderr,
					"%s: Only one of '--add', '--addin', '--replace', '--clear', or '--del' options permitted.\n",
					progname);
				exit(1);
			}
			action_type = EMT_DELEROUTE;
			break;
		case 'e':
			if (said_opt != NULL) {
				fprintf(stderr,
					"%s: Error, EDST parameter redefined:%s, already defined in SA:%s\n",
					progname, optarg, said_opt);
				exit(1);
			}
			if (edst_opt != NULL) {
				fprintf(stderr,
					"%s: Error, EDST parameter redefined:%s, already defined as:%s\n",
					progname, optarg, edst_opt);
				exit(1);
			}
			error_s = ttoaddr(optarg, 0, said_af, &said.dst);
			if (error_s != NULL) {
				fprintf(stderr,
					"%s: Error, %s converting --edst argument:%s\n",
					progname, error_s, optarg);
				exit(1);
			}
			edst_opt = optarg;
			break;
		case 'h':
		case '?':
			usage(progname);
			exit(1);
		case 's':
			if (said_opt != NULL) {
				fprintf(stderr,
					"%s: Error, SPI parameter redefined:%s, already defined in SA:%s\n",
					progname, optarg, said_opt);
				exit(1);
			}
			if (spi_opt != NULL) {
				fprintf(stderr,
					"%s: Error, SPI parameter redefined:%s, already defined as:%s\n",
					progname, optarg, spi_opt);
				exit(1);
			}

			error_s = ttoulb(optarg, 0, 0, 0xFFFFFFFFul, &u);
			if (error_s == NULL && u < 0x100)
				error_s = "values less than 0x100 are reserved";
			if (error_s != NULL) {
				fprintf(stderr,
					"%s: Invalid SPI parameter \"%s\": %s\n",
					progname, optarg, error_s);
				exit(1);
			}
			said.spi = htonl(u);
			spi_opt = optarg;
			break;
		case 'p':
			if (said_opt != NULL) {
				fprintf(stderr,
					"%s: Error, PROTO parameter redefined:%s, already defined in SA:%s\n",
					progname, optarg, said_opt);
				exit(1);
			}
			if (proto_opt != NULL) {
				fprintf(stderr,
					"%s: Error, PROTO parameter redefined:%s, already defined as:%s\n",
					progname, optarg, proto_opt);
				exit(1);
			}
#if 0
			if (said.proto != 0) {
				fprintf(stderr,
					"%s: Warning, PROTO parameter redefined:%s\n",
					progname, optarg);
				exit(1);
			}
#endif
			if (streq(optarg, "ah"))
				said.proto = SA_AH;
			if (streq(optarg, "esp"))
				said.proto = SA_ESP;
			if (streq(optarg, "tun"))
				said.proto = SA_IPIP;
			if (streq(optarg, "comp"))
				said.proto = SA_COMP;
			if (said.proto == 0) {
				fprintf(stderr,
					"%s: Invalid PROTO parameter: %s\n",
					progname, optarg);
				exit(1);
			}
			proto_opt = optarg;
			break;
		case 'I':
			if (said_opt != NULL) {
				fprintf(stderr,
					"%s: Error, SAID parameter redefined:%s, already defined in SA:%s\n",
					progname, optarg, said_opt);
				exit(1);
			}
			if (proto_opt != NULL) {
				fprintf(stderr,
					"%s: Error, PROTO parameter redefined in SA:%s, already defined as:%s\n",
					progname, optarg, proto_opt);
				exit(1);
			}
			if (edst_opt != NULL) {
				fprintf(stderr,
					"%s: Error, EDST parameter redefined in SA:%s, already defined as:%s\n",
					progname, optarg, edst_opt);
				exit(1);
			}
			if (spi_opt != NULL) {
				fprintf(stderr,
					"%s: Error, SPI parameter redefined in SA:%s, already defined as:%s\n",
					progname, optarg, spi_opt);
				exit(1);
			}
			if (said_af_opt != NULL) {
				fprintf(stderr,
					"%s: Error, address family parameter redefined in SA:%s, already defined as:%s\n",
					progname, optarg, said_af_opt);
				exit(1);
			}
			error_s = ttosa(optarg, 0, &said);
			if (error_s != NULL) {
				fprintf(stderr,
					"%s: Error, %s converting --sa argument:%s\n",
					progname, error_s, optarg);
				exit(1);
			} else if (ntohl(said.spi) < 0x100) {
				fprintf(stderr,
					"%s: Illegal reserved spi: %s => 0x%x Must be larger than or equal to 0x100.\n",
					progname, optarg, said.spi);
				exit(1);
			}
			said_af = addrtypeof(&said.dst);
			said_opt = optarg;
			break;
		case 'v':
			fprintf(stdout, "%s %s\n", me, ipsec_version_code());
			fprintf(stdout,
				"See `ipsec --copyright' for copyright information.\n");
			exit(1);
		case 'D':
			if (dst_opt != NULL) {
				fprintf(stderr,
					"%s: Error, --dst parameter redefined:%s, already defined as:%s\n",
					progname, optarg, dst_opt);
				exit(1);
			}
			error_s = ttosubnet(optarg, 0, eroute_af, &d_subnet);
			if (error_s != NULL) {
				fprintf(stderr,
					"%s: Error, %s converting --dst argument: %s\n",
					progname, error_s, optarg);
				exit(1);
			}
			dst_opt = optarg;
			break;
		case 'S':
			if (src_opt != NULL) {
				fprintf(stderr,
					"%s: Error, --src parameter redefined:%s, already defined as:%s\n",
					progname, optarg, src_opt);
				exit(1);
			}
			error_s = ttosubnet(optarg, 0, eroute_af, &s_subnet);
			if (error_s != NULL) {
				fprintf(stderr,
					"%s: Error, %s converting --src argument: %s\n",
					progname, error_s, optarg);
				exit(1);
			}
			src_opt = optarg;
			break;
		case 'P':
			if (transport_proto_opt != NULL) {
				fprintf(stderr,
					"%s: Error, --transport-proto parameter redefined:%s, already defined as:%s\n",
					progname, optarg,
					transport_proto_opt);
				exit(1);
			}
			transport_proto_opt = optarg;
			break;
		case 'Q':
			if (src_port_opt != NULL) {
				fprintf(stderr,
					"%s: Error, --src-port parameter redefined:%s, already defined as:%s\n",
					progname, optarg, src_port_opt);
				exit(1);
			}
			src_port_opt = optarg;
			break;
		case 'R':
			if (dst_port_opt != NULL) {
				fprintf(stderr,
					"%s: Error, --dst-port parameter redefined:%s, already defined as:%s\n",
					progname, optarg, dst_port_opt);
				exit(1);
			}
			dst_port_opt = optarg;
			break;
		case 'l':
		{
			static const char combine_fmt[] = "%s --label %s";
			size_t room = strlen(argv[0]) +
					  sizeof(combine_fmt) +
					  strlen(optarg);

			progname = malloc(room);
			snprintf(progname, room, combine_fmt,
				argv[0],
				optarg);
			argcount -= 2;
			break;
		}
		case 'i': /* specifies the address family of the SAID, stored in said_af */
			if (said_af_opt != NULL) {
				fprintf(stderr,
					"%s: Error, address family of SAID redefined:%s, already defined as:%s\n",
					progname, optarg, said_af_opt);
				exit(1);
			}
			if (streq(optarg, "inet"))
				said_af = AF_INET;
			if (streq(optarg, "inet6"))
				said_af = AF_INET6;
			if (said_af == 0) {
				fprintf(stderr,
					"%s: Invalid address family parameter for SAID: %s\n",
					progname, optarg);
				exit(1);
			}
			said_af_opt = optarg;
			break;
		case 'f': /* specifies the address family of the eroute, stored in eroute_af */
			if (eroute_af_opt != NULL) {
				fprintf(stderr,
					"%s: Error, address family of eroute redefined:%s, already defined as:%s\n",
					progname, optarg, eroute_af_opt);
				exit(1);
			}
			if (streq(optarg, "inet"))
				eroute_af = AF_INET;
			if (streq(optarg, "inet6"))
				eroute_af = AF_INET6;
			if (eroute_af == 0) {
				fprintf(stderr,
					"%s: Invalid address family parameter for eroute: %s\n",
					progname, optarg);
				exit(1);
			}
			eroute_af_opt = optarg;
			break;
		default:
			break;
		}
	}

	if (debug)
		fprintf(stdout, "%s: DEBUG: argc=%d\n", progname, argc);

	if (argcount == 1) {
		struct stat sts;

		if (stat("/proc/net/pfkey", &sts) == 0) {
			fprintf(stderr,
				"%s: NETKEY does not support eroute table.\n",
				progname);

			exit(1);
		} else {
			int ret = 1;

			if (stat("/proc/net/ipsec_eroute", &sts) != 0) {
				fprintf(stderr,
					"%s: No eroute table - no IPsec support in kernel (are the modules loaded?)\n",
					progname);
			} else {
				ret = system("cat /proc/net/ipsec_eroute");
				ret = ret != -1 &&
				      WIFEXITED(ret) ? WEXITSTATUS(ret) : 1;
			}
			exit(ret);
		}
	}

	/* Sanity checks */

	if (debug)
		fprintf(stdout, "%s: DEBUG: action_type=%d\n", progname,
			action_type);

	if (transport_proto_opt != 0) {
		struct protoent * proto = getprotobyname(transport_proto_opt);
		if (proto != 0) {
			transport_proto = proto->p_proto;
		} else {
			error_s = ttoulb(optarg, 0, 0, 255, &u);
			if (error_s != NULL) {
				fprintf(stderr,
					"%s: Invalid --transport-proto parameter \"%s\": %s\n",
					progname, transport_proto_opt, error_s);
				exit(1);
			}

			transport_proto = u;
		}
	}

	if (src_port_opt != 0 || dst_port_opt != 0) {
		switch (transport_proto) {
		case IPPROTO_UDP:
		case IPPROTO_TCP:
			break;
		default:
			fprintf(stderr,
				"%s: --transport-proto with either UDP or TCP must be specified if --src-port or --dst-port is used\n",
				progname);
			exit(1);
		}
	}

	if (src_port_opt != NULL) {
		struct servent * ent = getservbyname(src_port_opt, 0);
		if (ent != 0) {
			src_port = ent->s_port;
		} else {
			error_s = ttoulb(optarg, 0, 0, 0xFFFF, &u);
			if (error_s != NULL) {
				fprintf(stderr,
					"%s: Invalid --src-port parameter \"%s\": %s\n",
					progname, src_port_opt, error_s);
				exit(1);
			}
			src_port = htons(u);
		}
	}

	if (dst_port_opt != NULL) {
		struct servent * ent = getservbyname(dst_port_opt, 0);
		if (ent != 0) {
			dst_port = ent->s_port;
		} else {
			error_s = ttoulb(optarg, 0, 0, 0xFFFF, &u);
			if (error_s != NULL) {
				fprintf(stderr,
					"%s: Invalid --dst-port parameter \"%s\": %s\n",
					progname, src_port_opt, error_s);
				exit(1);
			}
			dst_port = htons(u);
		}
	}

	switch (action_type) {
	case EMT_SETEROUTE:
	case EMT_REPLACEROUTE:
	case EMT_INEROUTE:
	case EMT_INREPLACEROUTE:
		if ((said_af_opt == NULL || edst_opt == NULL ||
		     spi_opt == NULL || proto_opt == NULL) &&
		    said_opt == NULL) {
			fprintf(stderr,
				"%s: add and addin options must have SA specified.\n",
				progname);
			exit(1);
		}
		break;
	case EMT_DELEROUTE:
		if (src_opt == NULL) {
			fprintf(stderr,
				"%s: Error -- %s option '--src' is required.\n",
				progname,
				action_type == EMT_SETEROUTE ? "add" : "del");
			exit(1);
		}
		if (dst_opt == NULL) {
			fprintf(stderr,
				"%s: Error -- %s option '--dst' is required.\n",
				progname,
				action_type == EMT_SETEROUTE ? "add" : "del");
			exit(1);
		}
		break;
	case EMT_CLREROUTE:
		break;
	default:
		fprintf(stderr,
			"%s: exactly one of '--add', '--addin', '--replace', '--del' or '--clear' options must be specified.\n"
			"Try %s --help' for usage information.\n",
			progname,
			progname);
		exit(1);
	}

	pfkey_sock = pfkey_open_sock_with_error();
	if (pfkey_sock == -1)
		exit(1);

	if (debug) {
		fprintf(stdout,
			"%s: DEBUG: PFKEYv2 socket successfully openned=%d.\n",
			progname, pfkey_sock);
	}

	/* Build an SADB_X_ADDFLOW or SADB_X_DELFLOW message to send down. */
	/* It needs <base, SA, address(SD), flow(SD), mask(SD)> minimum. */
	pfkey_extensions_init(extensions);
	error = pfkey_msg_hdr_build(
			&extensions[0],
			(action_type == EMT_SETEROUTE ||
			 action_type == EMT_REPLACEROUTE ||
			 action_type == EMT_INREPLACEROUTE ||
			 action_type == EMT_INEROUTE) ?
				SADB_X_ADDFLOW : SADB_X_DELFLOW,
			proto2satype(said.proto),
			0,
			++pfkey_seq,
			getpid());
	if (error) {
		fprintf(stderr,
			"%s: Trouble building message header, error=%d.\n",
			progname, error);
		pfkey_extensions_free(extensions);
		exit(1);
	}

	if (debug) {
		fprintf(stdout,
			"%s: DEBUG: pfkey_msg_hdr_build successfull.\n",
			progname);
	}

	switch (action_type) {
	case EMT_CLREROUTE:
		sa_flags = SADB_X_SAFLAGS_CLEARFLOW;
		goto sa_build;

	case EMT_REPLACEROUTE:
		sa_flags = SADB_X_SAFLAGS_REPLACEFLOW;
		goto sa_build;

	case EMT_INREPLACEROUTE:
		sa_flags = SADB_X_SAFLAGS_REPLACEFLOW | SADB_X_SAFLAGS_INFLOW;
		goto sa_build;

	case EMT_INEROUTE:
		sa_flags = SADB_X_SAFLAGS_INFLOW;
		goto sa_build;

	case EMT_SETEROUTE:
sa_build:
		error = pfkey_sa_build(
				&extensions[SADB_EXT_SA],
				SADB_EXT_SA,
				said.spi, /* in network order */
				0,
				0,
				0,
				0,
				sa_flags);
		if (error) {
			fprintf(stderr,
				"%s: Trouble building sa extension, error=%d.\n",
				progname, error);
			pfkey_extensions_free(extensions);
			exit(1);
		}
		if (debug) {
			fprintf(stdout,
				"%s: DEBUG: pfkey_sa_build successful.\n",
				progname);
		}

	default:
		break;
	}

	switch (action_type) {
	case EMT_SETEROUTE:
	case EMT_REPLACEROUTE:
	case EMT_INEROUTE:
	case EMT_INREPLACEROUTE:
		anyaddr(said_af, &pfkey_address_s_ska);
		error = pfkey_address_build(
				&extensions[SADB_EXT_ADDRESS_SRC],
				SADB_EXT_ADDRESS_SRC,
				0,
				0,
				sockaddrof(&pfkey_address_s_ska));
		if (error) {
			ipstr_buf b;

			fprintf(stderr,
				"%s: Trouble building address_s extension (%s), error=%d.\n",
				progname, ipstr(&pfkey_address_s_ska, &b),
				error);
			pfkey_extensions_free(extensions);
			exit(1);
		}
		if (debug) {
			fprintf(stdout,
				"%s: DEBUG: pfkey_address_build successful for src.\n",
				progname);
		}

		error = pfkey_address_build(
				&extensions[SADB_EXT_ADDRESS_DST],
				SADB_EXT_ADDRESS_DST,
				0,
				0,
				sockaddrof(&said.dst));
		if (error) {
			ipstr_buf b;

			fprintf(stderr,
				"%s: Trouble building address_d extension (%s), error=%d.\n",
				progname, ipstr(&said.dst, &b), error);
			pfkey_extensions_free(extensions);
			exit(1);
		}
		if (debug) {
			fprintf(stdout,
				"%s: DEBUG: pfkey_address_build successful for dst.\n",
				progname);
		}
	default:
		break;
	}

	switch (action_type) {
	case EMT_SETEROUTE:
	case EMT_REPLACEROUTE:
	case EMT_INEROUTE:
	case EMT_INREPLACEROUTE:
	case EMT_DELEROUTE:
		networkof(&s_subnet, &pfkey_address_sflow_ska); /* src flow */
		add_port(eroute_af, &pfkey_address_sflow_ska, src_port);
		error = pfkey_address_build(
				&extensions[SADB_X_EXT_ADDRESS_SRC_FLOW],
				SADB_X_EXT_ADDRESS_SRC_FLOW,
				0,
				0,
				sockaddrof(&pfkey_address_sflow_ska));
		if (error) {
			ipstr_buf b;

			fprintf(stderr,
				"%s: Trouble building address_sflow extension (%s), error=%d.\n",
				progname, ipstr(&pfkey_address_sflow_ska, &b), error);
			pfkey_extensions_free(extensions);
			exit(1);
		}
		if (debug) {
			fprintf(stdout,
				"%s: DEBUG: pfkey_address_build successful for src flow.\n",
				progname);
		}

		networkof(&d_subnet, &pfkey_address_dflow_ska); /* dst flow */
		add_port(eroute_af, &pfkey_address_dflow_ska, dst_port);
		error = pfkey_address_build(
				&extensions[SADB_X_EXT_ADDRESS_DST_FLOW],
				SADB_X_EXT_ADDRESS_DST_FLOW,
				0,
				0,
				sockaddrof(&pfkey_address_dflow_ska));
		if (error) {
			ipstr_buf b;

			fprintf(stderr,
				"%s: Trouble building address_dflow extension (%s), error=%d.\n",
				progname, ipstr(&pfkey_address_dflow_ska, &b), error);
			pfkey_extensions_free(extensions);
			exit(1);
		}
		if (debug) {
			fprintf(stdout,
				"%s: DEBUG: pfkey_address_build successful for dst flow.\n",
				progname);
		}

		maskof(&s_subnet, &pfkey_address_smask_ska); /* src mask */
		add_port(eroute_af, &pfkey_address_smask_ska,
			 src_port ? ~0 : 0);
		error = pfkey_address_build(
				&extensions[SADB_X_EXT_ADDRESS_SRC_MASK],
				SADB_X_EXT_ADDRESS_SRC_MASK,
				0,
				0,
				sockaddrof(&pfkey_address_smask_ska));
		if (error) {
			ipstr_buf b;

			fprintf(stderr,
				"%s: Trouble building address_smask extension (%s), error=%d.\n",
				progname, ipstr(&pfkey_address_smask_ska, &b), error);
			pfkey_extensions_free(extensions);
			exit(1);
		}
		if (debug) {
			fprintf(stdout,
				"%s: DEBUG: pfkey_address_build successful for src mask.\n",
				progname);
		}

		maskof(&d_subnet, &pfkey_address_dmask_ska); /* dst mask */
		add_port(eroute_af, &pfkey_address_dmask_ska,
			 dst_port ? ~0 : 0);
		error = pfkey_address_build(
				&extensions[SADB_X_EXT_ADDRESS_DST_MASK],
					 SADB_X_EXT_ADDRESS_DST_MASK,
					 0,
					 0,
					 sockaddrof(&pfkey_address_dmask_ska));
		if (error) {
			ipstr_buf b;

			fprintf(stderr,
				"%s: Trouble building address_dmask extension (%s), error=%d.\n",
				progname, ipstr(&pfkey_address_dmask_ska, &b),
				error);
			pfkey_extensions_free(extensions);
			exit(1);
		}
		if (debug) {
			fprintf(stdout,
				"%s: DEBUG: pfkey_address_build successful for dst mask.\n",
				progname);
		}
	}

	if (transport_proto != 0) {
		error = pfkey_x_protocol_build(
				&extensions[SADB_X_EXT_PROTOCOL],
				transport_proto);
		if (error) {
			fprintf(stderr,
				"%s: Trouble building transport protocol extension, error=%d.\n",
				progname, error);
			exit(1);
		}
	}

	error = pfkey_msg_build(&pfkey_msg, extensions, EXT_BITS_IN);
	if (error) {
		fprintf(stderr,
			"%s: Trouble building pfkey message, error=%d.\n",
			progname, error);
		pfkey_extensions_free(extensions);
		pfkey_msg_free(&pfkey_msg);
		exit(1);
	}
	if (debug)
		fprintf(stdout, "%s: DEBUG: pfkey_msg_build successful.\n",
			progname);

	error = write(pfkey_sock,
			pfkey_msg,
			pfkey_msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN);
	if (error != (ssize_t)(pfkey_msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN)) {
		fprintf(stderr,
			"%s: pfkey write failed, returning %d with errno=%d.\n",
			progname, error, errno);
		pfkey_extensions_free(extensions);
		pfkey_msg_free(&pfkey_msg);
		switch (errno) {
		case EINVAL:
			fprintf(stderr,
				"Invalid argument, check kernel log messages for specifics.\n");
			break;
		case ENXIO:
			if ((action_type == EMT_SETEROUTE) ||
			    (action_type == EMT_REPLACEROUTE)) {
				fprintf(stderr, "Invalid mask.\n");
				break;
			}
			if (action_type == EMT_DELEROUTE) {
				fprintf(stderr, "Mask not found.\n");
				break;
			}
		case EFAULT:
			if ((action_type == EMT_SETEROUTE) ||
			    (action_type == EMT_REPLACEROUTE)) {
				fprintf(stderr, "Invalid address.\n");
				break;
			}
			if (action_type == EMT_DELEROUTE) {
				fprintf(stderr, "Address not found.\n");
				break;
			}
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
			fprintf(stderr, "KLIPS not loaded.\n");
			break;
		case EBUSY:
			fprintf(stderr,
				"KLIPS is busy.  Most likely a serious internal error occured in a previous command.  Please report as much detail as possible to development team.\n");
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
				"eroute already in use.  Delete old one first.\n");
			break;
		case ENOENT:
			if (action_type == EMT_INEROUTE ||
			    action_type == EMT_INREPLACEROUTE) {
				fprintf(stderr, "non-existant IPIP SA.\n");
				break;
			}
			fprintf(stderr,
				"eroute doesn't exist.  Can't delete.\n");
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
/*		fprintf(stderr, "%s: socket write returned errno %d\n",
		progname, errno);*/
		exit(1);
	}
	if (debug)
		fprintf(stdout, "%s: DEBUG: pfkey write successful.\n",
			progname);

	if (pfkey_msg != NULL) {
		pfkey_extensions_free(extensions);
		pfkey_msg_free(&pfkey_msg);
	}

	(void) close(pfkey_sock);  /* close the socket */

	if (debug)
		fprintf(stdout, "%s: DEBUG: write ok\n", progname);

	exit(0);
}
/*
 * $Log: eroute.c,v $
 * Revision 1.67  2005/08/18 14:04:39  ken
 * Patch from mt@suse.de to avoid GCC warnings with system() calls
 *
 * Revision 1.66  2005/07/08 02:56:38  paul
 * gcc4 fixes that were not commited because vault was down
 *
 * Revision 1.65  2005/03/22 23:14:54  ken
 * *** empty log message ***
 *
 * Revision 1.64  2005/03/22 23:14:06  ken
 * Fix logic
 *
 * Revision 1.63  2005/03/22 23:06:13  ken
 * Fix sloppy typo
 *
 * Revision 1.62  2005/03/22 23:02:37  ken
 * Nicer error messages - #234
 *
 * Revision 1.61  2004/12/10 12:38:29  paul
 * Renamed the stack names consistently to KLIPS and NETKEY
 *
 * Revision 1.60  2004/04/06 02:58:43  mcr
 *      freeswan->libreswan changes.
 *
 * Revision 1.59  2004/02/09 23:07:35  paul
 * better error for native 2.6 pfk_key for 'ipsec eroute'
 *
 * Revision 1.58  2003/12/05 16:44:12  mcr
 *      patches to avoid ipsec_netlink.h, which has been obsolete for
 *      some time now.
 *
 * Revision 1.57  2003/10/31 02:32:27  mcr
 *      pulled up port-selector patches
 *
 * Revision 1.56.2.1  2003/09/21 14:00:26  mcr
 *      pre-liminary X.509 patch - does not yet pass tests.
 *
 * Revision 1.56  2003/09/10 00:01:25  mcr
 *      fixes for gcc 3.3 from Matthias Bethke <Matthias.Bethke@gmx.net>
 *
 * Revision 1.55  2003/01/30 02:33:07  rgb
 *
 * Added ENOSPC for no room in SAref table and ESPIPE for SAref internal error.
 *
 * Revision 1.54  2002/10/04 03:52:46  dhr
 *
 * gcc3 now enforces C restriction on placement of labels
 *
 * Revision 1.53  2002/09/20 05:02:15  rgb
 * Cleaned up pfkey_lib_debug usage.
 *
 * Revision 1.52  2002/07/23 02:58:58  rgb
 * Fixed "opening" speeling mistake.
 *
 * Revision 1.51  2002/04/24 07:55:32  mcr
 *      #include patches and Makefiles for post-reorg compilation.
 *
 * Revision 1.50  2002/04/24 07:35:38  mcr
 * Moved from ./klips/utils/eroute.c,v
 *
 * Revision 1.49  2002/03/08 21:44:04  rgb
 * Update for all GNU-compliant --version strings.
 *
 * Revision 1.48  2002/02/15 19:54:11  rgb
 * Purged dead code.
 *
 * Revision 1.47  2001/11/09 01:42:36  rgb
 * Re-formatted usage text for clarity.
 *
 * Revision 1.46  2001/10/02 17:03:45  rgb
 * Check error return for all "tto*" calls and report errors.  This, in
 * conjuction with the fix to "tto*" will detect AF not set.
 *
 * Revision 1.45  2001/09/07 22:12:27  rgb
 * Added EAFNOSUPPORT error return explanation for KLIPS not loaded.
 *
 * Revision 1.44  2001/07/06 19:49:33  rgb
 * Renamed EMT_RPLACEROUTE to EMT_REPLACEROUTE for clarity and logical text
 * searching.
 * Added EMT_INEROUTE for supporting incoming policy checks.
 * Added inbound policy checking code for IPIP SAs.
 *
 * Revision 1.43  2001/06/15 05:02:05  rgb
 * Fixed error return messages and codes.
 *
 * Revision 1.42  2001/06/14 19:35:14  rgb
 * Update copyright date.
 *
 * Revision 1.41  2001/05/21 02:02:54  rgb
 * Eliminate 1-letter options.
 *
 * Revision 1.40  2001/05/16 04:39:57  rgb
 * Fix --label option to add to command name rather than replace it.
 * Fix 'print table' option to ignore --label and --debug options.
 *
 * Revision 1.39  2001/02/26 19:59:03  rgb
 * Added a number of missing ntohl() conversions for debug output.
 * Implement magic SAs %drop, %reject, %trap, %hold, %pass as part
 * of the new SPD and to support opportunistic.
 * Enforced spi > 0x100 requirement, now that pass uses a magic SA.
 *
 *
 *
 */
