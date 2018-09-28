/*
 * IPSEC interface configuration
 * Copyright (C) 1996  John Ioannidis.
 * Copyright (C) 1998, 1999, 2000, 2001  Richard Guy Briggs.
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
#include <string.h>
#include <stdlib.h>     /* system() */
#include <unistd.h>     /* getuid() */
#include <linux/types.h>
#include <sys/ioctl.h>  /* ioctl() */

#include <libreswan.h>
#ifdef NET_21 /* from libreswan.h */
#include <linux/sockios.h>
#include <sys/socket.h>
#endif /* NET_21 */ /* from libreswan.h */

#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <getopt.h>
#include "socketwrapper.h"
#include "lswtool.h"
#include "lswlog.h"

#include "libreswan/pfkey.h"
#include "libreswan/pfkeyv2.h"
#include "pfkey_help.h"
#include "libreswan/pfkey_debug.h"

#include "libreswan/ipsec_tunnel.h"

const char *progname;

static void usage(const char *name)
{
	fprintf(stdout, "%s --create <virtual>\n", name);
	fprintf(stdout, "%s --delete <virtual>\n", name);
	fprintf(stdout,
		"%s --attach --virtual <virtual-device> --physical <physical-device>\n",
		name);
	fprintf(stdout, "%s --detach --virtual <virtual-device>\n",
		name);
	fprintf(stdout, "%s --clear\n",
		name);
	fprintf(stdout, "%s --help\n",
		name);
	fprintf(stdout, "%s --version\n",
		name);
	fprintf(stdout, "%s\n",
		name);
	fprintf(stdout, "        [ --debug ] is optional to any %s command.\n",
		name);
	fprintf(stdout,
		"        [ --label <label> ] is optional to any %s command.\n",
		name);
	exit(1);
}

static const struct option longopts[] =
{
	{ "virtual", 1, 0, 'V' },
	{ "physical", 1, 0, 'P' },
	{ "create", required_argument, 0, 'C' },
	{ "delete", required_argument, 0, 'D' },
	{ "attach", 0, 0, 'a' },
	{ "detach", 0, 0, 'd' },
	{ "clear", 0, 0, 'c' },
	{ "help", 0, 0, 'h' },
	{ "version", 0, 0, 'v' },
	{ "label", 1, 0, 'l' },
	{ "debug", 0, 0, 'g' },
	{ 0, 0, 0, 0 }
};

static void check_conflict(uint32_t cf_cmd, int createdelete)
{
	if (cf_cmd || createdelete) {
		fprintf(stderr,
			"%s: exactly one of \n\t'--attach', '--detach', '--create', '--delete' or '--clear'\noptions must be specified.\n",
			progname);
		exit(1);
	}
}

uint32_t pfkey_seq = 0;

static int createdelete_virtual(int createdelete, char *virtname)
{
	int vifnum;
	struct sadb_ext *extensions[K_SADB_EXT_MAX + 1];
	struct sadb_msg *pfkey_msg;
	int error;
	int io_error, pfkey_sock;

	if (sscanf(virtname, "mast%d", &vifnum) == 1) {
		/* good */
	} else if (sscanf(virtname, "ipsec%d", &vifnum) == 1) {
		vifnum += IPSECDEV_OFFSET;
	} else {
		return 5;
	}

	pfkey_extensions_init(extensions);

	if ((error = pfkey_msg_hdr_build(&extensions[0],
					 createdelete,
					 0, 0,
					 ++pfkey_seq,
					 getpid()))) {
		fprintf(stderr,
			"%s: Trouble building message header, error=%d.\n",
			progname, error);
		pfkey_extensions_free(extensions);
		exit(1);
	}

	if ((error = pfkey_outif_build(&extensions[SADB_X_EXT_PLUMBIF],
				       vifnum))) {
		fprintf(stderr,
			"%s: Trouble building outif extension, error=%d.\n",
			progname, error);
		pfkey_extensions_free(extensions);
		exit(1);
	}

	if ((error = pfkey_msg_build(&pfkey_msg, extensions, EXT_BITS_IN))) {
		fprintf(stderr,
			"%s: Trouble building pfkey message, error=%d.\n",
			progname, error);
		pfkey_extensions_free(extensions);
		pfkey_msg_free(&pfkey_msg);
		exit(1);
	}

	pfkey_sock = pfkey_open_sock_with_error();
	if (pfkey_sock < 0)
		exit(1);

	io_error = write(pfkey_sock,
			 pfkey_msg,
			 pfkey_msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN);

	if (io_error !=
	    (ssize_t)(pfkey_msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN)) {
		perror("pfkey write");
		exit(2);
	}

	return 0;
}

int debug = 0;

int main(int argc, char *argv[])
{
	tool_init_log(argv[0]);
	/* force pfkey logging */
	pfkey_error_func = pfkey_debug_func = printf;

	struct ifreq ifr;
	struct ipsectunnelconf shc;
	int s;
	int c;
	int argcount = argc;
	int createdelete = 0;
	char virtname[64];
	struct stat sts;

	zero(&ifr);
	zero(&shc);
	virtname[0] = '\0';

	while ((c = getopt_long_only(argc, argv, "" /*"adchvV:P:l:+:"*/,
				     longopts, 0)) != EOF) {
		switch (c) {
		case 'g':
			debug = 1;
			argcount--;
			break;
		case 'a':
			check_conflict(shc.cf_cmd, createdelete);
			shc.cf_cmd = IPSEC_SET_DEV;
			break;
		case 'd':
			check_conflict(shc.cf_cmd, createdelete);
			shc.cf_cmd = IPSEC_DEL_DEV;
			break;
		case 'c':
			check_conflict(shc.cf_cmd, createdelete);
			shc.cf_cmd = IPSEC_CLR_DEV;
			break;
		case 'h':
			usage(progname);
			break;
		case 'v':
			if (optarg != NULL) {
				fprintf(stderr,
					"%s: warning; '-v' and '--version' options don't expect arguments, arg '%s' found, perhaps unintended.\n",
					progname, optarg);
			}
			fprintf(stdout, "%s, use ipsec --version instead\n",
				progname);
			exit(1);
			break;

		case 'C':
			check_conflict(shc.cf_cmd, createdelete);
			createdelete = SADB_X_PLUMBIF;
			jam_str(virtname, sizeof(virtname), optarg);
			break;
		case 'D':
			check_conflict(shc.cf_cmd, createdelete);
			createdelete = SADB_X_UNPLUMBIF;
			jam_str(virtname, sizeof(virtname), optarg);
			break;

		case 'V':
			fill_and_terminate(ifr.ifr_name, optarg, sizeof(ifr.ifr_name));
			break;
		case 'P':
			fill_and_terminate(shc.cf_name, optarg, sizeof(shc.cf_name));
			break;
		case 'l':
		{
			static const char combine_fmt[] = "%s --label %s";
			size_t room = strlen(argv[0]) +
					  sizeof(combine_fmt) +
					  strlen(optarg);
			char *b = malloc(room);

			snprintf(b, room, combine_fmt,
				argv[0],
				optarg);
			progname = b;
			argcount -= 2;
			break;
		}
		default:
			usage(progname);
			break;
		}
	}

	if (stat("/proc/net/pfkey", &sts) == 0) {
		fprintf(stderr,
			"%s: NETKEY does not support virtual interfaces.\n",
			progname);
		exit(1);
	}

	if (argcount == 1) {
		int ret = 1;
		if ((stat("/proc/net/ipsec_tncfg", &sts)) != 0) {
			fprintf(stderr,
				"%s: No tncfg - no IPsec support in kernel (are the modules loaded?)\n",
				progname);
		} else {
			ret = system("cat /proc/net/ipsec_tncfg");
			ret = ret != -1 &&
			      WIFEXITED(ret) ? WEXITSTATUS(ret) : 1;
		}
		exit(ret);
	}

	/* overlay our struct ipsectunnel onto ifr.ifr_ifru union (hope it fits!) */
	if (sizeof(ifr.ifr_ifru) < sizeof(shc)) {
		fprintf(stderr,
			"%s: Internal error: struct ipsectunnelconf won't fit inside struct ifreq\n",
			progname);
		exit(1);
	}
	memcpy(&ifr.ifr_ifru.ifru_newname, &shc, sizeof(shc));

	/* are we creating/deleting a virtual (mastXXX/ipsecXXX) interface? */
	if (createdelete)
		exit(createdelete_virtual(createdelete, virtname));

	switch (shc.cf_cmd) {
	case IPSEC_SET_DEV:
		if (!shc.cf_name[0]) {
			fprintf(stderr,
				"%s: physical I/F parameter missing.\n",
				progname);
			exit(1);
		}
		break;
	case IPSEC_DEL_DEV:
		if (!ifr.ifr_name[0]) {
			fprintf(stderr, "%s: virtual I/F parameter missing.\n",
				progname);
			exit(1);
		}
		break;
	case IPSEC_CLR_DEV:
		fill_and_terminate(ifr.ifr_name, "ipsec0", sizeof(ifr.ifr_name));
		break;
	default:
		fprintf(stderr, "%s: exactly one of '--attach', '--detach' or '--clear' options must be specified.\n"
			"Try %s --help' for usage information.\n",
			progname,
			progname);
		exit(1);
	}

	s = safe_socket(AF_INET, SOCK_DGRAM, 0);
	if (s == -1) {
		fprintf(stderr, "%s: Socket creation failed -- ", progname);
		switch (errno) {
		case EACCES:
			if (getuid() == 0)
				fprintf(stderr, "Root denied permission!?!\n");


			else
				fprintf(stderr, "Run as root user.\n");
			break;
		case EPROTONOSUPPORT:
			fprintf(stderr, "Internet Protocol not enabled");
			break;
		case EMFILE:
		case ENFILE:
		case ENOBUFS:
			fprintf(stderr, "Insufficient system resources.\n");
			break;
		case ENODEV:
			fprintf(stderr,
				"No such device.  Is the virtual device valid?  Is the ipsec module linked into the kernel or loaded as a module?\n");
			break;
		default:
			fprintf(stderr, "Unknown socket error %d.\n", errno);
		}
		exit(1);
	}
	if (ioctl(s, shc.cf_cmd, &ifr) == -1) {
		switch (shc.cf_cmd) {
		case IPSEC_SET_DEV:
			fprintf(stderr,
				"%s: Socket ioctl failed on attach -- ",
				progname);
			switch (errno) {
			case EINVAL:
				fprintf(stderr,
					"Invalid argument, check kernel log messages for specifics.\n");
				break;
			case ENODEV:
				fprintf(stderr,
					"No such device.  Is the virtual device valid?  Is the ipsec module linked into the kernel or loaded as a module?\n");
				break;
			case ENXIO:
				fprintf(stderr,
					"No such device.  Is the physical device valid?\n");
				break;
			case EBUSY:
				fprintf(stderr,
					"Device busy.  Virtual device %s is already attached to a physical device -- Use detach first.\n",
					ifr.ifr_name);
				break;
			default:
				fprintf(stderr, "Unknown socket error %d.\n",
					errno);
			}
			exit(1);

		case IPSEC_DEL_DEV:
			fprintf(stderr,
				"%s: Socket ioctl failed on detach -- ",
				progname);
			switch (errno) {
			case EINVAL:
				fprintf(stderr,
					"Invalid argument, check kernel log messages for specifics.\n");
				break;
			case ENODEV:
				fprintf(stderr,
					"No such device.  Is the virtual device valid?  The ipsec module may not be linked into the kernel or loaded as a module.\n");
				break;
			case ENXIO:
				fprintf(stderr,
					"Device requested is not linked to any physical device.\n");
				break;
			default:
				fprintf(stderr, "Unknown socket error %d.\n",
					errno);
			}
			exit(1);

		case IPSEC_CLR_DEV:
			fprintf(stderr, "%s: Socket ioctl failed on clear -- ",
				progname);
			switch (errno) {
			case EINVAL:
				fprintf(stderr,
					"Invalid argument, check kernel log messages for specifics.\n");
				break;
			case ENODEV:
				fprintf(stderr,
					"Failed.  Is the ipsec module linked into the kernel or loaded as a module?.\n");
				break;
			default:
				fprintf(stderr, "Unknown socket error %d.\n",
					errno);
			}
			exit(1);
		default:
			fprintf(stderr,
				"%s: Socket ioctl failed on unknown operation %u -- %s", progname,
				(unsigned) shc.cf_cmd, strerror(errno));
			exit(1);
		}
	}
	exit(0);
}
