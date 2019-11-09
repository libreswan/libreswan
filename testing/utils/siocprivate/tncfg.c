/*
 * IPSEC interface configuration
 * Copyright (C) 1996  John Ioannidis.
 * Copyright (C) 1998, 1999, 2000, 2001  Richard Guy Briggs.
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
#include <stdlib.h>     /* system(), strtoul() */
#include <unistd.h>     /* getuid() */
#include <linux/types.h>
#include <sys/ioctl.h>  /* ioctl() */

#include <libreswan.h>
#ifdef NET_21 /* from libreswan.h */
#include <linux/sockios.h>
#include <sys/socket.h>
#endif /* NET_21 */ /* from libreswan.h */

#if 0
#include <linux/if.h>
#else
#include <net/if.h>
#endif
#include <sys/types.h>
#include <errno.h>
#include <getopt.h>
#include "socketwrapper.h"
#include "libreswan/ipsec_tunnel.h"

static void usage(char *name)
{
	fprintf(stdout, "%s <virtual-device>\n", name);
	exit(1);
}

int main(int argc, char *argv[])
{
	struct ifreq ifr;

	zero(&ifr);	/* OK: no pointer fields */
	program_name = argv[0];

	s = safe_socket(AF_INET, SOCK_DGRAM, 0);
	if (s == -1) {
		fprintf(stderr, "%s: Socket creation failed:%s ",
			program_name, strerror(errno));
		exit(1);
	}

	/* if (ioctl(fd, SIOCDEVPRIVATE, &ifr) >= 0) { */

	if (ioctl(s, shc->cf_cmd, &ifr) == -1) {
		if (shc->cf_cmd == IPSEC_SET_DEV) {
			fprintf(stderr,
				"%s: Socket ioctl failed on attach -- ",
				program_name);
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
		}
		if (shc->cf_cmd == IPSEC_DEL_DEV) {
			fprintf(stderr,
				"%s: Socket ioctl failed on detach -- ",
				program_name);
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
		}
		if (shc->cf_cmd == IPSEC_CLR_DEV) {
			fprintf(stderr, "%s: Socket ioctl failed on clear -- ",
				program_name);
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
		}
	}
	exit(0);
}
