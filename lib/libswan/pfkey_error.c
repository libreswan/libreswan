/*
 * open a pfkey socket or dump a reason why it failed.
 *
 * Copyright (C) 2006 Michael Richardson <mcr@xelerance.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/lgpl-2.1.txt>.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 */
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include "libreswan.h"
#include <libreswan/pfkeyv2.h>
#include "pfkey_help.h"

extern char *progname;

void pfkey_write_error(int writeerror, int err)
{
	fprintf(stderr,
		"%s: pfkey write failed, returning %d with errno=%d.\n",
		progname, writeerror, err);
	switch (err) {
	case EACCES:
		fprintf(stderr, "access denied.  ");
		if (getuid() == 0)
			fprintf(stderr,
				"Check permissions.  Should be 600.\n");
		else
			fprintf(stderr,
				"You must be root to open this file.\n");
		break;
#ifdef EUNATCH
	case EUNATCH:
		fprintf(stderr, "Netlink not enabled OR KLIPS not loaded.\n");
		break;
#endif
	case EBUSY:
		fprintf(stderr,
			"KLIPS is busy.  Most likely a serious internal error occurred in a previous command.  Please report as much detail as possible to development team.\n");
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
			"Algorithm support not available in the kernel. Please compile in support.\n");
		break;
	case EEXIST:
		fprintf(stderr, "SA already in use.  Delete old one first.\n");
		break;
	case ENOENT:
		fprintf(stderr,
			"device does not exist.  See Libreswan installation procedure.\n");
		break;
	case ENXIO:
		fprintf(stderr, "SA does not exist.  Cannot delete.\n");
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

