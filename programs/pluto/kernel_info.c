/* declarations of routines that interface with the kernel's IPsec mechanism
 *
 * Copyright (C) 2024 Paul Wouters <pwouters@>
 * Copyright (C) 2024 Andrew Cagney
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
 *
 */

#include <sys/utsname.h>	/* for uname() */
#include <stdlib.h>

#include "kernel_info.h"
#include "log.h"
#include "sparse_names.h"

struct kernel_info {
	enum kinfo_os os;
	unsigned major;
	unsigned minor;
	unsigned patch;
};

static struct kernel_info kinfo; /* declare at end, so code uses header declaration */


const struct sparse_names kinfo_os_names = {
	.list = {
		SPARSE("FreeBSD", KINFO_FREEBSD),
		SPARSE("NetBSD", KINFO_NETBSD),
		SPARSE("OpenBSD", KINFO_OPENBSD),
		SPARSE("Linux", KINFO_LINUX),
		SPARSE_NULL,
	},
};

bool kernel_ge(enum kinfo_os os, unsigned major, unsigned minor, unsigned patch)
{
	if (kinfo.os != os)
		return false;
	if (kinfo.major < major)
		return false;
	if (kinfo.major == major && kinfo.minor < minor)
		return false;
	if (kinfo.major == major && kinfo.minor == minor && kinfo.patch < patch)
		return false;
	return true;
}

void init_kernel_info(struct logger *logger)
{
	struct utsname uts;
	if (uname(&uts) < 0) {
		llog(RC_LOG, logger, "host: unknown");
		return;
	}

	unsigned *ver[] = {
		&kinfo.major,
		&kinfo.minor,
		&kinfo.patch,
	};

	unsigned i = 0;
	char *c = uts.release;
	while (*c && i < elemsof(ver)) {
		if (char_isdigit(*c)) {
			(*ver[i]) = strtoul(c, &c, 10);
			i++;
		} else {
			c++;
		}
	}

	const struct sparse_name *os = sparse_lookup_by_name(&kinfo_os_names,
							     shunk1(uts.sysname));
	if (os == NULL) {
		kinfo.os = KINFO_UNKNOWN;
	} else {
		kinfo.os = os->value;
	}

	name_buf osn;
	llog(RC_LOG, logger, "operating system: %s %u.%u.%u [%s %s %s %s]",
	     str_sparse_long(&kinfo_os_names, kinfo.os, &osn),
	     kinfo.major, kinfo.minor, kinfo.patch,
	     uts.sysname, uts.release, uts.version, uts.machine);
}
