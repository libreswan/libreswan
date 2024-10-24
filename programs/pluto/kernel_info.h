/* declarations of routines that interface with the kernel's IPsec mechanism
 *
 * Copyright (C) 2024 Paul Wouters <pwouters@redhat.com>
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

#ifndef KERNEL_INFO_H
#define KERNEL_INFO_H

#include <stdbool.h>

struct logger;

enum kinfo_os {
	KINFO_UNKNOWN,
	KINFO_LINUX,
	KINFO_FREEBSD,
	KINFO_NETBSD,
	KINFO_OPENBSD
};

extern const struct sparse_names kinfo_os_names;

bool kernel_ge(enum kinfo_os, unsigned major, unsigned minor, unsigned patch);

extern void init_kernel_info(struct logger *logger);

#endif
