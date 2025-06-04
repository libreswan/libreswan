/* seccomp_mode, for libreswan
 *
 * Copyright (C) 2016 Paul Wouters <pwouters@redhat.com>
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

#ifndef SECCOMP_MODE_H
#define SECCOMP_MODE_H

/*
 * seccomp mode
 *
 * on syscall violation, enabled kills pluto, tolerant ignores syscall
 */

enum seccomp_mode {
	SECCOMP_ENABLED = 1,
	SECCOMP_TOLERANT,
	SECCOMP_DISABLED
};

extern const struct sparse_names seccomp_mode_names;

#endif
