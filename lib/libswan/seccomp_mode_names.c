/* seccomp_mode, for libreswan
 *
 * Copyright (C) 2016 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2022,2025 Andrew Cagney
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

#include "seccomp_mode.h"
#include "sparse_names.h"

const struct sparse_names seccomp_mode_names = {
	.list = {
		SPARSE("enabled", SECCOMP_ENABLED),
		SPARSE("disabled", SECCOMP_DISABLED),
		SPARSE("tolerant", SECCOMP_TOLERANT),
		SPARSE_NULL
	},
};
