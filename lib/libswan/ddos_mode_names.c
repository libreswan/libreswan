/* ddos_mode's names, for libreswan
 *
 * Copyright (C) 2015 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2022,2025 Andrew Cagney <cagney@gnu.org>
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

#include "ddos_mode.h"
#include "sparse_names.h"

const struct sparse_names ddos_mode_names = {
	.list = {
		SPARSE("auto",      DDOS_AUTO),
		SPARSE("busy",      DDOS_FORCE_BUSY),
		SPARSE("unlimited", DDOS_FORCE_UNLIMITED),
		SPARSE_NULL
	},
};
