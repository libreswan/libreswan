/* Send CA policy names, for libreswan
 *
 * Copyright (C) 2025 Andrew Cagney
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

#include "constants.h"
#include "sparse_names.h"

/*
 * certificate request payload policy
 */

const struct sparse_names sendcert_policy_names = {
	.list = {
		/* prefered names */
		SPARSE("always",	SENDCERT_ALWAYS),
		SPARSE("sendifasked",	SENDCERT_IFASKED),
		SPARSE("never",		SENDCERT_NEVER),
		/* aliases */
		SPARSE("alwayssend",	SENDCERT_ALWAYS),
		SPARSE("no",		SENDCERT_NEVER),
		SPARSE("yes",		SENDCERT_ALWAYS),
		SPARSE("ifasked",	SENDCERT_IFASKED),
		SPARSE_NULL
	},
};
