/* Supported PUBKEY types, for libreswan
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

#include "secrets.h"

const struct pubkey_type *pubkey_types[] = {
	&pubkey_type_rsa,
	&pubkey_type_ecdsa,
	&pubkey_type_eddsa,
	NULL,
};

const struct pubkey_type *pubkey_type_from_ipseckey_algorithm(enum ipseckey_algorithm_type algorithm)
{
	for (const struct pubkey_type **p = pubkey_types;
	     (*p) != NULL; p++) {
		const struct pubkey_type *type = (*p);
		if (type->ipseckey_algorithm == algorithm) {
			return type;
		}
	}
	return NULL;
}

