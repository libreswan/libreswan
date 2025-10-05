/* tables of names for values defined in constants.h
 *
 * Copyright (C) 2022 Andrew Cagney
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

#include "lswcdefs.h"		/* for ARRAY_REF() */
#include "enum_names.h"
#include "ietf_constants.h"	/* for enum ipseckey_algorithm_type_names */

static const char *ipseckey_algorithm_config_name[] = {
#define S(E,S) [E - IPSECKEY_ALGORITHM_RSA] = S
	S(IPSECKEY_ALGORITHM_RSA, "rsasigkey"),
	S(IPSECKEY_ALGORITHM_ECDSA, "ecdsakey"),
	S(IPSECKEY_ALGORITHM_EDDSA, "eddsakey"),
	S(IPSECKEY_ALGORITHM_X_PUBKEY, "pubkey"),
#undef S
};

const struct enum_names ipseckey_algorithm_config_names = {
	IPSECKEY_ALGORITHM_RSA,
	IPSECKEY_ALGORITHM_X_PUBKEY,
	ARRAY_REF(ipseckey_algorithm_config_name),
	NULL, NULL,
};
