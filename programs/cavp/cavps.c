/*
 * Parse CAVP test vectors, for libreswan
 *
 * Copyright (C) 2015-2017, Andrew Cagney <cagney@gnu.org>
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

#include <stddef.h>	/* for NULL */

#include "cavps.h"
#include "test_ikev1_dsa.h"
#include "test_ikev1_psk.h"
#include "test_ikev2.h"
#include "test_sha.h"
#include "test_hmac.h"
#include "test_gcm.h"

const struct cavp *cavps[] = {
	&test_ikev1_dsa,
	&test_ikev1_psk,
	&test_ikev2,
	&test_sha_msg,
	&test_sha_monte,
	&test_hmac,
	&test_gcm,
	NULL
};
