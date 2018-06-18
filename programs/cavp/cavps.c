/*
 * Parse CAVP test vectors, for libreswan
 *
 * Copyright (C) 2015-2017, Andrew Cagney <cagney@gnu.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <stddef.h>	/* for NULL */

#include "cavps.h"
#include "cavp_ikev1_dsa.h"
#include "cavp_ikev1_psk.h"
#include "cavp_ikev2.h"
#include "cavp_sha.h"
#include "cavp_hmac.h"
#include "cavp_gcm.h"

const struct cavp *cavps[] = {
	&cavp_ikev1_dsa,
	&cavp_ikev1_psk,
	&cavp_ikev2,
	&cavp_sha_msg,
	&cavp_sha_monte,
	&cavp_hmac,
	&cavp_gcm,
	NULL
};
