/* cookie generation/verification routines.
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
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

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <libreswan.h>

#include "constants.h"
#include "defs.h"
#include "lswlog.h"
#include "rnd.h"
#include "cookie.h"
#include "ike_alg_hash.h"
#include "crypt_hash.h"

const u_char zero_cookie[COOKIE_SIZE];  /* guaranteed 0 */

/*
 * Generate a cookie (aka SPI)
 * First argument is true if we're to create an Initiator cookie.
 *
 * As responder, we use a hashing method to get a pseudo random
 * value instead of using our own random pool. It will prevent
 * an attacker from gaining raw data from our random pool and
 * it will prevent an attacker from depleting our random pool
 * or entropy.
 *
 * TODO: This use of SHA2 should be allowed even if we have USE_SHA2=false
 */
void get_cookie(bool initiator, uint8_t cookie[COOKIE_SIZE],
		const ip_address *addr)
{
	do {
		if (initiator) {
			get_rnd_bytes(cookie, COOKIE_SIZE);
		} else {
			static uint32_t counter = 0; /* STATIC */

			struct crypt_hash *ctx = crypt_hash_init(&ike_alg_hash_sha2_256,
								 "cookie", DBG_CRYPT);

			const unsigned char *addr_ptr;
			size_t addr_length = addrbytesptr_read(addr, &addr_ptr);
			crypt_hash_digest_bytes(ctx, "addr",
						addr_ptr, addr_length);

			crypt_hash_digest_bytes(ctx, "sod",
						secret_of_the_day,
						sizeof(secret_of_the_day));
			counter++;
			crypt_hash_digest_bytes(ctx, "counter",
						(const void *) &counter,
						sizeof(counter));

			u_char buffer[SHA2_256_DIGEST_SIZE];
			crypt_hash_final_bytes(&ctx, buffer, SHA2_256_DIGEST_SIZE);
			/* cookie size is smaller than hash output size */
			passert(COOKIE_SIZE <= SHA2_256_DIGEST_SIZE);
			memcpy(cookie, buffer, COOKIE_SIZE);
		}
	} while (is_zero_cookie(cookie)); /* probably never loops */
}
