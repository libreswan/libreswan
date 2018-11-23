/* IKE SPI generation routines, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright (C) 2018  Andrew Cagney
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

#include "lswlog.h"
#include "ike_alg_hash.h"

#include "defs.h"	/* for all_zero */
#include "state.h"	/* for ike_sa */
#include "ike_spi.h"
#include "rnd.h"
#include "crypt_hash.h"

const uint8_t zero_cookie[IKE_SA_SPI_SIZE];  /* guaranteed 0 */

bool is_zero_cookie(const uint8_t spi[IKE_SA_SPI_SIZE])
{
	return memeq(spi, zero_cookie, IKE_SA_SPI_SIZE);
}

const ike_spi_t zero_ike_spi;  /* guaranteed 0 */

bool ike_spi_is_zero(const ike_spi_t *spi)
{
	return ike_spi_eq(spi, &zero_ike_spi);
}

bool ike_spi_eq(const ike_spi_t *lhs, const ike_spi_t *rhs)
{
	return memeq(lhs, rhs, sizeof(*lhs));
}

static uint8_t ike_spi_secret[SHA2_256_DIGEST_SIZE];

void refresh_ike_spi_secret(void)
{
	get_rnd_bytes(ike_spi_secret, sizeof(ike_spi_secret));
}

/*
 * Generate the IKE Initiator's SPI.
 */
ike_spi_t ike_initiator_spi(void)
{
	ike_spi_t spi;
	do {
		get_rnd_bytes(spi.bytes, sizeof(spi));
	} while (ike_spi_is_zero(&spi)); /* probably never loops */
	return spi;
}

/*
 * Generate the IKE Responder's SPI.
 *
 * As responder, we use a hashing method to get a pseudo random
 * value instead of using our own random pool. It will prevent
 * an attacker from gaining raw data from our random pool and
 * it will prevent an attacker from depleting our random pool
 * or entropy.
 */
ike_spi_t ike_responder_spi(const ip_address *addr)
{
	ike_spi_t spi;
	do {
		static uint32_t counter = 0; /* STATIC */

		struct crypt_hash *ctx = crypt_hash_init(&ike_alg_hash_sha2_256,
							 "IKE Responder SPI",
							 DBG_CRYPT);

		const unsigned char *addr_ptr;
		size_t addr_length = addrbytesptr_read(addr, &addr_ptr);
		crypt_hash_digest_bytes(ctx, "addr",
					addr_ptr, addr_length);

		crypt_hash_digest_bytes(ctx, "sod",
					ike_spi_secret,
					sizeof(ike_spi_secret));
		counter++;
		crypt_hash_digest_bytes(ctx, "counter",
					(const void *) &counter,
					sizeof(counter));

		u_char buffer[SHA2_256_DIGEST_SIZE];
		crypt_hash_final_bytes(&ctx, buffer, SHA2_256_DIGEST_SIZE);
		/* cookie size is smaller than hash output size */
		passert(IKE_SA_SPI_SIZE <= SHA2_256_DIGEST_SIZE);
		passert(IKE_SA_SPI_SIZE == sizeof(spi));
		memcpy(&spi, buffer, sizeof(spi));

	} while (ike_spi_is_zero(&spi)); /* probably never loops */
	return spi;
}

/*
 * Generate the IKE Initiator's SPI.
 */
void fill_ike_initiator_spi(struct state *st)
{
	st->st_ike_spis.initiator = ike_initiator_spi();
}

/*
 * Generate the IKE Responder's SPI.
 *
 * As responder, we use a hashing method to get a pseudo random
 * value instead of using our own random pool. It will prevent
 * an attacker from gaining raw data from our random pool and
 * it will prevent an attacker from depleting our random pool
 * or entropy.
 */
void fill_ike_responder_spi(struct state *st, const ip_address *addr)
{
	st->st_ike_spis.responder = ike_responder_spi(addr);
}
