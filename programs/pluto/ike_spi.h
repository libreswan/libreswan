/* IKE SPI generation routines, for libreswan
 *
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

#ifndef IKE_SPI_H
#define IKE_SPI_H

#include <stdint.h>
#include <stdbool.h>

#include "ietf_constants.h"	/* for IKE_SA_SPI_SIZE */
#include "ip_address.h"

struct state;

/*
 * New and old.
 *
 * Switching from spi[IKE_SA_SPI_SIZE] to ike_spi_t will take time as
 * it churns the code.  First with a cookie->ike_spi rename and second
 * with a switch to an explicit reference parameter (old code worked
 * without '&' because parameter was passed by array reference).
 */

typedef struct {
	uint8_t ike_spi[IKE_SA_SPI_SIZE];
} ike_spi_t;
extern const ike_spi_t zero_ike_spi;
bool ike_spi_is_zero(const ike_spi_t *ike_spi);

extern const uint8_t zero_cookie[IKE_SA_SPI_SIZE]; /* use zero_ike_spi */
bool is_zero_cookie(const uint8_t ike_spi[IKE_SA_SPI_SIZE]); /* use ike_spi_is_zero() */

/*
 * Need to handle two cases:
 *
 * - new IKE SA - and ST is the IKE SA
 *
 * - rekeying old IKE SA - and ST has not yet been emancipated so it
 *   still looks like a child
 */

void fill_ike_initiator_spi(struct state *st);
void fill_ike_responder_spi(struct state *st, const ip_address *addr);

void refresh_ike_spi_secret(void);

#endif
