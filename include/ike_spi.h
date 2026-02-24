/* IKE SPI generation routines, for libreswan
 *
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright (C) 2018-2019 Andrew Cagney <cagney@gnu.org>
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
#include "ip_endpoint.h"

struct state;

typedef struct {
	uint8_t bytes[IKE_SA_SPI_SIZE];
} ike_spi_t;

extern const ike_spi_t zero_ike_spi;
bool ike_spi_is_zero(const ike_spi_t *ike_spi);
bool ike_spi_eq(const ike_spi_t *lhs, const ike_spi_t *rhs);

typedef struct {
	ike_spi_t initiator;
	ike_spi_t responder;
} ike_spis_t;

bool ike_spis_eq(const ike_spis_t *lhs, const ike_spis_t *rhs);

/*
 * Need to handle two cases:
 *
 * - new IKE SA - and ST is the IKE SA
 *
 * - rekeying old IKE SA - and ST has not yet been emancipated so it
 *   still looks like a child
 */

ike_spi_t ike_initiator_spi(void);
ike_spi_t ike_responder_spi(const ip_endpoint *initiator_endpoint, struct logger *logger);

void refresh_ike_spi_secret(struct logger *logger);

#endif
