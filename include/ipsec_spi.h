/*
 * header file for Libreswan library functions
 * Copyright (C) 1998, 1999, 2000  Henry Spencer.
 * Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/lgpl-2.1.txt>.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 *
 */

#ifndef IPSEC_SPI_H
#define IPSEC_SPI_H    /* seen it, no need to see it again */

#include <stdint.h>
/*
 * And the SA ID stuff.
 *
 * The value is in network order.
 *
 * XXX: Like IKE SPIs it should be hunk like byte array so that the
 * network ordering is enforced.
 *
 * struct ipsec_spi_t { uint8_t[4]val; };
 */

typedef uint32_t ipsec_spi_t;
#define PRI_IPSEC_SPI "%08x"
#define pri_ipsec_spi(SPI) ((unsigned) ntohl(SPI))

#endif
