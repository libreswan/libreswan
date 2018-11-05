/* IP SAID (?), for libreswan
 *
 * Copyright (C) 1998, 1999, 2000  Henry Spencer.
 * Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
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

#ifndef IP_SAID_H
#define IP_SAID_H

#include "err.h"
#include "ip_address.h"
#include "libreswan.h"		/* for ipsec_spi_t */

typedef struct {                                /* to identify an SA, we need: */
	ip_address dst;                         /* A. destination host */
	ipsec_spi_t spi;                        /* B. 32-bit SPI, assigned by dest. host */
#               define  SPI_PASS        256     /* magic values... */
#               define  SPI_DROP        257     /* ...for use... */
#               define  SPI_REJECT      258     /* ...with SA_INT */
#               define  SPI_HOLD        259
#               define  SPI_TRAP        260
#               define  SPI_TRAPSUBNET  261
	int proto;                      /* C. protocol */
#               define  SA_ESP  50      /* IPPROTO_ESP */
#               define  SA_AH   51      /* IPPROTO_AH */
#               define  SA_IPIP 4       /* IPPROTO_IPIP */
#               define  SA_COMP 108     /* IPPROTO_COMP */
#               define  SA_INT  61      /* IANA reserved for internal use */
} ip_said;

extern err_t ttosa(const char *src, size_t srclen, ip_said *dst);
extern size_t satot(const ip_said *src, int format, char *bufptr, size_t buflen);
#define SATOT_BUF       (5 + ULTOT_BUF + 1 + ADDRTOT_BUF)

/* initializations */
extern void initsaid(const ip_address *addr, ipsec_spi_t spi, int proto,
	      ip_said *dst);

/* tests */
extern bool samesaid(const ip_said *a, const ip_said *b);

#endif
