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
#include "ip_endpoint.h"
#include "libreswan.h"		/* for ipsec_spi_t */
#include "jambuf.h"

/*
 * to identify an SA, we need
 */
typedef struct {
	/*
	 * destination host; no port
	 *
	 * Per rfc2367, 2.3.3 Address Extension: The zeroing of ports
	 * (e.g. sin_port and sin6_port) MUST be done for all messages
	 * except for originating SADB_ACQUIRE messages, which SHOULD
	 * fill them in with ports from the relevant TCP or UDP
	 * session which generates the ACQUIRE message.
	 */
	ip_address dst;
	/*
	 * 32-bit SPI, assigned by the destination host; or one of the
	 * below magic values.
	 *
	 * This is in network order (but is manipulated like an int.
	 *
	 * XXX: Does this mean it is the SPI that the remote end
	 * expects to see on its incomming packets?
	 */
#               define  SPI_PASS        256     /* magic values... */
#               define  SPI_DROP        257     /* ...for use... */
#               define  SPI_REJECT      258     /* ...with SA_INT */
#               define  SPI_HOLD        259
#               define  SPI_TRAP        260
#               define  SPI_TRAPSUBNET  261
	ipsec_spi_t spi;

	/*
	 * protocol
	 *
	 * See list below; where does this magic come from?
	 *
	 * Don't confuse this with the type of the above address.  Why
	 * do these #defines seem to be duplicates of other values.
	 */
#               define  SA_ESP  50      /* IPPROTO_ESP */
#               define  SA_AH   51      /* IPPROTO_AH */
#               define  SA_IPIP 4       /* IPPROTO_IPIP */
#               define  SA_COMP 108     /* IPPROTO_COMP */
#               define  SA_INT  61      /* IANA reserved for internal use */
	int proto;

} ip_said;

/*
 * Formatting
 */

typedef struct {
	char buf[5 + ULTOT_BUF + 1 + sizeof(address_buf)];
} said_buf;

void jam_said(jambuf_t *buf, const ip_said *said, int format);
const char *str_said(const ip_said *said, int format, said_buf *buf);

/*
 * Details.
 */

const struct ip_info *said_type(const ip_said *said);
ip_address said_address(const ip_said *said);

/*
 * old stype
 */

extern err_t ttosa(const char *src, size_t srclen, ip_said *dst);
extern size_t satot(const ip_said *src, int format, char *bufptr, size_t buflen);
#define SATOT_BUF       sizeof(said_buf)

/* initializations */
extern void initsaid(const ip_address *addr, ipsec_spi_t spi, int proto,
	      ip_said *dst);

#endif
