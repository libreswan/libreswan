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

#include "diag.h"
#include "ip_endpoint.h"
#include "libreswan.h"		/* for ipsec_spi_t */
#include "ttodata.h"
#include "ip_protocol.h"

struct jambuf;

/*
 * Magic values for use in combination with ip_protocol_internal to
 * flag shunt types.
 *
 * Danger! these are in host order; but SPIs are often in network
 * order.
 *
 * XXX: why do these start at 256? i.e., require more than one byte?
 */

enum policy_spi {
	SPI_NONE = 0,
	SPI_PASS = 256,
	SPI_DROP = 257,
	SPI_REJECT = 258,
	SPI_HOLD = 259,
	SPI_TRAP = 260,
	SPI_IGNORE = 261,
	SPI_TRAPSUBNET = 262,
};

extern const struct enum_names policy_spi_names;


/*
 * to identify an SA, we need
 */

typedef struct {
	bool is_set;
	/*
	 * Index into the struct ip_info array; must be stream
	 * friendly.
	 */
	enum ip_version version; /* 0, 4, 6 */
	/*
	 * We need something that makes static IPv4 initializers possible
	 * (struct in_addr requires htonl() which is run-time only).
	 */
	struct ip_bytes dst;
	/*
	 * Protocol 0 is interpreted as a wild card so isn't allowed.
	 */
	unsigned ipproto;
	/*
	 * 32-bit SPI, assigned by the destination host; or one of the
	 * below magic values above (in network order).
	 *
	 * This is in network order (but is manipulated like an int.
	 *
	 * XXX: Does this mean it is the SPI that the remote end
	 * expects to see on its incoming packets?
	 */
	ipsec_spi_t spi;
#if 0
	/*
	 * The "port" which might actually be some sort of ICMP
	 * encoding.  Determined by ipproto.
	 */
	int hport;
#endif
} ip_said;

extern const ip_said unset_said;

/*
 * Constructors
 *
 * Technically it should be constructed from an endpoint;
 * unfortunately code still passes around address+protocol+[port].
 */

ip_said said_from_raw(where_t where, enum ip_version version,
		      const struct ip_bytes bytes,
		      const struct ip_protocol *protocol,
		      /*ip_port port,*/
		      ipsec_spi_t spi);

ip_said said_from_endpoint_spi(const ip_endpoint endpoint,
			       const ipsec_spi_t spi/*network-byte-ordered*/);

ip_said said_from_address_protocol_spi(const ip_address address,
				       const struct ip_protocol *proto,
				       ipsec_spi_t spi/*network-byte-order*/);

/*
 * Formatting
 */

typedef struct {
	char buf[5 + ULTOT_BUF + 1 + sizeof(address_buf)];
} said_buf;

size_t jam_said(struct jambuf *buf, const ip_said *said);
const char *str_said(const ip_said *said, said_buf *buf);

/*
 * Details.
 */

bool said_is_unset(const ip_said *said);		/* handles NULL */
const struct ip_info *said_type(const ip_said *said);	/* handles NULL */
const struct ip_info *said_info(const ip_said said);

ip_address said_address(const ip_said said);
const struct ip_protocol *said_protocol(const ip_said said);

/*
 * Parsing
 */

extern diag_t ttosaid(shunk_t src, ip_said *dst);

#endif
