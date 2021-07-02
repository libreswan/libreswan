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
#include "ip_protocol.h"

struct jambuf;

/*
 * Magic values for use in combination with ip_protocol_internal to
 * flag shunt types.
 *
 * Danger! these are in host order; but SPIs are often in network
 * order.
 */

enum policy_spi {
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
#if 0
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
	struct ip_bytes bytes;
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
#else
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
	 * below magic values above (in network order).
	 *
	 * This is in network order (but is manipulated like an int.
	 *
	 * XXX: Does this mean it is the SPI that the remote end
	 * expects to see on its incoming packets?
	 */
	ipsec_spi_t spi;

	/*
	 * protocol
	 *
	 * Don't confuse this with the IP version of the above
	 * address.
	 */
	const struct ip_protocol *proto;
#endif
} ip_said;

/*
 * Constructors
 *
 * Technically it should be constructed from an endpoint;
 * unfortunately code still passes around address+protocol+[port].
 */

ip_said said_from_raw(where_t where, enum ip_version version,
		      const struct ip_bytes bytes,
		      const struct ip_protocol *protocol,
		      ip_port port,
		      ipsec_spi_t spi);

ip_said said_from_endpoint_spi(const ip_endpoint endpoint,
			       const ipsec_spi_t spi/*network-byte-ordered*/);

ip_said said_from_address_protocol_spi(const ip_address address,
				       const struct ip_protocol *proto,
				       ipsec_spi_t spi/*network-byte-order*/);

/*
 * Formatting
 */

/* room for textual represenation of an SAID */
#define SATOT_BUF       (5 + ULTOT_BUF + 1 + sizeof(address_buf))

typedef struct {
	char buf[SATOT_BUF];
} said_buf;

void jam_said(struct jambuf *buf, const ip_said *said);
const char *str_said(const ip_said *said, said_buf *buf);

/*
 * Details.
 */

const struct ip_info *said_type(const ip_said *said);
ip_address said_address(const ip_said *said);

/*
 * old stype
 */

extern err_t ttosa(const char *src, size_t srclen, ip_said *dst);

#endif
