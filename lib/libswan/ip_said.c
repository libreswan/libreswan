/* SA ID, for libreswan
 *
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2000, 2001  Henry Spencer.
 * Copyright (C) 2012 David McCullough <david_mccullough@mcafee.com>
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

#include "ip_said.h"
#include "ip_info.h"

#include "jambuf.h"

const ip_said unset_said;

ip_said said_from_raw(where_t where UNUSED, enum ip_version version,
		      const struct ip_bytes dst,
		      const struct ip_protocol *protocol,
		      ipsec_spi_t spi)
{
	ip_said said = {
		.is_set = true,
		.version = version,
		.dst = dst,
		.ipproto = protocol->ipproto,
		.spi = spi,
	};
	return said;

}

ip_said said_from_address_protocol_spi(const ip_address address,
				       const struct ip_protocol *protocol,
				       ipsec_spi_t spi)
{
	return said_from_raw(HERE, address.version, address.bytes,
			     protocol, spi);
}

bool said_is_unset(const ip_said *said)
{
	if (said == NULL) {
		return true;
	}
	return !said->is_set;
}

/*
 * convert SA to text "ah507@1.2.3.4"
 */

size_t jam_said(struct jambuf *buf, const ip_said *said)
{
	if (!said->is_set) {
		return jam_string(buf, "<unset-said>");
	}

	if (said->ipproto == ip_protocol_internal.ipproto) {
		switch (ntohl(said->spi)) {
		case SPI_PASS:
			return jam_string(buf, "%pass");
		case SPI_DROP:
			return jam_string(buf, "%drop");
		case SPI_REJECT:
			return jam_string(buf, "%reject");
		case SPI_HOLD:
			return jam_string(buf, "%hold");
		case SPI_TRAP:
			return jam_string(buf, "%trap");
		case SPI_IGNORE:
			return jam_string(buf, "%ignore");
		case SPI_TRAPSUBNET:
			return jam_string(buf, "%trapsubnet");
		default:
#if 0
			return jam(buf, "%s-"PRI_IPSEC_SPI, "%unk", pri_ipsec_spi(said->spi));
#else
			return jam(buf, "%s-%d", "%unk", ntohl(said->spi));
#endif
		}
	}

	const struct ip_info *afi = said_type(said);
	if (afi == NULL) {
		return jam(buf, "<said-has-no-type");
	}

	const ip_protocol *proto = protocol_by_ipproto(said->ipproto);

	if (proto == &ip_protocol_ipip/*TUN*/ &&
	    said->spi == PASSTHROUGHSPI &&
	    /* any zero */ thingeq(said->dst, unset_bytes)) {
		return jam_string(buf, (afi == &ipv4_info ? PASSTHROUGH4NAME :
					afi == &ipv6_info ? PASSTHROUGH6NAME :
					"<unknown-said-version>"));;
	}

	/* general case needed */
	size_t s = 0;
	s += jam_string(buf, proto->prefix != NULL ? proto->prefix : proto->name);
	/* .SPI */
	s += jam_char(buf, (afi == &ipv4_info ? '.' :
			    afi == &ipv6_info ? ':' :
			    '?'));
	s += jam(buf, "%x", ntohl(said->spi));;
	s += jam_char(buf, '@');
	s += afi->address.jam(buf, afi, &said->dst);
	return s;
}

const char *str_said(const ip_said *said, said_buf *buf)
{
	struct jambuf b = ARRAY_AS_JAMBUF(buf->buf);
	jam_said(&b, said);
	return buf->buf;
}

const struct ip_info *said_type(const ip_said *said)
{
	if (said == NULL) {
		return NULL;
	}

	/* may return NULL */
	return said_info(*said);
}

const struct ip_info *said_info(const ip_said said)
{
	if (!said.is_set) {
		return NULL;
	}

	/* may return NULL */
	return ip_version_info(said.version);
}

ip_address said_address(const ip_said said)
{
	const struct ip_info *afi = said_type(&said);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return unset_address; /* empty_address? */
	}

	return address_from_raw(HERE, said.version, said.dst);
}

const struct ip_protocol *said_protocol(const ip_said said)
{
	if (said_is_unset(&said)) {
		return NULL;
	}

	return protocol_by_ipproto(said.ipproto);
}
