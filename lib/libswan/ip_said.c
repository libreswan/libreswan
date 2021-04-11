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

#include "lswlog.h"	/* for bad_case() */

ip_said said3(const ip_address *address, ipsec_spi_t spi,
	      const struct ip_protocol *proto)
{
	ip_said said = {
		.dst = *address,
		.spi = spi,
		.proto = proto,
	};
	return said;
}


/*
 * convert SA to text "ah507@1.2.3.4"
 */

void jam_said(struct jambuf *buf, const ip_said *sa)
{
	const struct ip_protocol *proto = sa->proto;
	const char *pre = (proto == NULL ? "unk" : proto->prefix);

	if (strcmp(pre, PASSTHROUGHTYPE) == 0 &&
	    sa->spi == PASSTHROUGHSPI &&
	    (address_is_unset(&sa->dst) /*short-circuit*/||
	     address_is_any(sa->dst))) {
		jam_string(buf, (said_type(sa) == &ipv4_info ?
				 PASSTHROUGH4NAME :
				 PASSTHROUGH6NAME));
	} else if (sa->proto == &ip_protocol_internal) {
		switch (ntohl(sa->spi)) {
		case SPI_PASS:
			jam_string(buf, "%pass");
			break;
		case SPI_DROP:
			jam_string(buf, "%drop");
			break;
		case SPI_REJECT:
			jam_string(buf, "%reject");
			break;
		case SPI_HOLD:
			jam_string(buf, "%hold");
			break;
		case SPI_TRAP:
			jam_string(buf, "%trap");
			break;
		case SPI_TRAPSUBNET:
			jam_string(buf, "%trapsubnet");
			break;
		default:
			jam(buf, "%s-%d", "%unk", ntohl(sa->spi));
			break;
		}
	} else {
		/* general case needed */
		jam_string(buf, pre);
		/* .SPI */
		jam_char(buf, (said_type(sa) == &ipv4_info ? '.' : ':'));
		jam(buf, "%x", ntohl(sa->spi));;
		jam_char(buf, '@');
		jam_address(buf, &sa->dst);
	}
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
	return ip_version_info(said->dst.version);
}

ip_address said_address(const ip_said *said)
{
	return said->dst;
}
