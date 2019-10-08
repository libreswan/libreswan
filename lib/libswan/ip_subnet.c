/* ip subnet, for libreswan
 *
 * Copyright (C) 2012-2017 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 1998-2002,2015  D. Hugh Redelmeier.
 * Copyright (C) 2016-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
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

#include "jambuf.h"
#include "ip_subnet.h"
#include "libreswan/passert.h"
#include "lswlog.h"	/* for pexpect() */
#include "ip_info.h"

const ip_subnet subnet_invalid; /* all zeros */

static ip_subnet subnet3(const ip_address *address, int maskbits, int port)
{
	ip_endpoint e = endpoint(address, port);
	ip_subnet s = {
		.addr = e,
		.maskbits = maskbits,
	};
	return s;
}

#ifdef SUBNET_TYPE
static ip_subnet subnet4(const ip_address *lo_address, const ip_address *hi_address,
			 int lo_hport, int hi_hport)
{
	ip_subnet s = {
		.lo_address = *lo_address,
		.hi_address = *hi_address,
		.lo_port = lo_port,
		.hi_port = hi_port,
	};
}
#endif

ip_subnet subnet_from_address(const ip_address *address)
{
	const struct ip_info *afi = address_type(address);
	if (!pexpect(afi != NULL)) {
		return subnet_invalid;
	}
	return subnet3(address, afi->mask_cnt, 0);
}

ip_subnet subnet_from_endpoint(const ip_endpoint *endpoint)
{
	const struct ip_info *afi = endpoint_type(endpoint);
	if (!pexpect(afi != NULL)) {
		return subnet_invalid;
	}
	ip_address address = endpoint_address(endpoint);
	int hport = endpoint_hport(endpoint);
	pexpect(hport != 0);
	return subnet3(&address, afi->mask_cnt, hport);
}

ip_address subnet_prefix(const ip_subnet *src)
{
	return subnet_blit(src,
			   /*routing-prefix*/&keep_bits,
			   /*host-id*/&clear_bits);
}

const struct ip_info *subnet_type(const ip_subnet *src)
{
	return endpoint_type(&src->addr);
}

int subnet_hport(const ip_subnet *s)
{
#ifdef SUBNET_TYPE
	const struct ip_info *afi = subnet_type(s);
	if (afi == NULL) {
		/* not asserting, who knows what nonsense a user can generate */
		libreswan_log("%s has unspecified type", __func__);
		return -1;
	}
	return s->hport;
#else
	return endpoint_hport(&s->addr);
#endif
}

int subnet_nport(const ip_subnet *s)
{
#ifdef SUBNET_TYPE
	const struct ip_info *afi = subnet_type(s);
	if (afi == NULL) {
		/* not asserting, who knows what nonsense a user can generate */
		libreswan_log("%s has unspecified type", __func__);
		return -1;
	}
	return htons(s->hport);
#else
	return endpoint_nport(&s->addr);
#endif
}

ip_subnet set_subnet_hport(const ip_subnet *subnet, int hport)
{
	ip_subnet s = *subnet;
#ifdef SUBNET_TYPE
	s.port = hport;
#else
	s.addr = set_endpoint_hport(&subnet->addr, hport);
#endif
	return s;
}

bool subnet_is_specified(const ip_subnet *s)
{
	return endpoint_is_specified(&s->addr);
}

bool subnet_contains_all_addresses(const ip_subnet *s)
{
	const struct ip_info *afi = subnet_type(s);
	if (!pexpect(afi != NULL) ||
	    s->maskbits != 0) {
		return false;
	}
	ip_address network = subnet_prefix(s);
	return (address_is_any(&network)
		&& subnet_hport(s) == 0);
}

bool subnet_contains_no_addresses(const ip_subnet *s)
{
	const struct ip_info *afi = subnet_type(s);
	if (!pexpect(afi != NULL) ||
	    s->maskbits != afi->mask_cnt) {
		return false;
	}
	ip_address network = subnet_prefix(s);
	return (address_is_any(&network)
		&& subnet_hport(s) == 0);
}

/*
 * mashup() notes:
 * - mashup operates on network-order IP addresses
 */

struct ip_blit {
	uint8_t and;
	uint8_t or;
};

const struct ip_blit clear_bits = { .and = 0x00, .or = 0x00, };
const struct ip_blit set_bits = { .and = 0x00/*don't care*/, .or = 0xff, };
const struct ip_blit keep_bits = { .and = 0xff, .or = 0x00, };

ip_address subnet_blit(const ip_subnet *src,
			  const struct ip_blit *prefix,
			  const struct ip_blit *host)
{
	/* strip port; copy type */
	ip_address mask = endpoint_address(&src->addr);
	chunk_t raw = address_as_chunk(&mask);

	if (!pexpect((size_t)src->maskbits <= raw.len * 8)) {
		return address_invalid;	/* "can't happen" */
	}

	uint8_t *p = raw.ptr; /* cast void* */

	/* the cross over byte */
	size_t xbyte = src->maskbits / BITS_PER_BYTE;
	unsigned xbit = src->maskbits % BITS_PER_BYTE;

	/* leading bytes: & PREFIX->AND | PREFIX->OR */
	unsigned b = 0;
	for (; b < xbyte; b++) {
		p[b] &= prefix->and;
		p[b] |= prefix->or;
	}

	/*
	 * cross over: & {PREFIX,HOST}_AND | {PREFIX,HOST}_OR
	 *
	 * tricky logic:
	 * - b == xbyte
	 * - if xbyte == raw.len we must not access p[xbyte]
	 * - if xbyte == raw.len, xbit will be 0
	 * - if xbit == 0, the loop for trailing bytes will
	 *   perform the required operation slightly more efficiently
	 * So we guard this step with xbit != 0 instead of b < raw.len
	 */
	if (xbit != 0) {
		uint8_t hmask = 0xFF >> xbit;
		p[b] &= (prefix->and & ~hmask) | (host->and & hmask);
		p[b] |= (prefix->or & ~hmask) | (host->or & hmask);
		b++;
	}

	/* trailing bytes: & HOST->AND | HOST->OR */
	for (; b < raw.len; b++) {
		p[b] &= host->and;
		p[b] |= host->or;
	}

	return mask;
}

/*
 * subnet mask - get the mask of a subnet, as an address
 *
 * For instance 1.2.3.4/24 -> 255.255.255.0.
 */

ip_address subnet_mask(const ip_subnet *src)
{
	return subnet_blit(src, /*prefix*/ &set_bits, /*host*/ &clear_bits);
}

void jam_subnet(jambuf_t *buf, const ip_subnet *subnet)
{
	jam_address(buf, &subnet->addr); /* sensitive? */
	jam(buf, "/%u", subnet->maskbits);
}

const char *str_subnet(const ip_subnet *subnet, subnet_buf *out)
{
	jambuf_t buf = ARRAY_AS_JAMBUF(out->buf);
	jam_subnet(&buf, subnet);
	return out->buf;
}

void jam_subnet_port(jambuf_t *buf, const ip_subnet *subnet)
{
	jam_address(buf, &subnet->addr); /* sensitive? */
	jam(buf, "/%u", subnet->maskbits);
	int port = subnet_hport(subnet);
	if (port >= 0) {
		jam(buf, ":%d", port);
	}
}

const char *str_subnet_port(const ip_subnet *subnet, subnet_buf *out)
{
	jambuf_t buf = ARRAY_AS_JAMBUF(out->buf);
	jam_subnet_port(&buf, subnet);
	return out->buf;
}
