/* ip cidr, for libreswan
 *
 * Copyright (C) 2019-2020 Andrew Cagney <cagney@gnu.org>
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
 */

#include "passert.h"
#include "jambuf.h"
#include "lswlog.h"

#include "ip_cidr.h"
#include "ip_info.h"

const ip_cidr unset_cidr;

ip_cidr cidr_from_raw(where_t where, enum ip_version version,
		      const struct ip_bytes bytes,
		      unsigned prefix_bits)
{

 	/* combine */
	ip_cidr cidr = {
		.is_set = true,
		.version = version,
		.bytes = bytes,
		.prefix_bits = prefix_bits,
	};
	pexpect_cidr(cidr, where);
	return cidr;
}

const struct ip_info *cidr_type(const ip_cidr *cidr)
{
	if (cidr == NULL) {
		return NULL;
	}

	/* may return NULL */
	return cidr_info(*cidr);
}

const struct ip_info *cidr_info(const ip_cidr cidr)
{
	if (!cidr.is_set) {
		return NULL;
	}

	/* may return NULL */
	return ip_version_info(cidr.version);
}

ip_address cidr_address(const ip_cidr cidr)
{
	const struct ip_info *afi = cidr_type(&cidr);
	if (afi == NULL) {
		return unset_address;
	}

	return address_from_raw(HERE, cidr.version, cidr.bytes);
}

err_t cidr_specified(const ip_cidr cidr)
{
	if (!cidr.is_set) {
		return "unset";
	}

	const struct ip_info *afi = cidr_type(&cidr);
	if (afi == NULL) {
		return "unknown address family";
	}

	/* https://en.wikipedia.org/wiki/IPv6_address#Special_addresses */
	/* ::/0 and/or 0.0.0.0/0 */
	if (cidr.prefix_bits == 0 && thingeq(cidr.bytes, unset_ip_bytes)) {
		return "default route (no specific route)";
	}

	if (thingeq(cidr.bytes, unset_ip_bytes)) {
		return "unspecified address";
	}

	return NULL;
}

bool cidr_is_specified(const ip_cidr cidr)
{
	return cidr_specified(cidr) == NULL;
}

err_t numeric_to_cidr(shunk_t src, const struct ip_info *afi, ip_cidr *cidr)
{
	*cidr = unset_cidr;
	err_t err;

	/* split CIDR into ADDRESS/MASK. */
	char slash;
	shunk_t address = shunk_token(&src, &slash, "/");
	shunk_t mask = src;
	if (slash == '\0') {
		return "missing mask";
	}
	if (mask.len == 0) {
		return "empty mask";
	}

	/* parse ADDRESS */
	ip_address addr;
	err = ttoaddress_num(address, afi/*possibly NULL */,
				 &addr);
	if (err != NULL) {
		return err;
	}
	/* Fix AFI, now that it is known */
	afi = address_type(&addr);
	passert(afi != NULL);

	/* parse MASK */
	uintmax_t maskbits = afi->mask_cnt;/*anything*/
	/* don't use bound - error is confusing */
	err = shunk_to_uintmax(mask, NULL, 0, &maskbits, 0);
	if (err != NULL) {
		/* not a number */
		return err;
	}
	if (maskbits > (uintmax_t)afi->mask_cnt) {
		return "mask is too big";
	}

	/* combine */
	*cidr = cidr_from_raw(HERE, addr.version, addr.bytes, maskbits);
	return NULL;
}

size_t jam_cidr(struct jambuf *buf, const ip_cidr *cidr)
{
	if (cidr == NULL) {
		return jam_string(buf, "<null-cidr>");
	}

	if (!cidr->is_set) {
		return jam_string(buf, "<unset-cidr>");
	}

	size_t s = 0;
	ip_address sa = cidr_address(*cidr);
	s += jam_address(buf, &sa); /* sensitive? */
	s += jam(buf, "/%u", cidr->prefix_bits);
	return s;
}

const char *str_cidr(const ip_cidr *cidr, cidr_buf *out)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(out->buf);
	jam_cidr(&buf, cidr);
	return out->buf;
}

void pexpect_cidr(const ip_cidr cidr, where_t where)
{
	if (cidr.is_set == false ||
	    cidr.version == 0) {
		llog_pexpect(&global_logger, where, "invalid "PRI_CIDR, pri_cidr(cidr));
	}
}
