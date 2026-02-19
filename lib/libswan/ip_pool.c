/* ip_pool type, for libreswan
 *
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2000 Henry Spencer.
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
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
 */

/*
 * convert from text form of IP address pool specification to binary;
 * and more minor utilities for mask length calculations for IKEv2
 */

#include <string.h>
#include <arpa/inet.h>		/* for ntohl() */

#include "jambuf.h"
#include "ip_pool.h"
#include "ip_info.h"
#include "passert.h"
#include "lswlog.h"		/* for pexpect() */

const ip_pool unset_pool; /* all zeros */

ip_pool pool_from_raw(where_t where, const struct ip_info *afi,
			const struct ip_bytes lo,
			const struct ip_bytes hi,
			unsigned subprefix)
{
	ip_pool r = {
		.ip.is_set = true,
		.ip.version = afi->ip.version,
		.lo = lo,
		.hi = hi,
		.subprefix = subprefix,
	};
	pexpect_pool(&r, where);
	return r;
}

/*
 * Calculate the number of significant bits in the size of the pool.
 * floor(lg(|high-low| + 1)); or -1.
 */

int pool_prefix_len(const ip_pool pool)
{
	const struct ip_info *afi = pool_info(pool);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return -1;
	}

	return ip_bytes_prefix_len(afi, pool.lo, pool.hi);
}

int pool_host_len(const ip_pool pool)
{
	const struct ip_info *afi = pool_info(pool);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return -1;
	}

	return ip_bytes_host_len(afi, pool.lo, pool.hi);
}

size_t jam_pool(struct jambuf *buf, const ip_pool *pool)
{
	const struct ip_info *afi;
	size_t s = jam_invalid_ip(buf, "pool", pool, &afi);
	if (s > 0) {
		return s;
	}

	s += jam_ip_bytes_range(buf, afi, pool->lo, pool->hi);
	if (pool->subprefix != afi->mask_cnt) {
		s += jam(buf, "/%u", pool->subprefix);
	}

	return s;
}

const char *str_pool(const ip_pool *pool, pool_buf *out)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(out->buf);
	jam_pool(&buf, pool);
	return out->buf;
}

ip_pool pool_from_address(const ip_address address)
{
	const struct ip_info *afi = address_info(address);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return unset_pool;
	}

	return pool_from_raw(HERE, afi,
			      address.bytes, address.bytes,
			      afi->mask_cnt);
}

ip_pool pool_from_cidr(const ip_cidr cidr)
{
	const struct ip_info *afi = cidr_info(cidr);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return unset_pool;
	}

	return pool_from_raw(HERE, afi,
			      ip_bytes_blit(afi, cidr.bytes,
					    &keep_routing_prefix,
					    &clear_host_identifier,
					    cidr.prefix_len),
			      ip_bytes_blit(afi, cidr.bytes,
					    &keep_routing_prefix,
					    &set_host_identifier,
					    cidr.prefix_len),
			      afi->mask_cnt);
}

ip_pool pool_from_subnet(const ip_subnet subnet)
{
	const struct ip_info *afi = subnet_info(subnet);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return unset_pool;
	}

	return pool_from_raw(HERE, afi,
			      ip_bytes_blit(afi, subnet.bytes,
					    &keep_routing_prefix,
					    &clear_host_identifier,
					    subnet.maskbits),
			      ip_bytes_blit(afi, subnet.bytes,
					    &keep_routing_prefix,
					    &set_host_identifier,
					    subnet.maskbits),
			      afi->mask_cnt);
}

ip_pool pool_from_range(const ip_range range)
{
	const struct ip_info *afi = range_info(range);
	if (afi == NULL) {
		/* NULL+unset+unknown */
		return unset_pool;
	}

	return pool_from_raw(HERE, afi,
			     range.lo, range.hi,
			     afi->mask_cnt);
}

const struct ip_info *pool_type(const ip_pool *pool)
{
	/* may return NULL */
	return ip_type(pool);
}

const struct ip_info *pool_info(const ip_pool pool)
{
	/* may return NULL */
	return ip_info(pool);
}

bool pool_is_unset(const ip_pool *pool)
{
	return ip_is_unset(pool);
}

bool pool_is_zero(const ip_pool pool)
{
	const struct ip_info *afi = pool_info(pool);
	if (afi == NULL) {
		return false;
	}

	return pool_eq_pool(pool, afi->pool.zero);
}

bool pool_is_all(const ip_pool pool)
{
	const struct ip_info *afi = pool_info(pool);
	if (afi == NULL) {
		return false;
	}

	return pool_eq_pool(pool, afi->pool.all);
}

bool pool_is_cidr(ip_pool pool)
{
	const struct ip_info *afi = pool_info(pool);
	if (afi == NULL) {
		return false;
	}

	return ip_bytes_prefix_len(afi, pool.lo, pool.hi) >= 0;
}

uintmax_t pool_size(const ip_pool pool)
{
	const struct ip_info *afi = pool_info(pool);
	if (afi == NULL) {
		return 0;
	}

	struct ip_bytes diff_bytes = {0};
	err_t e = ip_bytes_sub(afi, &diff_bytes, pool.hi, pool.lo);
	if (e != NULL) {
		return UINTMAX_MAX;
	}

	/* more than uintmax_t-bits of host-prefix always overflows. */
	unsigned prefix_bits = ip_bytes_first_set_bit(afi, diff_bytes);
	unsigned host_bits = afi->mask_cnt - prefix_bits;
	if (host_bits > sizeof(uintmax_t) * 8) {
		return UINTMAX_MAX;
	}

	/*
	 * can't overflow; but could be 0xf..f and adding one will
	 * overflow
	 */
	uintmax_t diff = raw_ntoh(diff_bytes.byte, afi->ip_size);
	if (diff >= UINTMAX_MAX) {
		/* size+1 would overflow */
		return UINTMAX_MAX;
	}

	return diff + 1;
}

bool pool_eq_address(const ip_pool pool, const ip_address address)
{
	ip_pool address_pool = pool_from_address(address);
	return pool_eq_pool(pool, address_pool);
}

bool pool_eq_subnet(const ip_pool pool, const ip_subnet subnet)
{
	ip_pool subnet_pool = pool_from_subnet(subnet);
	return pool_eq_pool(pool, subnet_pool);
}

bool pool_eq_pool(const ip_pool l, const ip_pool r)
{
	if (pool_is_unset(&l) && pool_is_unset(&r)) {
		/* unset/NULL pools are equal */
		return true;
	}
	if (pool_is_unset(&l) || pool_is_unset(&r)) {
		return false;
	}

	return (ip_bytes_cmp(l.ip.version, l.lo,
			     r.ip.version, r.lo) == 0 &&
		ip_bytes_cmp(l.ip.version, l.hi,
			     r.ip.version, r.hi) == 0);
}

bool address_in_pool(const ip_address address, const ip_pool pool)
{
	ip_pool address_pool = pool_from_address(address);
	return pool_in_pool(address_pool, pool);
}

bool cidr_in_pool(const ip_cidr cidr, const ip_pool pool)
{
	ip_pool cidr_pool = pool_from_cidr(cidr);
	return pool_in_pool(cidr_pool, pool);
}

bool subnet_in_pool(const ip_subnet subnet, const ip_pool pool)
{
	ip_pool subnet_pool = pool_from_subnet(subnet);
	return pool_in_pool(subnet_pool, pool);
}

bool pool_in_pool(const ip_pool inner, const ip_pool outer)
{
	if (pool_is_unset(&inner) || pool_is_unset(&outer)) {
		return false;
	}

	return (ip_bytes_cmp(inner.ip.version, inner.lo,
			     outer.ip.version, outer.lo) >= 0 &&
		ip_bytes_cmp(inner.ip.version, inner.hi,
			     outer.ip.version, outer.hi) <= 0);
}

ip_address pool_start(const ip_pool pool)
{
	const struct ip_info *afi = pool_info(pool);
	if (afi == NULL) {
		return unset_address;
	}

	return address_from_raw(HERE, afi, pool.lo);
}

ip_address pool_end(const ip_pool pool)
{
	const struct ip_info *afi = pool_info(pool);
	if (afi == NULL) {
		return unset_address;
	}

	return address_from_raw(HERE, afi, pool.hi);
}

bool pool_overlaps_pool(const ip_pool l, const ip_pool r)
{
	if (pool_is_unset(&l) || pool_is_unset(&r)) {
		/* presumably overlap is bad */
		return false;
	}

	/* l before r */
	if (ip_bytes_cmp(l.ip.version, l.hi,
			 r.ip.version, r.lo) < 0) {
		return false;
	}
	/* l after r */
	if (ip_bytes_cmp(l.ip.version, l.lo,
			 r.ip.version, r.hi) > 0) {
		return false;
	}

	return true;
}

err_t addresses_to_nonzero_pool(const ip_address lo, const ip_address hi, ip_pool *dst)
{
	*dst = unset_pool;

	const struct ip_info *lo_afi = address_info(lo);
	if (lo_afi == NULL) {
		/* NULL+unset+unknown */
		return "start address invalid";
	}

	const struct ip_info *hi_afi = address_info(hi);
	if (hi_afi == NULL) {
		/* NULL+unset+unknown */
		return "end address invalid";
	}

	if (lo_afi != hi_afi) {
		return "conflicting address types";
	}

	/* reject both 0 */
	if (thingeq(lo.bytes, unset_ip_bytes) &&
	    thingeq(hi.bytes, unset_ip_bytes)) {
		return "zero address pool";
	}

	if (addrcmp(&lo, &hi) > 0) {
		return "out-of-order";
	}

	*dst = pool_from_raw(HERE, lo_afi,
			      lo.bytes, hi.bytes,
			      lo_afi->mask_cnt);
	return NULL;
}

err_t pool_to_subnet(const ip_pool pool, ip_subnet *dst)
{
	*dst = unset_subnet;
	const struct ip_info *afi = pool_info(pool);
	if (afi == NULL) {
		return "invalid pool";
	}

	/*
	 * Determine the prefix_bits (the CIDR network part) by
	 * matching leading bits of FROM and TO.  Trailing bits
	 * (subnet address) must be either all 0 (from) or 1 (to).
	 */
	int prefix_bits = ip_bytes_prefix_len(afi, pool.lo, pool.hi);
	if (prefix_bits < 0) {
		return "address pool is not a subnet";
	}

	*dst = subnet_from_raw(HERE, afi, pool.lo, prefix_bits);
	return NULL;
}

err_t pool_offset_to_cidr(const ip_pool pool,
			   uintmax_t offset,
			   ip_cidr *cidr_out)
{
	err_t e;
	*cidr_out = unset_cidr;

	const struct ip_info *afi = pool_info(pool);
	if (afi == NULL) {
		return "invalid pool";
	}

	struct ip_bytes ip_offset;
	e = uintmax_to_ip_bytes(afi, pool.subprefix, offset, &ip_offset);
	if (e != NULL) {
		return e;
	}

	struct ip_bytes sum = {0};
	e = ip_bytes_add(afi, &sum, pool.lo, ip_offset);
	if (e != NULL) {
		return e;
	}

	ip_cidr cidr = cidr_from_raw(HERE, afi, sum, pool.subprefix);
	if (!cidr_in_pool(cidr, pool)) {
		return "pool overflow";
	}

	*cidr_out = cidr;
	return NULL;
}

err_t cidr_to_pool_offset(const ip_pool pool, const ip_cidr cidr, uintmax_t *offset)
{
	err_t e;
	*offset = UINTMAX_MAX;

	const struct ip_info *afi = pool_info(pool);
	if (afi == NULL) {
		return "pool invalid";
	}

	if (cidr_info(cidr) != afi) {
		return "address is not from pool";
	}

	if (!cidr_in_pool(cidr, pool)) {
		return "address out-of-bounds";
	}

	struct ip_bytes diff = {0};
	e = ip_bytes_sub(afi, &diff, cidr.bytes, pool.lo);
	if (e != NULL) {
		return e;
	}

	e = ip_bytes_to_uintmax(afi, pool.subprefix, diff, offset);
	if (e != NULL) {
		return e;
	}

	return NULL;
}

void pexpect_pool(const ip_pool *r, where_t where)
{
	if (r == NULL) {
		return;
	}

	/* more strict than is_unset() */
	if (pool_eq_pool(*r, unset_pool)) {
		return;
	}

	if (r->ip.is_set == false ||
	    r->ip.version == 0 ||
	    ip_bytes_cmp(r->ip.version, r->lo, r->ip.version, r->hi) > 0) {
		llog_pexpect(&global_logger, where, "invalid pool: "PRI_POOL, pri_pool(r));
	}
}
