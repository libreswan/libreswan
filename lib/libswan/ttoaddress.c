/*
 * conversion from text forms of addresses to internal ones
 *
 * Copyright (C) 2000  Henry Spencer.
 * Copyright (C) 2019-2021 Andrew Cagney <cagney@gnu.org>
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

#include <string.h>
#include <netdb.h>		/* for gethostbyname2() */

#include "ip_address.h"
#include "ip_info.h"
#include "lswalloc.h"		/* for alloc_things(), pfree() */
#include "lswlog.h"		/* for pexpect() */
#include "hunk.h"		/* for char_is_xdigit() */

static bool tryhex(shunk_t hex, ip_address *dst);
static err_t trydotted(shunk_t src, bool *was_numeric, ip_address *);
static err_t colon(shunk_t src, ip_address *);
static err_t getpiece(const char **, const char *, unsigned *);

/*
 * ttoaddr - convert text name or dotted-decimal address to binary
 * address.
 *
 * NULL for success, else string literal.  WAS_NUMERIC is true when
 * the the string is non-numeric.
 */

static err_t ttoaddr_base(shunk_t src,
			  const struct ip_info *afi,	/* address family; could be NULL */
			  bool *was_numeric,
			  ip_address *dst)
{
	*was_numeric = true;
	*dst = unset_address;

	if (src.len == 0) {
		return "empty string";
	}

	/*
	 * Hack to recognize a HEX IPv4 address; presumably DNS names
	 * can't start with a number so this can't be misinterpreted.
	 *
	 * If this fails, stumble on like nothing happened, letting
	 * the more typical code report an error.
	 */

	if (afi == &ipv4_info || afi == NULL) {
		if (tryhex(src, dst)) {
			return NULL;
		}
	}

	if (memchr(src.ptr, ':', src.len) != NULL) {
		if (afi == &ipv4_info) {
			return "IPv4 address may not contain `:'";
		}
		return colon(src, dst);
	}

	return trydotted(src, was_numeric, dst);
}

/*
 * tryname - try it as a name
 *
 * Error return is intricate because we cannot compose a static string.
 */
static err_t tryname(const char *p,
		     int af,
		     int suggested_af,	/* kind(s) of numeric addressing tried */
		     ip_address *dst)
{
	struct hostent *h = gethostbyname2(p, af);
	if (h != NULL) {
		if (h->h_addrtype != af) {
			return "address-type mismatch from gethostbyname2!!!";
		}

		return data_to_address(h->h_addr, h->h_length, aftoinfo(af), dst);
	}

	if (af == AF_INET6) {
		if (suggested_af == AF_INET6) {
			return "not a numeric IPv6 address and name lookup failed (no validation performed)";
		} else /* AF_UNSPEC */ {
			return "not a numeric IPv4 or IPv6 address and name lookup failed (no validation performed)";
		}
	}

	pexpect(af == AF_INET);

	/* like, windows even has an /etc/networks? */
	struct netent *ne = getnetbyname(p);
	if (ne == NULL) {
		/* intricate because we cannot compose a static string */
		if (suggested_af == AF_INET) {
			return "not a numeric IPv4 address and name lookup failed (no validation performed)";
		} else {
			return "not a numeric IPv4 or IPv6 address and name lookup failed (no validation performed)";
		}
	}

	if (ne->n_addrtype != af) {
		return "address-type mismatch from getnetbyname!!!";
	}

	/* apparently .n_net is in host order */
	struct in_addr in = { htonl(ne->n_net), };
	*dst = address_from_in_addr(&in);
	return NULL;
}

/*
 * tryhex - try conversion as an eight-digit hex number (AF_INET only)
 */

static bool tryhex(shunk_t hex,
		   ip_address *dst)
{
	if (hex.len != strlen("0x12345678")) {
		return false;
	}

	if (!shunk_strcaseeat(&hex, "0x")) {
		return false;
	}

	uintmax_t ul;
	err_t err = shunk_to_uintmax(hex, NULL, 16, &ul, UINT32_MAX);
	if (err != NULL) {
		return false;
	}

	struct in_addr addr = { htonl(ul), };
	*dst = address_from_in_addr(&addr);
	return true;
}

/*
 * trydotted - try conversion as dotted numeric (AF_INET only).
 *
 * But could a DNS name also be a valid IPv4 address, vis:
 * - can start with a decimal-digit
 * - can end with a decimal-digit
 * - must contain at least one letter
 * https://tools.ietf.org/html/rfc1912
 *
 * Yes, for instance: 0x01.0x02.0x03.0x04.
 *
 * This code tries to avoid this pitfall by only allowing non-decimal
 * fields when they match a very limited format.
 */

static err_t trydotted(shunk_t src, bool *was_numeric, ip_address *dst)
{
	struct ip_bytes bytes = unset_bytes;

	shunk_t cursor = src;
	for (unsigned b = 0; b < 4 && cursor.ptr != NULL /* more-input */; b++) {
		/* Danger: nested breaks and returns. */

		/*
		 * Carve off the next number.
		 *
		 * This way, given "09.1.2.", the full sub-string "09"
		 * is extracted and converted.  Being invalid, it will
		 * report an error about a bogus digit (and not the
		 * less meaningful trailing garbage error).
		 *
		 * After the last token has been extracted cursor is
		 * left pointing at NULL i.e., cursor.ptr==NULL.
		 */
		shunk_t token = shunk_token(&cursor, NULL, ".");
		if (token.len == 0) {
			/* ex: 0xa. */
			*was_numeric = false;
			return "empty dotted-numeric address field";
		}
#if 0
		fprintf(stderr, "cursor="PRI_SHUNK" token="PRI_SHUNK"\n",
			pri_shunk(cursor), pri_shunk(token));
#endif

		/*
		 * Try converting to a number.
		 *
		 * See examples in wikepedia.
		 *
		 * This lets uintmax decide how to convert the number
		 * (play with wget).
		 *
		 * The alternative is to do a very strict check.
                 */
#if 0
		unsigned base;
		if (token.len == strlen("0xXX") && shunk_strcaseeat(&token, "0x")) {
			base = 16;
		} else if (token.len == strlen("0ooo") && shunk_strcaseeat(&token, "0")) {
			base = 8;
		} else {
			base = 10;
		}
		if (hunk_strcasestarteq(token, "0") && token.len == strlen("0xXX")) {
			base = 16;
		}
		uintmax_t byte;
		err_t err = shunk_to_uintmax(token, NULL, base, &byte, 0/*no-celing*/);
#else
		uintmax_t byte;
		err_t err = shunk_to_uintmax(token, NULL, 0, &byte, 0/*no-celing*/);
#endif
		if (err != NULL) {
			*was_numeric = false;
			return err;
		}

		/*
		 * The last byte overflows into earlier unfilled
		 * bytes.  For instance:
		 *
		 *   127.1     -> 127.0.0.1
		 *   127.65534 -> 127.0.255.254
		 *
		 * A bizare hangover from address classes:
		 * https://en.wikipedia.org/wiki/IPv4#Address_representations
		 *
		 * Now while it is arguable that:
		 *
		 *   65534 -> 0.0.255.254
		 *   127   -> 0.0.0.127 !?!?!
		 *
		 * is also valid, that is too weird and rejected (but
		 * 0x01020304 is accepted by an earlier call to
		 * tryhex()).
		 */
		if (cursor.len == 0 && b > 0) {
			for (unsigned e = 3; e >= b && byte != 0; e--) {
				bytes.byte[e] = byte; /* truncate */
				byte = byte >> 8;
			}
			if (byte != 0) {
				return "overflow in dotted-numeric address";
			}
			break;
		}

		/* A non-last bytes need to fit into the byte */
		if (byte > UINT8_MAX) {
			return "byte overflow in dotted-numeric address";
		}

		bytes.byte[b] = byte;
	}
	if (cursor.ptr != NULL) {
		*was_numeric = false;
		return "garbage at end of dotted-address";
	}

	*dst = address_from_raw(HERE, ipv4_info.ip_version, bytes);
	return NULL;
}

/*
 * colon - convert IPv6 "numeric" address
 */

static err_t colon(shunk_t cursor, ip_address *dst)
{
	const char *src = cursor.ptr;
	unsigned srclen = cursor.len;
	const char *stop = src + srclen;	/* just past end */
	unsigned piece;
	int gapat;	/* where was empty piece seen */
	err_t oops;
#       define  NPIECES 8
	struct ip_bytes u = unset_bytes;
	int i;
	int j;
#       define  IT      "IPv6 numeric address"
	int naftergap;

	/* leading or trailing :: becomes single empty field */
	if (*src == ':') {	/* legal only if leading :: */
		if (srclen == 1 || *(src + 1) != ':')
			return "illegal leading `:' in " IT;

		if (srclen == 2) {
			*dst = ipv6_info.address.any;
			return NULL;
		}
		src++;	/* past first but not second */
		srclen--;
	}
	if (*(stop - 1) == ':') {	/* legal only if trailing :: */
		if (srclen == 1 || *(stop - 2) != ':')
			return "illegal trailing `:' in " IT;

		srclen--;	/* leave one */
	}

	gapat = -1;
	piece = 0;
	for (i = 0; i < NPIECES && src < stop; i++) {
		oops = getpiece(&src, stop, &piece);
		if (oops != NULL && *oops == ':') {	/* empty field */
			if (gapat >= 0)
				return "more than one :: in " IT;

			gapat = i;
		} else if (oops != NULL) {
			return oops;
		}
		u.byte[2 * i] = piece >> 8;
		u.byte[2 * i + 1] = piece & 0xff;
		if (i < NPIECES - 1) {	/* there should be more input */
			if (src == stop && gapat < 0)
				return IT " ends prematurely";

			if (src != stop && *src++ != ':')
				return "syntax error in " IT;
		}
	}
	if (src != stop)
		return "extra garbage on end of " IT;

	if (gapat < 0 && i < NPIECES)	/* should have been caught earlier */
		return "incomplete " IT " (internal error)";

	if (gapat >= 0 && i == NPIECES)
		return "non-abbreviating empty field in " IT;

	if (gapat >= 0) {
		naftergap = i - (gapat + 1);
		for (i--, j = NPIECES - 1; naftergap > 0;
			i--, j--, naftergap--) {
			u.byte[2 * j] = u.byte[2 * i];
			u.byte[2 * j + 1] = u.byte[2 * i + 1];
		}
		for (; j >= gapat; j--)
			u.byte[2 * j] = u.byte[2 * j + 1] = 0;
	}

	*dst = address_from_raw(HERE, ipv6_info.ip_version, u);
	return NULL;
}

/*
 * getpiece - try to scan one 16-bit piece of an IPv6 address
 *
 * ":" means "empty field seen"
 */
err_t getpiece(const char **srcp,	/* *srcp is updated */
	       const char *stop,	/* first untouchable char */
	       unsigned *retp)	/* return-value pointer */
{
	const char *p;
#       define  NDIG    4
	int d;
	unsigned long ret;
	err_t oops;

	if (*srcp >= stop || **srcp == ':') {	/* empty field */
		*retp = 0;
		return ":";
	}

	p = *srcp;
	d = 0;
	while (p < stop && d < NDIG && char_isxdigit(*p)) {
		p++;
		d++;
	}
	if (d == 0)
		return "non-hex field in IPv6 numeric address";

	if (p < stop && d == NDIG && char_isxdigit(*p))
		return "field in IPv6 numeric address longer than 4 hex digits";

	oops = ttoul(*srcp, d, 16, &ret);
	if (oops != NULL)	/* shouldn't happen, really... */
		return oops;

	*srcp = p;
	*retp = ret;
	return NULL;
}

err_t ttoaddress_dns(shunk_t src, const struct ip_info *afi, ip_address *dst)
{
	*dst = unset_address;
	if (src.len == 0) {
		return "empty string";
	}

	bool was_numeric = true;
	err_t err = ttoaddr_base(src, afi, &was_numeric, dst);
	if (was_numeric) {
		/* no-point in continuing */
		return err;
	}

	/* err == non-numeric */

	for (const char *cp = src.ptr, *end = cp + src.len; cp < end; cp++) {
		/*
		 * Legal ASCII characters in a domain name.
		 * Underscore technically is not, but is a common
		 * misunderstanding.  Non-ASCII characters are simply
		 * exempted from checking at the moment, to allow for
		 * UTF-8 encoded stuff; the purpose of this check is
		 * merely to catch blatant errors.
		 *
		 * XXX: Suspect the ISASCII() check can be dropped -
		 * utf-8 isn't allowed in DNS names and without a
		 * utf-8 parser the check is flawed.
		 */
		static const char namechars[] =
			"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_.";
#define ISASCII(c) (((c) & 0x80) == 0)
		if (ISASCII(*cp) && strchr(namechars, *cp) == NULL) {
			return "illegal (non-DNS-name) character in name";
		}
	}

	/*
	 * need a guarenteed null terminated string
	 */
	char *name = clone_hunk_as_string(src, "ttoaddress_dns"); /* must free */
	int suggested_af = afi == NULL ? AF_UNSPEC : afi->af;
	err_t v4err = NULL, v6err = NULL;
	if (err && (suggested_af == AF_UNSPEC || suggested_af == AF_INET)) {
		err = v4err = tryname(name, AF_INET, suggested_af, dst);
	}
	if (err && (suggested_af == AF_UNSPEC || suggested_af == AF_INET6)) {
		err = v6err = tryname(name, AF_INET6, suggested_af, dst);
	}
	/* prefer the IPv4 error */
	if (err != NULL && v4err != NULL) {
		err = v4err;
	}
	pfree(name);
	return err;
}

err_t ttoaddress_num(shunk_t src, const struct ip_info *afi, ip_address *dst)
{
	bool was_numeric; /* ignored */
	return ttoaddr_base(src, afi, &was_numeric, dst);
}
