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

/*
 * Unit testing is available through
 *   OBJ.$WHATEVER/testing/programs/ipcheck/ipcheck
 * This does not require KVM and is built by "make base".
 */

#include "ip_address.h"
#include "ip_info.h"

static bool tryhex(shunk_t hex, ip_address *dst);
static err_t trydotted(shunk_t src, ip_address *);
static err_t colon(shunk_t src, ip_address *);

/*
 * ttoaddress_num - convert "numeric" IP address to binary address.
 *
 * NULL for success, else static string literal diagnostic.
 */

err_t ttoaddress_num(shunk_t src, const struct ip_info *afi, ip_address *dst)
{
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

	if (afi == &ipv4_info) {
		if (tryhex(src, dst)) {
			return NULL;
		}
		return trydotted(src, dst);
	}

	if (afi == &ipv6_info) {
		return colon(src, dst);
	}

	if (afi == NULL) {
		if (tryhex(src, dst)) {
			return NULL;
		}
		if (memchr(src.ptr, ':', src.len) != NULL) {
			return colon(src, dst);
		}
		return trydotted(src, dst);
	}

	return "address family unknown";
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

	if (!hunk_strcaseeat(&hex, "0x")) {
		return false;
	}

	uintmax_t ul;
	err_t err = shunk_to_uintmax(hex, NULL, 16, &ul);
	if (err != NULL) {
		return false;
	}
	if (ul > UINT32_MAX) {
		return false; /* IPv4 is 32-bit */
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

static err_t trydotted(shunk_t src, ip_address *dst)
{
	struct ip_bytes bytes = unset_ip_bytes;

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
		err_t err = shunk_to_uintmax(token, NULL, base, &byte);
#else
		uintmax_t byte;
		err_t err = shunk_to_uintmax(token, NULL, 0, &byte);
#endif
		if (err != NULL) {
			return err;
		}

		/*
		 * The last byte overflows into earlier unfilled
		 * bytes.  For instance:
		 *
		 *   127.1     -> 127.0.0.1
		 *   127.65534 -> 127.0.255.254
		 *
		 * A bizarre hangover from address classes:
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
		return "garbage at end of dotted-address";
	}

	*dst = address_from_raw(HERE, &ipv4_info, bytes);
	return NULL;
}

/*
 * colon - convert IPv6 "numeric" address
 */

static err_t colon(shunk_t src, ip_address *dst)
{
	shunk_t cursor = src;
	struct ip_bytes u = unset_ip_bytes;
#       define  IT      "IPv6 numeric address"

	int gapat = -1;	/* where was empty piece seen */
	unsigned colon_count = 0;
	unsigned i = 0;
	/* while there is more to parse and room for a pair of octets ... */
	while (cursor.len > 0 && i <= sizeof(u.byte) - 2) {

		/* all paths needs to make progress or return */

		if (hunk_strcaseeat(&cursor, ":")) {
			colon_count++;
			if (colon_count > 2) {
				return "::: in " IT;
			}
			if (colon_count == 2) {
				if (gapat >= 0) {
					return "more than one :: in " IT;
				}
				gapat = i;
			}
		} else if (colon_count == 1 && i == 0) {
			return "single leading `:' in " IT;
		} else {

			/* parsing: NNNN[:...] */
			colon_count = 0;
			uintmax_t value;
			err_t oops = shunk_to_uintmax(cursor, &cursor, 16, &value);
			if (oops != NULL) {
				return oops;
			}
			if (value > 65535) {
				return "too large";
			}

			/* network order */
			u.byte[i++] = value >> 8;
			u.byte[i++] = value & 0xff;
		}
	}

	if (cursor.len != 0 && hunk_char(cursor, 0) == ':') {
		/* special, common case */
		return "trailing `:' in " IT;
	}

	if (cursor.len != 0) {
		return "extra garbage on end of " IT;
	}

	if (gapat < 0 && i < sizeof(u.byte)) {
		return "incomplete " IT;
	}

	if (gapat >= 0 && i == sizeof(u.byte)) {
		return "non-abbreviating empty field in " IT;
	}

	/* shift bytes; fill gap with zeros */
	if (gapat >= 0) {
		int gap = sizeof(u.byte) - i; /* short by ... */
		/* use memmove(); there definitely an overlap! */
		memmove(&u.byte[gapat + gap], &u.byte[gapat], i - gapat);
		memset(&u.byte[gapat], '\0', gap);
	}

	*dst = address_from_raw(HERE, &ipv6_info, u);
	return NULL;
}
