/* Output raw bytes, for libreswan
 *
 * Copyright (C) 2017, 2019 Andrew Cagney
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
 *
 */


#include "jambuf.h"

size_t jam_hex_bytes(struct jambuf *buf, const void *ptr, size_t size)
{
	size_t n = 0;
	const uint8_t *bytes = ptr;
	for (unsigned i = 0; i < size; i++) {
		uint8_t b = bytes[i];
		n += jam(buf, "%02x", b);
	}
	return n;
}

size_t jam_HEX_bytes(struct jambuf *buf, const void *ptr, size_t size)
{
	size_t n = 0;
	const uint8_t *bytes = ptr;
	for (unsigned i = 0; i < size; i++) {
		uint8_t b = bytes[i];
		n += jam(buf, "%02X", b);
	}
	return n;
}

/*
 * Roughly mimic DBG_dump(): use a space separator; and after the 4th
 * byte, a double space separator.
 *
 * This is so that values dumped by DBG_dump() and lswlog_bytes() have
 * the same 'look' - make searching and grepping easier.
 */

size_t jam_dump_bytes(struct jambuf *buf, const void *bytes, size_t size)
{
	if (size == 0) {
		return 0;
	} else if (bytes == NULL) {
		/* will inject "(null)" or error */
		return jam_string(buf, NULL);
	}

	size_t n = 0;
	const uint8_t *byte = bytes;
	const uint8_t *end = byte + size;
	const char *sep = "";
	while (byte < end) {
		for (unsigned b = 0; b < 4 && byte < end; b++) {
			n += jam(buf, "%s%02x", sep, *byte++);
			sep = " ";
		}
		sep = "  ";
	}
	return n;
}

/*
 * For logging - output the string but convert any unprintable
 * characters into an equivalent escape code.
 *
 * XXX: bonus points for anyone encoding \r \n ... correctly?
 */

size_t jam_sanitized_bytes(struct jambuf *buf, const void *ptr, size_t size)
{
	size_t n = 0;
	const char *chars = ptr;
	for (unsigned i = 0; i < size; i++) {
		char c = chars[i];
		if (char_isprint(c)) {
			n += jam_char(buf, c);
		} else {
			n += jam(buf, "\\%03o", c & 0xFF);
		}
	}
	return n;
}

/*
 * For shell variables - output the string but (assuming text is
 * enclosed in single quotes) convert any shell meta characters into
 * equivalent escape codes.
 */

size_t jam_meta_escaped_bytes(struct jambuf *buf, const void *ptr, size_t size)
{
	size_t n = 0;
	const char *chars = ptr;
	for (unsigned i = 0; i < size; i++) {
		char c = chars[i];
		if (char_isprint(c)) {
			switch (c) {
			case '\'':
			case '\\':
			case '"':
			case '`':
			case '$':
				n += jam(buf, "\\%03o", c & 0xFF);
				break;
			default:
				n += jam_char(buf, c);
			}
		} else {
			n += jam(buf, "\\%03o", c & 0xFF);
		}
	}
	return n;
}
