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
		n += jam(buf, "%02x", bytes[i]);
	}
	return n;
}

size_t jam_HEX_bytes(struct jambuf *buf, const void *ptr, size_t size)
{
	size_t n = 0;
	const uint8_t *bytes = ptr;
	for (unsigned i = 0; i < size; i++) {
		n += jam(buf, "%02X", bytes[i]);
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
 */

size_t jam_sanitized_bytes(struct jambuf *buf, const void *ptr, size_t size)
{
	size_t n = 0;
	const char *chars = ptr;
	for (unsigned i = 0; i < size; i++) {
		char c = chars[i];
		/*
		 * Notes:
		 *
		 * - NUL is always represented as '\0'.
		 *
		 * - octal format can use up-to 3 digts but can't be
		 *   ambigious, so only use when next character isn't
		 *   numeric
		 */

		switch (c) {
		case '\0': n += jam_string(buf, "\\0"); break;
		case '\a': n += jam_string(buf, "\\a"); break;
		case '\b': n += jam_string(buf, "\\b"); break;
		case '\t': n += jam_string(buf, "\\t"); break;
		case '\n': n += jam_string(buf, "\\n"); break;
		case '\v': n += jam_string(buf, "\\v"); break;
		case '\f': n += jam_string(buf, "\\f"); break;
		case '\r': n += jam_string(buf, "\\r"); break;
		default:
			if (char_isprint(c)) {
				n += jam_char(buf, c);
			} else if (i + 1 == size ||
				   !char_isdigit(chars[i + 1])) {
				n += jam(buf, "\\%o", c & 0xFF);
			} else {
				n += jam(buf, "\\%03o", c & 0xFF);
			}
			break;

		}
	}
	return n;
}

/*
 * For shell variables - output the string but (assuming text is
 * enclosed in single quotes) convert any shell meta characters into
 * equivalent escape codes.
 *
 * XXX: bonus points for anyone encoding \r \n ... correctly?  But is
 * it even safe?
 */

size_t jam_meta_escaped_bytes(struct jambuf *buf, const void *ptr, size_t size)
{
	size_t n = 0;
	const char *chars = ptr;
	for (unsigned i = 0; i < size; i++) {
		char c = chars[i];
		switch (c) {
		case '\'':
		case '\\':
		case '"':
		case '`':
		case '$':
			n += jam(buf, "\\%03o", c & 0xFF);
			break;
		default:
			if (char_isprint(c)) {
				n += jam_char(buf, c);
			} else {
				n += jam(buf, "\\%03o", c & 0xFF);
			}
			break;
		}
	}
	return n;
}
