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
#include "chunk.h"
#include "ttodata.h"	/* for datatot() */
#include "passert.h"

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
 * Roughly mimic LDBG_dump(): use a space separator; and after the 4th
 * byte, a double space separator.
 *
 * This is so that values dumped by LDBG_dump() and lswlog_bytes()
 * have the same 'look' - make searching and grepping easier.
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
 * Notes:
 *
 * - NUL is always represented as '\0'.
 *
 * - octal format can use up-to 3 digts but can't be ambiguous, so
 *   only use when next character isn't numeric
 *
 *   hence need to pass to characters to jam_sanitized_char().
 */

static size_t jam_control(struct jambuf *buf, char c, char c1)
{
	switch (c) {
	case '\0': return jam_string(buf, "\\0");
	case '\a': return jam_string(buf, "\\a");
	case '\b': return jam_string(buf, "\\b");
	case '\t': return jam_string(buf, "\\t");
	case '\n': return jam_string(buf, "\\n");
	case '\v': return jam_string(buf, "\\v");
	case '\f': return jam_string(buf, "\\f");
	case '\r': return jam_string(buf, "\\r");
	}

	if (char_isdigit(c1)) {
		/* force \OOO when next char is digit */
		return jam(buf, "\\%03o", c & 0xFF);
	}

	return jam(buf, "\\%o", c & 0xFF);
}

size_t jam_sanitized_bytes(struct jambuf *buf, const void *ptr, size_t size)
{
	size_t n = 0;
	const char *chars = ptr;
	for (unsigned i = 0; i < size; i++) {
		char c = chars[i];
		if (char_isprint(c)) {
			n += jam_char(buf, c);
		} else {
			/* handle \0001 */
			char c1 = (i + 1 == size ? '\0' : chars[i+1]);
			n += jam_control(buf, c, c1);
		}
	}
	return n;
}

/*
 * For shell variables.  Output the string in a format suitable for
 * use by shell scripts, but wrapped in single quotes.
 *
 * XXX: bonus points for anyone encoding \r \n ... correctly?  But is
 * it even safe?
 */

size_t jam_shell_quoted_bytes(struct jambuf *buf, const void *ptr, size_t size)
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

size_t jam_uppercase_bytes(struct jambuf *buf, const void *ptr, size_t size)
{
	size_t n = 0;
	const char *chars = ptr;
	for (unsigned i = 0; i < size; i++) {
		char c = chars[i];
		if (char_isprint(c)) {
			n += jam_char(buf, char_toupper(c));
		} else {
			/* handles \0001 */
			char c1 = (i + 1 == size ? '\0' : chars[i+1]);
			n += jam_control(buf, c, c1);
		}
	}
	return n;
}

size_t jam_string_uppercase(struct jambuf *buf, const char *string)
{
	return jam_uppercase_bytes(buf, string, strlen(string));
}

size_t jam_human_bytes(struct jambuf *buf, const void *ptr, size_t size)
{
	size_t n = 0;
	const char *chars = ptr;
	for (unsigned i = 0; i < size; i++) {
		char c = chars[i];
		if (c == '_') {
			n += jam_char(buf, '-');
		} else if (char_isprint(c)) {
			n += jam_char(buf, char_tolower(c));
		} else {
			/* handles \0001 */
			char c1 = (i + 1 == size ? '\0' : chars[i+1]);
			n += jam_control(buf, c, c1);
		}
	}
	return n;
}

size_t jam_string_human(struct jambuf *buf, const char *string)
{
	if (string == NULL) {
		/* will inject "(null)" or error */
		return jam_string(buf, NULL);
	}

	return jam_human_bytes(buf, string, strlen(string));
}
