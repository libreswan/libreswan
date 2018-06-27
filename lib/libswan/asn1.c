/*
 * Simple ASN.1 parser
 * Copyright (C) 2000-2004 Andreas Steffen, Zuercher Hochschule Winterthur
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "lswlog.h"
#include "lswalloc.h"
#include "realtime.h"
#include "asn1.h"
#include "oid.h"

/*
 * If the oid is listed in the oid_names table then the corresponding
 * position in the oid_names table is returned otherwise -1 is returned
 */
int known_oid(chunk_t object)
{
	int oid = 0;

	while (object.len > 0) {
		if (oid_names[oid].octet == *object.ptr) {
			object.len--;
			object.ptr++;
			if (object.len == 0) {
				/* at end of object */
				if (oid_names[oid].down == 0)
					return oid;	/* found terminal symbol */
				else
					return OID_UNKNOWN;	/* end of object but not terminal */
			} else {
				/* object continues */
				if (oid_names[oid].down == 0) {
					return OID_UNKNOWN;	/* terminal but not end of object */
				} else {
					/* advance to next hex octet in table
					 * so we can match next octet of OID
					 */
					oid++;
				}
			}
		} else {
			if (oid_names[oid].next != 0)
				oid = oid_names[oid].next;
			else
				return OID_UNKNOWN;
		}
	}
	return OID_UNKNOWN;
}

/*
 * Skip tag and decode the length in bytes of an ASN.1 object.
 * Blob is updated to reflect the tag and length have been consumed
 */
size_t asn1_length(chunk_t *blob)
{
	u_char n;
	size_t len;

	if (blob->len < 2)
	{
		DBG(DBG_PARSING, DBG_log(
			"insufficient number of octets to parse ASN.1 length"));
		return ASN1_INVALID_LENGTH;
	}

	/* advance from tag field on to length field */
	blob->ptr++;
	blob->len--;

	/* read first octet of length field */
	n = *blob->ptr++;
	blob->len--;

	if ((n & 0x80) == 0) { /* single length octet */
		if (n > blob->len) {
			DBG(DBG_PARSING,
				DBG_log("number of length octets is larger than ASN.1 object"));
			return ASN1_INVALID_LENGTH;
		}
		return n;
	}

	/* composite length, determine number of length octets */
	n &= 0x7f;

	if (n > blob->len) {
		DBG(DBG_PARSING,
			DBG_log("number of length octets is larger than ASN.1 object"));
		return ASN1_INVALID_LENGTH;
	}

	if (n > sizeof(len)) {
		DBG(DBG_PARSING,
			DBG_log("number of length octets is larger than limit of %d octets",
				(int) sizeof(len)));
		return ASN1_INVALID_LENGTH;
	}

	len = 0;

	while (n-- > 0) {
		len = 256 * len + *blob->ptr++;
		blob->len--;
	}
	if (len > blob->len) {
		DBG(DBG_PARSING,
			DBG_log("length is larger than remaining blob size"));
		return ASN1_INVALID_LENGTH;
	}

	return len;
}

/*
 * codes ASN.1 lengths up to a size of 16'777'215 bytes
 */
void code_asn1_length(size_t length, chunk_t *code)
{
	if (length < 128) {
		code->ptr[0] = length;
		code->len = 1;
	} else if (length < 256) {
		code->ptr[0] = 0x81;
		code->ptr[1] = (u_char) length;
		code->len = 2;
	} else if (length < 65536) {
		code->ptr[0] = 0x82;
		code->ptr[1] = length >> 8;
		code->ptr[2] = length & 0x00ff;
		code->len = 3;
	} else {
		code->ptr[0] = 0x83;
		code->ptr[1] = length >> 16;
		code->ptr[2] = (length >> 8) & 0x00ff;
		code->ptr[3] = length & 0x0000ff;
		code->len = 4;
	}
}

/*
 * determines if a character string is of type ASN.1 printableString
 */
bool is_printablestring(chunk_t str)
{
	const char printablestring_charset[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?";
	u_int i;

	for (i = 0; i < str.len; i++) {
		if (strchr(printablestring_charset, str.ptr[i]) == NULL)
			return FALSE;
	}
	return TRUE;
}

/*
 * tests if a blob contains a valid ASN.1 set or sequence
 */
bool is_asn1(chunk_t blob)
{
	u_int len;

	if (blob.len < 1) {
		DBG(DBG_PARSING,
			DBG_log("  cert blob is empty: not binary ASN.1"));
		return FALSE;
	}

	switch (blob.ptr[0]) {
	case ASN1_SEQUENCE:
	case ASN1_SET:
		break;	/* looks OK */
	default:
		DBG(DBG_PARSING,
			DBG_log("  cert blob content is not binary ASN.1"));
		return FALSE;
	}

	len = asn1_length(&blob);
	if (len != blob.len) {
		DBG(DBG_PARSING,
			DBG_log("  cert blob size (%zu) does not match ASN.1 coded length (%u)",
				blob.len, len));
		return FALSE;
	}
	return TRUE;
}
