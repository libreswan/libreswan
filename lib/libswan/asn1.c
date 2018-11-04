/*
 * Simple ASN.1 parser
 * Copyright (C) 2000-2004 Andreas Steffen, Zuercher Hochschule Winterthur
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

size_t asn1_length_signature(chunk_t *blob , chunk_t *sig_val)
{
	u_char n;
	u_char type_r,type_s;
	int len_r,len_s;

	if (blob->len < 2)
	{
		DBG(DBG_PARSING, DBG_log(
			"insufficient number of octets to parse DER Signature length"));
		return ASN1_INVALID_LENGTH;
	}

	/* advance from tag field on to length field */
	blob->ptr++;
	blob->len--;

	/* read first octet of length field */
	n = *blob->ptr++;
	/* advance from length field to type field of integer r 0x02*/
	type_r = *blob->ptr++;

	if (type_r == 0x02) { /* single length octet */
		/* find the length of integer r*/
		len_r = *blob->ptr++;
		if (len_r%2 != 0) {
			len_r = len_r-1;
			/* advance to the next octect as the current octet is 0 */
			blob->ptr++;
		}
		sig_val->len = len_r;
		/* XXX: need to check len_r and len_s fits in this */
	        sig_val->ptr = alloc_bytes(len_r * 2, "ec points");
		DBG(DBG_PARSING, DBG_log(" sig_val  len is %zu",sig_val->len));
		/* copy the values of r into signature */
		memcpy(sig_val->ptr,blob->ptr,len_r);

		/* advance from length field of integer r to type field of integer s 0x02*/
		blob->ptr += len_r;
		type_s = *(blob->ptr);

		DBG(DBG_PARSING, DBG_log(" type_s is %d",type_s));
		if (type_s == 0x02) {
			/* find the length of integer r*/
			blob->ptr++;
			len_s = *blob->ptr++;
			if (len_s%2 !=0) {
				len_s = len_s-1;
				/* advance to the next octect as the current octet is 0 */
				blob->ptr++;
			}
			DBG(DBG_PARSING, DBG_log("  len_s is %d",len_s));
			sig_val->len += len_s;
			DBG(DBG_PARSING, DBG_log(" sig_val total len is %zu",sig_val->len));
			/* copy the values of r into signature */
			memcpy(sig_val->ptr+len_r,blob->ptr,len_s);
		}

	} else {
		DBG(DBG_PARSING, DBG_log("Invalid DER encoded signature"));
	}

		if (n > blob->len) {
			DBG(DBG_PARSING,
				DBG_log("number of length octets is larger than ASN.1 object"));
			return ASN1_INVALID_LENGTH;
		}

	return (sig_val->len);
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
 * Determines if a character string is of type ASN.1 printableString.
 * See https://en.wikipedia.org/w/index.php?title=PrintableString
 */
bool is_printablestring(chunk_t str)
{
	/*
	 * printable string character set:
	 * "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?"
	 */
	static const unsigned char printable_set[] = {
		0201u,	/* 0x20        '  (first is the real SPACE) */
		0373u,	/* 0x28 () +,-./ */
		0377u,	/* 0x30 01234567 */
		0247u,	/* 0x38 89:  = ? */
		0376u,	/* 0x40  ABCDEFG */
		0377u,	/* 0x48 HIJKLMNO */
		0377u,	/* 0x50 PQRSTUVW */
		0007u,	/* 0x58 XYZ      */
		0376u,	/* 0x60  abcdefg */
		0377u,	/* 0x68 hijklmno */
		0377u,	/* 0x70 pqrstuvw */
		0007u,	/* 0x78 xyz      */
	};

	for (unsigned i = 0; i < str.len; i++) {
		/*
		 * Tricky test.
		 * The first part checks if the current character is
		 * within the range of graphical characters (0x20 - 0x7f).
		 * It saves a branch instruction by exploiting the way
		 * underflow of unsigned subtraction yields a large number.
		 * If the character is in range, we check it by subscripting
		 * its bit within printable_set[].
		 */
		unsigned u = (unsigned)str.ptr[i] - 0x20u;
		if (!(u <= 0x7fU - 0x20u &&
		      (printable_set[u / 8u] & 1u << (u % 8u))))
			return FALSE;
	}
	return TRUE;
}

/*
 * tests if a blob contains a valid ASN.1 set or sequence
 */
bool is_asn1(chunk_t blob)
{
	unsigned len;

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

bool is_asn1_der_encoded_signature(chunk_t blob, chunk_t *sig_val)
{

	if (blob.len < 1) {
		DBG(DBG_PARSING,
			DBG_log("  Signature is empty: not binary ASN.1 DER encoded Signature"));
		return FALSE;
	}

	switch (blob.ptr[0]) {
	case ASN1_SEQUENCE:
		break;	/* looks OK */
	default:
		DBG(DBG_PARSING,
			DBG_log("  Signature blob content is not binary ASN.1"));
		return FALSE;
	}

	asn1_length_signature(&blob , sig_val);
	return TRUE;
}
