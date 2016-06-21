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
#include "asn1.h"
#include "oid.h"

#define TIME_MAX 0x7fffffff	/* ??? doesn't seem portable */

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
 * build an empty asn.1 object with tag and length fields already filled in
 */
u_char *build_asn1_object(chunk_t *object, asn1_t type, size_t datalen)
{
	u_char length_buf[4];
	chunk_t length = { length_buf, 0 };
	u_char *pos;

	/* code the asn.1 length field */
	code_asn1_length(datalen, &length);

	/* allocate memory for the asn.1 TLV object */
	object->len = 1 + length.len + datalen;
	object->ptr = alloc_bytes(object->len, "asn1 object");

	/* set position pointer at the start of the object */
	pos = object->ptr;

	/* copy the asn.1 tag field and advance the pointer */
	*pos++ = type;

	/* copy the asn.1 length field and advance the pointer */
	chunkcpy(pos, length);

	return pos;
}

/*
 * build an empty asn.1 object with explicit tags and length fields
 * already filled in
 */
u_char *build_asn1_explicit_object(chunk_t *object, asn1_t outer_type,
				asn1_t inner_type,
				size_t datalen)
{
	u_char length_buf[4];
	chunk_t length = { length_buf, 0 };
	u_char *pos;

	/* code the inner asn.1 length field */
	code_asn1_length(datalen, &length);

	/*create the outer asn.1 object */
	pos = build_asn1_object(object, outer_type, 1 + length.len + datalen);

	/* copy the inner asn.1 tag field and advance the pointer */
	*pos++ = inner_type;

	/* copy the inner asn.1 length field and advance the pointer */
	chunkcpy(pos, length);

	return pos;
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
 * Converts ASN.1 UTCTIME or GENERALIZEDTIME into calender time
 * ??? Returns UNDEFINED_TIME for many problems and TIME_MAX for others.  Is this reasonable?
 */
realtime_t asn1totime(const chunk_t *utctime, asn1_t type)
{
	struct tm t;
	time_t tz_offset;
	char *eot = NULL;

	if ((eot = memchr(utctime->ptr, 'Z', utctime->len)) != NULL) {
		/* ??? a Z anywhere in the tz is sufficient? */
		tz_offset = 0; /* Zulu time with a zero time zone offset */
	} else if ((eot = memchr(utctime->ptr, '+', utctime->len)) != NULL) {
		int tz_hour, tz_min;

		if (sscanf(eot + 1, "%2d%2d", &tz_hour, &tz_min) != 2)
			return undefinedrealtime(); /* error in positive timezone offset format */

		/* positive time zone offset */
		tz_offset = tz_hour * secs_per_hour + tz_min * secs_per_minute;
	} else if ((eot = memchr(utctime->ptr, '-', utctime->len)) != NULL) {
		int tz_hour, tz_min;

		if (sscanf(eot + 1, "%2d%2d", &tz_hour, &tz_min) != 2)
			return undefinedrealtime(); /* error in negative timezone offset format */

		/* negative time zone offset */
		tz_offset = -(tz_hour * secs_per_hour + tz_min * secs_per_minute);
	} else {
		return undefinedrealtime(); /* error in time format */
	}

	/* parse ASN.1 time string */
	if (sscanf((const char *)utctime->ptr,
			(type == ASN1_UTCTIME) ?
			  "%2d%2d%2d%2d%2d" :
			  "%4d%2d%2d%2d%2d",
			&t.tm_year, &t.tm_mon, &t.tm_mday,
			&t.tm_hour, &t.tm_min) != 5)
		return undefinedrealtime();	/* error in time st [yy]yymmddhhmm time format */

	/* is there a seconds field? */
	if ((eot - (char *)utctime->ptr) ==
	    ((type == ASN1_UTCTIME) ? 12 : 14)) {
		if (sscanf(eot - 2, "%2d", &t.tm_sec) != 1)
			return undefinedrealtime();	/* error in ss seconds field format */
	} else {
		t.tm_sec = 0;
	}

	/* representation of year */
	if (t.tm_year >= 1900)
		t.tm_year -= 1900;
	else if (t.tm_year >= 100)
		return undefinedrealtime();
	else if (t.tm_year < 50)
		t.tm_year += 100;

	if (t.tm_mon < 1 || t.tm_mon > 12)
		return undefinedrealtime(); /* error in month format */

	/* representation of month 0..11 in struct tm */
	t.tm_mon--;

	/* set daylight saving time to off */
	t.tm_isdst = 0;

	/* if no conversion overflow occurred, compensate timezone */
	/* ??? is TIME_MAX really a good failure mode? */
	{
		time_t tc = mktime(&t);
		realtime_t r = { tc == -1 ? TIME_MAX : tc - timezone - tz_offset };

		return r;
	}
}

/*
 * Initializes the internal context of the ASN.1 parser
 */
void asn1_init(asn1_ctx_t *ctx, chunk_t blob, u_int level0,
	bool implicit, u_int cond)
{
	ctx->blobs[0] = blob;
	ctx->level0   = level0;
	ctx->implicit = implicit;
	ctx->cond     = cond;
	zero(&ctx->loopAddr);
}

/*
 * Parses and extracts the next ASN.1 object
 */
bool extract_object(const asn1Object_t *const objects,
		u_int *objectID,	/* IN/OUT */
		chunk_t *object,	/* OUT */
		u_int *level,	/* OUT */
		asn1_ctx_t *ctx)
{
	asn1Object_t obj = objects[*objectID];
	chunk_t *blob;
	chunk_t *blob1;
	u_char *start_ptr;

	*object = empty_chunk;

	if (obj.flags & ASN1_END) { /* end of loop or option found */
		if (ctx->loopAddr[obj.level] &&
			ctx->blobs[obj.level + 1].len > 0) {
			/* another iteration */
			*objectID = ctx->loopAddr[obj.level];
			obj = objects[*objectID];
		} else {
			ctx->loopAddr[obj.level] = 0; /* exit loop or option */
			return TRUE;
		}
	}

	*level = ctx->level0 + obj.level;
	blob = ctx->blobs + obj.level;
	blob1 = blob + 1;
	start_ptr = blob->ptr;

	/* handle ASN.1 defaults values */
	if ((obj.flags & ASN1_DEF) &&
		(blob->len == 0 || *start_ptr != obj.type)) {
		/* field is missing */
		DBG(DBG_PARSING,
			DBG_log("L%d - %s:", *level, obj.name));
		if (obj.type & ASN1_CONSTRUCTED)
			(*objectID)++; /* skip context-specific tag */
		return TRUE;
	}

	/* handle ASN.1 options */
	if ((obj.flags & ASN1_OPT) &&
		(blob->len == 0 || *start_ptr != obj.type)) {
		/* advance to end of missing option field */
		do {
			(*objectID)++;
		} while (!((objects[*objectID].flags & ASN1_END) &&
				(objects[*objectID].level == obj.level)));
		return TRUE;
	}

	/* an ASN.1 object must possess at least a tag and length field */
	if (blob->len < 2) {
		DBG(DBG_PARSING,
			DBG_log("L%d - %s:  ASN.1 object smaller than 2 octets",
				ctx->level0 + obj.level, obj.name));
		return FALSE;
	}

	blob1->len = asn1_length(blob);

	if (blob1->len == ASN1_INVALID_LENGTH) {
		DBG(DBG_PARSING,
			DBG_log("L%d - %s:  length of ASN1 object invalid or too large",
				*level, obj.name));
		return FALSE;
	}

	blob1->ptr = blob->ptr;
	blob->ptr += blob1->len;
	blob->len -= blob1->len;

	/* return raw ASN.1 object without prior type checking */
	if (obj.flags & ASN1_RAW) {
		DBG(DBG_PARSING,
			DBG_log("L%d - %s:", *level, obj.name));
		object->ptr = start_ptr;
		object->len = (size_t)(blob->ptr - start_ptr);
		return TRUE;
	}

	if (*start_ptr != obj.type && !(ctx->implicit && *objectID == 0)) {
		DBG(DBG_PARSING,
			DBG_log("L%d - %s: ASN1 tag 0x%02x expected, but is 0x%02x",
				*level, obj.name, obj.type, *start_ptr);
			DBG_dump("", start_ptr, (u_int)(blob->ptr - start_ptr));
			);
		return FALSE;
	}

	DBG(DBG_PARSING,
		DBG_log("L%d - %s:", ctx->level0 + obj.level, obj.name));

	/* In case of "SEQUENCE OF" or "SET OF" start a loop */
	if (obj.flags & ASN1_LOOP) {
		if (blob1->len > 0) {
			/* at least one item, start the loop */
			ctx->loopAddr[obj.level] = *objectID + 1;
		} else {
			/* no items, advance directly to end of loop */
			do {
				(*objectID)++;
			} while ((objects[*objectID].flags & ASN1_END) == 0 ||
			       objects[*objectID].level != obj.level);
			return TRUE;
		}
	}

	if (obj.flags & ASN1_OBJ) {
		object->ptr = start_ptr;
		object->len = (size_t)(blob->ptr - start_ptr);
		DBG(ctx->cond,
			DBG_dump_chunk("", *object));
	} else if (obj.flags & ASN1_BODY) {
		int oid;

		*object = *blob1;

		switch (obj.type) {
		case ASN1_OID:
			oid = known_oid(*object);
			if (oid != OID_UNKNOWN) {
				DBG(DBG_PARSING,
					DBG_log("  '%s'", oid_names[oid].name));
				return TRUE;
			}
			break;
		case ASN1_UTF8STRING:
		case ASN1_IA5STRING:
		case ASN1_PRINTABLESTRING:
		case ASN1_T61STRING:
		case ASN1_VISIBLESTRING:
			DBG(DBG_PARSING,
				DBG_log("  '%.*s'",
					(int)object->len, object->ptr));
			return TRUE;

		case ASN1_UTCTIME:
		case ASN1_GENERALIZEDTIME:
			DBG(DBG_PARSING,
				char tbuf[REALTIMETOA_BUF];
				DBG_log("  '%s'",
					realtimetoa(asn1totime(object, obj.type), TRUE, tbuf,
						sizeof(tbuf)));
				);
			return TRUE;

		default:
			break;
		}
		DBG(ctx->cond,
			DBG_dump_chunk("", *object));
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
