/*
 * Support of X.509 certificates and CRLs
 *
 * Copyright (C) 2000 Andreas Hess, Patric Lichtsteiner, Roger Wegmann
 * Copyright (C) 2001 Marco Bertossa, Andreas Schleiss
 * Copyright (C) 2002 Mario Strasser
 * Copyright (C) 2000-2004 Andreas Steffen, Zuercher Hochschule Winterthur
 * Copyright (C) 2003-2008 Michael C Richardson <mcr@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
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
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <limits.h>
#include <sys/types.h>
#include "sysdep.h"
#include "constants.h"
#include "lswlog.h"
#include "lswalloc.h"
#include "id.h"
#include "asn1.h"
#include "oid.h"
#include "x509.h"
#include "certs.h"
#include <prerror.h>
#include <nss.h>
#include <pk11pub.h>
#include <keyhi.h>
#include <secerr.h>
#include "lswconf.h"

static void hex_str(chunk_t bin, chunk_t *str);	/* forward */

/* coding of X.501 distinguished name */
typedef struct {
	const char *name;
	chunk_t oid;
	u_char type;
} x501rdn_t;

/* X.501 acronyms for well known object identifiers (OIDs) */
static u_char oid_ND[] = { 0x02, 0x82, 0x06, 0x01, 0x0A, 0x07, 0x14 };
static u_char oid_UID[] = { 0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64,
				0x01, 0x01 };
static u_char oid_DC[] = { 0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64,
				0x01, 0x19 };
static u_char oid_CN[] = { 0x55, 0x04, 0x03 };
static u_char oid_S[] = { 0x55, 0x04, 0x04 };
static u_char oid_SN[] = { 0x55, 0x04, 0x05 };
static u_char oid_C[] = { 0x55, 0x04, 0x06 };
static u_char oid_L[] = { 0x55, 0x04, 0x07 };
static u_char oid_ST[] = { 0x55, 0x04, 0x08 };
static u_char oid_O[] = { 0x55, 0x04, 0x0A };
static u_char oid_OU[] = { 0x55, 0x04, 0x0B };
static u_char oid_T[] = { 0x55, 0x04, 0x0C };
static u_char oid_D[] = { 0x55, 0x04, 0x0D };
static u_char oid_N[] = { 0x55, 0x04, 0x29 };
static u_char oid_G[] = { 0x55, 0x04, 0x2A };
static u_char oid_I[] = { 0x55, 0x04, 0x2B };
static u_char oid_ID[] = { 0x55, 0x04, 0x2D };
static u_char oid_E[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09,
				0x01 };
static u_char oid_UN[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09,
				0x02 };
static u_char oid_TCGID[] = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x89, 0x31, 0x01,
				0x01, 0x02, 0x02, 0x4B };

static const x501rdn_t x501rdns[] = {
	{ "ND", { oid_ND, 7 }, ASN1_PRINTABLESTRING },
	{ "UID", { oid_UID, 10 }, ASN1_PRINTABLESTRING },
	{ "DC", { oid_DC, 10 }, ASN1_PRINTABLESTRING },
	{ "CN", { oid_CN, 3 }, ASN1_PRINTABLESTRING },
	{ "S", { oid_S, 3 }, ASN1_PRINTABLESTRING },
	{ "SN", { oid_SN, 3 }, ASN1_PRINTABLESTRING },
	{ "serialNumber", { oid_SN, 3 }, ASN1_PRINTABLESTRING },
	{ "C", { oid_C, 3 }, ASN1_PRINTABLESTRING },
	{ "L", { oid_L, 3 }, ASN1_PRINTABLESTRING },
	{ "ST", { oid_ST, 3 }, ASN1_PRINTABLESTRING },
	{ "O", { oid_O, 3 }, ASN1_PRINTABLESTRING },
	{ "OU", { oid_OU, 3 }, ASN1_PRINTABLESTRING },
	{ "T", { oid_T, 3 }, ASN1_PRINTABLESTRING },
	{ "D", { oid_D, 3 }, ASN1_PRINTABLESTRING },
	{ "N", { oid_N, 3 }, ASN1_PRINTABLESTRING },
	{ "G", { oid_G, 3 }, ASN1_PRINTABLESTRING },
	{ "I", { oid_I, 3 }, ASN1_PRINTABLESTRING },
	{ "ID", { oid_ID, 3 }, ASN1_PRINTABLESTRING },
	{ "E", { oid_E, 9 }, ASN1_IA5STRING },
	{ "Email", { oid_E, 9 }, ASN1_IA5STRING },
	{ "emailAddress", { oid_E, 9 }, ASN1_IA5STRING },
	{ "UN", { oid_UN, 9 }, ASN1_IA5STRING },
	{ "unstructuredName", { oid_UN, 9 }, ASN1_IA5STRING },
	{ "TCGID", { oid_TCGID, 12 }, ASN1_PRINTABLESTRING }
};

#define X501_RDN_ROOF elemsof(x501rdns)

static void format_chunk(chunk_t *ch, const char *format, ...) PRINTF_LIKE(2);

/*
 * format into a chunk.
 * The chunk is used as a cursor for free space at the end of the buffer.
 * We leave it advanced to the remainder of the free space.
 * BUG: if there is no free space to start with, we don't do anything.
 */
static void format_chunk(chunk_t *ch, const char *format, ...)
{
	if (ch->len > 0) {
		size_t len = ch->len;
		va_list args;
		va_start(args, format);
		int ret = vsnprintf((char *)ch->ptr, len, format, args);
		va_end(args);
		if (ret < 0) {
			/*
			 * BUG: if ret < 0, vsnprintf encountered some error,
			 * we ought to raise a stink
			 * For now: pretend nothing happened!
			 */
		} else if ((size_t)ret > len) {
			/*
			 * BUG: if ret >= len, then the vsnprintf output was
			 * truncate, we ought to raise a stink!
			 * For now: accept truncated output.
			 */
			ch->ptr += len;
			ch->len = 0;
		} else {
			ch->ptr += ret;
			ch->len -= ret;
		}
	}
}

/*
 * Pointer is set to the first RDN in a DN
 */
static err_t init_rdn(chunk_t dn, chunk_t *rdn, chunk_t *attribute, bool *next)
{
	*rdn = empty_chunk;
	*attribute = empty_chunk;

	/* a DN is a SEQUENCE OF RDNs */
	if (*dn.ptr != ASN1_SEQUENCE)
		return "DN is not a SEQUENCE";

	rdn->len = asn1_length(&dn);

	if (rdn->len == ASN1_INVALID_LENGTH)
		return "Invalid RDN length";

	rdn->ptr = dn.ptr;

	/* are there any RDNs ? */
	*next = rdn->len > 0;

	return NULL;
}

/*
 * Fetches the next RDN in a DN
 */
static err_t get_next_rdn(chunk_t *rdn,
	chunk_t *attribute, /* output */
	chunk_t *oid /* output */,
	chunk_t *value,	/* output */
	asn1_t *type,	/* output */
	bool *next) /* output */
{
	chunk_t body;

	/* initialize return values */
	*oid = empty_chunk;
	*value = empty_chunk;

	/* if all attributes have been parsed, get next rdn */
	if (attribute->len <= 0) {
		/* an RDN is a SET OF attributeTypeAndValue */
		if (*rdn->ptr != ASN1_SET)
			return "RDN is not a SET";

		attribute->len = asn1_length(rdn);

		if (attribute->len < 1 || attribute->len == ASN1_INVALID_LENGTH)
			return "Invalid attribute length";

		attribute->ptr = rdn->ptr;

		/* advance to start of next RDN */
		rdn->ptr += attribute->len;
		rdn->len -= attribute->len;
	}

	/* an attributeTypeAndValue is a SEQUENCE */
	if (*attribute->ptr != ASN1_SEQUENCE)
		return "attributeTypeAndValue is not a SEQUENCE";

	/* extract the attribute body */
	body.len = asn1_length(attribute);

	if (body.len < 1 || body.len == ASN1_INVALID_LENGTH)
		return "Invalid attribute body length";

	body.ptr = attribute->ptr;

	/* advance to start of next attribute */
	attribute->ptr += body.len;
	attribute->len -= body.len;

	/* attribute type is an OID */
	if (*body.ptr != ASN1_OID)
		return "attributeType is not an OID";

	/* extract OID */
	oid->len = asn1_length(&body);

	if (oid->len == ASN1_INVALID_LENGTH)
		return "Invalid attribute OID length";

	oid->ptr = body.ptr;

	/* advance to the attribute value */
	body.ptr += oid->len;
	body.len -= oid->len;

	/* extract string type */
	if (body.len < 2)
	    return "Invalid value in RDN";
	*type = *body.ptr;

	/* extract string value */
	value->len = asn1_length(&body);

	if (value->len == ASN1_INVALID_LENGTH)
		return "Invalid attribute string length";

	value->ptr = body.ptr;

	/* are there any RDNs left? */
	*next = rdn->len > 0 || attribute->len > 0;

	return NULL;
}

/*
 * Parses an ASN.1 distinguished name int its OID/value pairs
 */
static err_t dn_parse(chunk_t dn, chunk_t *str)
{
	chunk_t rdn, oid, attribute, value;
	asn1_t type;
	int oid_code;
	bool next;
	bool first = TRUE;
	err_t ugh;

	if (dn.ptr == NULL) {
		format_chunk(str, "(empty)");
		return NULL;
	}
	ugh = init_rdn(dn, &rdn, &attribute, &next);

	if (ugh != NULL)	/* a parsing error has occurred */
		return ugh;

	while (next) {
		ugh = get_next_rdn(&rdn, &attribute, &oid, &value, &type,
				   &next);

		if (ugh != NULL)	/* a parsing error has occurred */
			return ugh;

		if (first)	/* first OID/value pair */
			first = FALSE;
		else	/* separate OID/value pair by a comma */
			format_chunk(str, ", ");

		/* print OID */
		oid_code = known_oid(oid);
		if (oid_code == OID_UNKNOWN)	/* OID not found in list */
			hex_str(oid, str);
		else
			format_chunk(str, "%s", oid_names[oid_code].name);

		/* print value */
		format_chunk(str, "=%.*s", (int)value.len, value.ptr);
	}
	return NULL;
}

/*
 * Count the number of wildcard RDNs in a distinguished name
 */
int dn_count_wildcards(chunk_t dn)
{
	chunk_t rdn, attribute, oid, value;
	asn1_t type;
	bool next;
	int wildcards = 0;

	err_t ugh = init_rdn(dn, &rdn, &attribute, &next);

	if (ugh != NULL)	/* a parsing error has occurred */
		return -1;

	while (next) {
		ugh = get_next_rdn(&rdn, &attribute, &oid, &value, &type,
				   &next);

		if (ugh != NULL)	/* a parsing error has occurred */
			return -1;

		if (value.len == 1 && *value.ptr == '*')
			wildcards++;	/* we have found a wildcard RDN */
	}
	return wildcards;
}

/*
 * Prints a binary string in hexadecimal form
 */
static void hex_str(chunk_t bin, chunk_t *str)
{
	unsigned i;

	format_chunk(str, "0x");
	for (i = 0; i < bin.len; i++)
		format_chunk(str, "%02X", *bin.ptr++);
}

/*
 * Converts a binary DER-encoded ASN.1 distinguished name
 * into LDAP-style human-readable ASCII format
 */
int dntoa(char *dst, size_t dstlen, chunk_t dn)
{
	err_t ugh = NULL;
	chunk_t str;

	str.ptr = (unsigned char *)dst;
	str.len = dstlen;
	ugh = dn_parse(dn, &str);

	if (ugh != NULL) {	/* error, print DN as hex string */
		libreswan_log("error in DN parsing: %s", ugh);
		DBG_dump_chunk("Bad DN:", dn);
		str.ptr = (unsigned char *)dst;
		str.len = dstlen;
		hex_str(dn, &str);
	}
	return (int)(dstlen - str.len);
}

/*
 * Same as dntoa but prints a special string for a null dn
 */
int dntoa_or_null(char *dst, size_t dstlen, chunk_t dn, const char *null_dn)
{
	if (dn.ptr == NULL)
		return snprintf(dst, dstlen, "%s", null_dn);
	else
		return dntoa(dst, dstlen, dn);
}

/*
 * function for use in atodn() that escapes a character in
 * in the leftid/rightid string. Needed for '//' and ',,'
 * escapes for OID fields
 */
static void escape_char(char *str, char esc)
{
	char *src, *dst;
	int once = 0;

	src = dst = str;
	while (*src != '\0' && once == 0) {
		*dst = *src;
		src++;
		if (*dst++ == esc && *src == esc) {
			src++;
			once = 1;
		}
	}
	while (*src != '\0') {
		*dst = *src;
		src++;
		dst++;
	}
	*dst = '\0';
}

/*
 * Converts an LDAP-style human-readable ASCII-encoded
 * ASN.1 distinguished name into binary DER-encoded format
 */
err_t atodn(char *src, chunk_t *dn)
{
	/* finite state machine for atodn */

	typedef enum {
		SEARCH_OID = 0,
		READ_OID = 1,
		SEARCH_NAME = 2,
		READ_NAME = 3,
		UNKNOWN_OID = 4
	} state_t;

	u_char oid_len_buf[ASN1_MAX_LEN_LEN];
	u_char name_len_buf[ASN1_MAX_LEN_LEN];
	u_char rdn_seq_len_buf[ASN1_MAX_LEN_LEN];
	u_char rdn_set_len_buf[ASN1_MAX_LEN_LEN];
	u_char dn_seq_len_buf[ASN1_MAX_LEN_LEN];

	chunk_t asn1_oid_len = { oid_len_buf, 0 };
	chunk_t asn1_name_len = { name_len_buf, 0 };
	chunk_t asn1_rdn_seq_len = { rdn_seq_len_buf, 0 };
	chunk_t asn1_rdn_set_len = { rdn_set_len_buf, 0 };
	chunk_t asn1_dn_seq_len = { dn_seq_len_buf, 0 };
	chunk_t oid = empty_chunk;
	chunk_t name = empty_chunk;

	int whitespace = 0;
	int rdn_seq_len = 0;
	int rdn_set_len = 0;
	int dn_seq_len = 0;
	int pos = 0;

	err_t ugh = NULL;

	/* leave room for prefix */
	u_char *dn_ptr = dn->ptr + 1 + ASN1_MAX_LEN_LEN;

	/*
	 * Concatenate the contents of a chunk onto dn.
	 * The destination pointer is incremented by the length.
	 * Pray that there is enough space.
	 */
#	define addchunk(chunk) { \
			memcpy(dn_ptr, (chunk).ptr, (chunk).len); \
			dn_ptr += (chunk).len; \
		}
#	define addtychunk(ty, chunk) { \
		*dn_ptr++ = ty; \
		addchunk(chunk); \
		}

	state_t state = SEARCH_OID;

	do {
		switch (state) {
		case SEARCH_OID:
			if (*src != ' ' && *src != '/' && *src != ',') {
				oid.ptr = (unsigned char *)src;
				oid.len = 1;
				state = READ_OID;
			}
			break;
		case READ_OID:
			if (*src != ' ' && *src != '=') {
				oid.len++;
			} else {
				for (pos = 0; pos < (int)X501_RDN_ROOF;
					pos++) {
					if (strlen(x501rdns[pos].name) ==
						oid.len &&
						strncaseeq(x501rdns[pos].name,
							(char *)oid.ptr,
							oid.len))
						break;	/* found a valid OID */
				}
				if (pos == X501_RDN_ROOF) {
					ugh = "unknown OID in ID_DER_ASN1_DN";
					state = UNKNOWN_OID;
					break;
				}
				code_asn1_length(x501rdns[pos].oid.len,
						&asn1_oid_len);

				/* reset oid and change state */
				oid = empty_chunk;
				state = SEARCH_NAME;
			}
			break;
		case SEARCH_NAME:
			if (*src != ' ' && *src != '=') {
				name.ptr = (unsigned char *)src;
				name.len = 1;
				whitespace = 0;
				state = READ_NAME;
			}
			break;
		case READ_NAME:
			if (*src != ',' && *src != '/' && *src != '\0') {
				name.len++;
				if (*src == ' ')
					whitespace++;
				else
					whitespace = 0;
			} else {
				if (*src == ',') {
					if (*++src == ',') {
						src--;
						name.len++;
						escape_char(src, ',');
						break;
					} else {
						src--;
					}
				}
				if (*src == '/') {
					if (*++src == '/') {
						src--;
						name.len++;
						escape_char(src, '/');
						break;
					} else {
						src--;
					}
				}

				name.len -= whitespace;
				code_asn1_length(name.len, &asn1_name_len);

				/*
				 * compute the length of the relative
				 * distinguished name sequence
				 */
				rdn_seq_len = 1 + asn1_oid_len.len +
					x501rdns[pos].oid.len +
					1 + asn1_name_len.len + name.len;
				code_asn1_length(rdn_seq_len,
						&asn1_rdn_seq_len);

				/*
				 * compute the length of the relative
				 * distinguished name set
				 */
				rdn_set_len = 1 + asn1_rdn_seq_len.len +
					rdn_seq_len;
				code_asn1_length(rdn_set_len,
						&asn1_rdn_set_len);

				/* encode the relative distinguished name */
				if (IDTOA_BUF < dn_ptr - dn->ptr +
				    1 + asn1_rdn_set_len.len + /* set */
				    1 + asn1_rdn_seq_len.len + /* sequence */
				    1 + asn1_oid_len.len + /* oid len */
				    x501rdns[pos].oid.len + /* oid */
				    1 + asn1_name_len.len + name.len /* type name */
				    ) {
					/* no room! */
					ugh = "DN is too big";
					state = UNKNOWN_OID;
					/*
					 * I think that it is safe to continue
					 * (but perhaps pointless)
					 */
				} else {
					addtychunk(ASN1_SET, asn1_rdn_set_len);
					addtychunk(ASN1_SEQUENCE, asn1_rdn_seq_len);
					addtychunk(ASN1_OID, asn1_oid_len);
					addchunk(x501rdns[pos].oid);
					/*
					 * encode the ASN.1 character string
					 * type of the name
					 */
					asn1_t nt =
						x501rdns[pos].type == ASN1_PRINTABLESTRING &&
						!is_printablestring(name) ?
							ASN1_T61STRING :
							x501rdns[pos].type;
					addtychunk(nt, asn1_name_len);
					addchunk(name);

					/*
					 * accumulate the length of the
					 * distinguished name sequence
					 */
					dn_seq_len += 1 +
						asn1_rdn_set_len.len +
						rdn_set_len;

					/* reset name and change state */
					name = empty_chunk;
					state = SEARCH_OID;
				}
			}
			break;
		case UNKNOWN_OID:
			break;
		}
	} while (*src++ != '\0');

	/*
	 * complete the distinguished name sequence: prefix it with
	 * ASN1_SEQUENCE and length
	 */
	code_asn1_length((size_t)dn_seq_len, &asn1_dn_seq_len);
	dn->ptr += ASN1_MAX_LEN_LEN + 1 - 1 - asn1_dn_seq_len.len;
	dn->len = 1 + asn1_dn_seq_len.len + dn_seq_len;
	dn_ptr = dn->ptr;
	*dn_ptr++ = ASN1_SEQUENCE;
	addchunk(asn1_dn_seq_len);
	return ugh;
#	undef addtychunk
#	undef addchunk
}

/*
 * compare two distinguished names by
 * comparing the individual RDNs
 */
bool same_dn(chunk_t a, chunk_t b)
{
	return match_dn(a, b, NULL);	/* degenerate case of match_dn() */
}

/*
 * compare two distinguished names by comparing the individual RDNs.
 * A single '*' character designates a wildcard RDN in DN b.
 * If wildcards is NULL, exact match is required.
 */
bool match_dn(chunk_t a, chunk_t b, int *wildcards)
{
	chunk_t rdn_a, rdn_b, attribute_a, attribute_b;
	chunk_t oid_a, oid_b, value_a, value_b;
	asn1_t type_a, type_b;
	bool next_a, next_b;

	if (wildcards != NULL) {
		/* initialize wildcard counter */
		*wildcards = 0;
	} else {
		/* fast checks possible without wildcards */
		/* same lengths for the DNs */
		if (a.len != b.len)
			return FALSE;

		/* try a binary comparison first */
		if (memeq(a.ptr, b.ptr, b.len))
			return TRUE;
	}

	/* initialize DN parsing */
	if (init_rdn(a, &rdn_a, &attribute_a, &next_a) != NULL ||
		init_rdn(b, &rdn_b, &attribute_b, &next_b) != NULL)
		return FALSE;

	/* fetch next RDN pair */
	while (next_a && next_b) {
		/* parse next RDNs and check for errors */
		if (get_next_rdn(&rdn_a, &attribute_a, &oid_a, &value_a,
					&type_a, &next_a) != NULL ||
			get_next_rdn(&rdn_b, &attribute_b, &oid_b, &value_b,
				&type_b, &next_b) != NULL)
			return FALSE;

		/* OIDs must agree */
		if (oid_a.len != oid_b.len ||
			!memeq(oid_a.ptr, oid_b.ptr, oid_b.len))
			return FALSE;

		/* does rdn_b contain a wildcard? */
		if (wildcards != NULL && value_b.len == 1 && *value_b.ptr == '*') {
			(*wildcards)++;
			continue;
		}

		/* same lengths for values */
		if (value_a.len != value_b.len)
			return FALSE;

		/*
		 * printableStrings and email RDNs require uppercase
		 * comparison
		 */
		if (type_a == type_b &&
		    (type_a == ASN1_PRINTABLESTRING ||
		     (type_a == ASN1_IA5STRING &&
		      known_oid(oid_a) == OID_PKCS9_EMAIL))) {
			if (!strncaseeq((char *)value_a.ptr,
					(char *)value_b.ptr,
					value_b.len))
				return FALSE;
		} else {
			if (!strneq((char *)value_a.ptr, (char *)value_b.ptr,
				    value_b.len))
				return FALSE;
		}
	}
	/* both DNs must have same number of RDNs */
	if (next_a || next_b) {
		if (wildcards != NULL && *wildcards != 0) {
			/* ??? for some reason we think a failure with wildcards is worth logging */
			char abuf[ASN1_BUF_LEN];
			char bbuf[ASN1_BUF_LEN];

			dntoa(abuf, ASN1_BUF_LEN, a);
			dntoa(bbuf, ASN1_BUF_LEN, b);

			libreswan_log(
				"while comparing A='%s'<=>'%s'=B with a wildcard count of %d, %s had too few RDNs",
				abuf, bbuf, *wildcards,
				(next_a ? "B" : "A"));
		}
		return FALSE;
	}

	/* the two DNs match! */
	return TRUE;
}

/*
 * free the dynamic memory used to store generalNames
 */
void free_generalNames(generalName_t *gn, bool free_name)
{
	while (gn != NULL) {
		generalName_t *gn_top = gn;

		if (free_name)
			pfree(gn->name.ptr);
		gn = gn->next;
		pfree(gn_top);
	}
}
