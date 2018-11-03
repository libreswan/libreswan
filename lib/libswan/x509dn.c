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
 * Copyright (C) 2013-2018 D. Hugh Redelmeier <hugh@mimosa.com>
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
#include "constants.h"
#include "lswlog.h"
#include "lswalloc.h"
#include "id.h"
#include "asn1.h"
#include "oid.h"
#include "x509.h"
#include "lswconf.h"

static void hex_str(chunk_t bin, chunk_t *str);	/* forward */

/* coding of X.501 distinguished name */
typedef const struct {
	const char *name;
	const unsigned char *oid_ptr;
	size_t oid_len;
	asn1_t type;
} x501rdn_t;

/* X.501 acronyms for well known object identifiers (OIDs) */
static const unsigned char oid_ND[] = { 0x02, 0x82, 0x06, 0x01, 0x0A, 0x07, 0x14 };
static const unsigned char oid_UID[] = { 0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64,
				0x01, 0x01 };
static const unsigned char oid_DC[] = { 0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64,
				0x01, 0x19 };
static const unsigned char oid_CN[] = { 0x55, 0x04, 0x03 };
static const unsigned char oid_S[] = { 0x55, 0x04, 0x04 };
static const unsigned char oid_SN[] = { 0x55, 0x04, 0x05 };
static const unsigned char oid_C[] = { 0x55, 0x04, 0x06 };
static const unsigned char oid_L[] = { 0x55, 0x04, 0x07 };
static const unsigned char oid_ST[] = { 0x55, 0x04, 0x08 };
static const unsigned char oid_O[] = { 0x55, 0x04, 0x0A };
static const unsigned char oid_OU[] = { 0x55, 0x04, 0x0B };
static const unsigned char oid_T[] = { 0x55, 0x04, 0x0C };
static const unsigned char oid_D[] = { 0x55, 0x04, 0x0D };
static const unsigned char oid_N[] = { 0x55, 0x04, 0x29 };
static const unsigned char oid_G[] = { 0x55, 0x04, 0x2A };
static const unsigned char oid_I[] = { 0x55, 0x04, 0x2B };
static const unsigned char oid_ID[] = { 0x55, 0x04, 0x2D };
static const unsigned char oid_E[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09,
				0x01 };
static const unsigned char oid_UN[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09,
				0x02 };
static const unsigned char oid_TCGID[] = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x89, 0x31, 0x01,
				0x01, 0x02, 0x02, 0x4B };

static const x501rdn_t x501rdns[] = {
#	define OC(oid) oid, sizeof(oid)

	{ "ND", OC(oid_ND), ASN1_PRINTABLESTRING },
	{ "UID", OC(oid_UID), ASN1_PRINTABLESTRING },
	{ "DC", OC(oid_DC), ASN1_PRINTABLESTRING },
	{ "CN", OC(oid_CN), ASN1_PRINTABLESTRING },
	{ "S", OC(oid_S), ASN1_PRINTABLESTRING },
	{ "SN", OC(oid_SN), ASN1_PRINTABLESTRING },
	{ "serialNumber", OC(oid_SN), ASN1_PRINTABLESTRING },
	{ "C", OC(oid_C), ASN1_PRINTABLESTRING },
	{ "L", OC(oid_L), ASN1_PRINTABLESTRING },
	{ "ST", OC(oid_ST), ASN1_PRINTABLESTRING },
	{ "O", OC(oid_O), ASN1_PRINTABLESTRING },
	{ "OU", OC(oid_OU), ASN1_PRINTABLESTRING },
	{ "T", OC(oid_T), ASN1_PRINTABLESTRING },
	{ "D", OC(oid_D), ASN1_PRINTABLESTRING },
	{ "N", OC(oid_N), ASN1_PRINTABLESTRING },
	{ "G", OC(oid_G), ASN1_PRINTABLESTRING },
	{ "I", OC(oid_I), ASN1_PRINTABLESTRING },
	{ "ID", OC(oid_ID), ASN1_PRINTABLESTRING },
	{ "E", OC(oid_E), ASN1_IA5STRING },
	{ "Email", OC(oid_E), ASN1_IA5STRING },
	{ "emailAddress", OC(oid_E), ASN1_IA5STRING },
	{ "UN", OC(oid_UN), ASN1_IA5STRING },
	{ "unstructuredName", OC(oid_UN), ASN1_IA5STRING },
	{ "TCGID", OC(oid_TCGID), ASN1_PRINTABLESTRING }

#	undef OC
};

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
 * Routines to iterate through a DN.
 * rdn: remainder of the sequence of RDNs
 * attribute: remainder of the current RDN.
 */

/* Structure of the DN:
 *
 * ASN_SEQUENCE {
 *	for each Relative DN {
 *		ASN1_SET {
 *			ASN1_SEQUENCE {
 *				ASN1_OID {
 *					oid
 *				}
 *				ASN1_*STRING* {
 *					value
 *				}
 *			}
 *		}
 *	}
 * }
 */

#define RETURN_IF_ERR(f) { err_t ugh = (f); if (ugh != NULL) return ugh; }

static err_t unwrap(asn1_t ty, chunk_t *container, chunk_t *contents)
{
	if (container->len == 0)
		return "missing ASN1 type";
	if (container->ptr[0] != ty)
		return "unexpected ASN1 type";
	size_t sz = asn1_length(container);
	if (sz == ASN1_INVALID_LENGTH)
		return "invalid ASN1 length";
	if (sz > container->len)
		return "ASN1 length larger than space";
	contents->ptr = container->ptr;
	contents->len = sz;
	container->ptr += sz;
	container->len -= sz;
	return NULL;
}

static err_t init_rdn(chunk_t dn, /* input (copy) */
		chunk_t *rdn, /* output */
		chunk_t *attribute, /* output */
		bool *more) /* output */
{
	*attribute = empty_chunk;

	/* a DN is a SEQUENCE OF RDNs */
	RETURN_IF_ERR(unwrap(ASN1_SEQUENCE, &dn, rdn));

	/* the whole DN should be this ASN1_SEQUENCE */
	if (dn.len != 0)
		return "DN has crud after ASN1_SEQUENCE";

	*more = rdn->len != 0;
	return NULL;
}

/*
 * Fetches the next RDN in a DN
 */
static err_t get_next_rdn(chunk_t *rdn,	/* input/output */
	chunk_t *attribute, /* input/output */
	chunk_t *oid /* output */,
	asn1_t *val_ty,	/* output */
	chunk_t *value,	/* output */
	bool *more) /* output */
{
	/* if all attributes have been parsed, get next rdn */
	if (attribute->len == 0) {
		/*
		 * An RDN is a SET OF attributeTypeAndValue.
		 * Strip off the ASN1_set wrapper.
		 */
		RETURN_IF_ERR(unwrap(ASN1_SET, rdn, attribute));
	}

	/* An attributeTypeAndValue is a SEQUENCE */
	chunk_t body;
	RETURN_IF_ERR(unwrap(ASN1_SEQUENCE, attribute, &body));

	/* extract oid from body */

	RETURN_IF_ERR(unwrap(ASN1_OID, &body, oid));

	/* extract string value and its type from body */

	if (body.len == 0)
		return "no room for string's type";

	*val_ty = body.ptr[0];

	/* ??? what types of string are legitimate? */
	switch(*val_ty) {
	case ASN1_PRINTABLESTRING:
	case ASN1_T61STRING:
	case ASN1_IA5STRING:
	case ASN1_UTF8STRING:	/* ??? will this work? */
	case ASN1_BMPSTRING:
		break;
	default:
		DBGF(DBG_X509, "unexpected ASN1 string type 0x%x", *val_ty);
		return "unexpected ASN1 string type";
	}

	RETURN_IF_ERR(unwrap(*val_ty, &body, value));

	if (body.len != 0)
		return "crap after OID and value pair of RDN";

	/* are there any RDNs left? */
	*more = rdn->len > 0 || attribute->len > 0;
	return NULL;
}

/*
 * Parses an ASN.1 distinguished name into its OID/value pairs
 */
static err_t dn_parse(chunk_t dn, chunk_t *str)
{
	chunk_t rdn;
	chunk_t attribute;
	bool more;

	if (dn.ptr == NULL) {
		format_chunk(str, "(empty)");
		return NULL;
	}
	RETURN_IF_ERR(init_rdn(dn, &rdn, &attribute, &more));

	for (bool first = TRUE; more; first = FALSE) {
		chunk_t oid;
		asn1_t type;
		chunk_t value;
		RETURN_IF_ERR(get_next_rdn(&rdn, &attribute, &oid, &type, &value,
				   &more));
		if (!first)
			format_chunk(str, ", ");

		/* print OID */
		int oid_code = known_oid(oid);
		if (oid_code == OID_UNKNOWN)	/* OID not found in list */
			hex_str(oid, str);
		else
			format_chunk(str, "%s", oid_names[oid_code].name);

		format_chunk(str, "=");
		/* print value, doubling any ',' and '/' */
		unsigned char *p = value.ptr;
		size_t l = value.len;
		for (size_t i = 0; i<l; ) {
			if (p[i] == ',' || p[i] == '/') {
				/* character p[i] must be doubled */
				format_chunk(str, "%.*s%c", (int)(i + 1), p, p[i]);
				l -= i + 1;
				p += i + 1;
				i = 0;
			} else {
				i++;
			}
		}
		format_chunk(str, "%.*s", (int)l, p);
	}
	return NULL;
}

/*
 * Count the number of wildcard RDNs in a distinguished name; -1 signifies error.
 */
int dn_count_wildcards(chunk_t dn)
{
	chunk_t rdn;
	chunk_t attribute;
	bool more;
	int wildcards = 0;

	err_t ugh = init_rdn(dn, &rdn, &attribute, &more);
	if (ugh != NULL)
		return -1;

	while (more) {
		chunk_t oid;
		asn1_t type;
		chunk_t value;
		ugh = get_next_rdn(&rdn, &attribute, &oid, &type, &value,
				   &more);
		if (ugh != NULL)
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
	format_chunk(str, "0x");
	for (unsigned i = 0; i < bin.len; i++)
		format_chunk(str, "%02X", *bin.ptr++);
}

/*
 * Converts a binary DER-encoded ASN.1 distinguished name
 * into LDAP-style human-readable ASCII format
 */
int dntoa(char *dst, size_t dstlen, chunk_t dn)
{
	chunk_t str;

	str.ptr = (unsigned char *)dst;
	str.len = dstlen;
	err_t ugh = dn_parse(dn, &str);

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
	return dn.ptr == NULL ?
		snprintf(dst, dstlen, "%s", null_dn) :
		dntoa(dst, dstlen, dn);
}

/*
 * Converts an LDAP-style human-readable ASCII-encoded
 * ASN.1 distinguished name into binary DER-encoded format.
 * *dn is the result, allocated by temporary_cyclic_buffer.
 *
 * Structure of the output:
 *
 * ASN_SEQUENCE {
 *	for each Relative DN {
 *		ASN1_SET {
 *			ASN1_SEQUENCE {
 *				ASN1_OID {
 *					op->oid
 *				}
 *				op->type|ASN1_PRINTABLESTRING {
 *					name
 *				}
 *			}
 *		}
 *	}
 * }
 */
err_t atodn(const char *src, chunk_t *dn)
{
	DBGF(DBG_X509, "ASCII to DN <= \"%s\"", src);

	/* stack of unfilled lengths */
	unsigned char *(patchpoint[5]);	/* only 4 are actually needed */
	unsigned char **ppp = patchpoint;

	/* space for result */
	dn->ptr = temporary_cyclic_buffer();	/* nasty! */

	unsigned char *dn_ptr = dn->ptr;	/* growth point */
	unsigned char *dn_redline = dn_ptr + IDTOA_BUF;

#	define START_OBJ() { *ppp++ = dn_ptr; }

	/* note: on buffer overflow this returns from atodn */
#	define EXTEND_OBJ(ptr, len) { \
		if (dn_redline - dn_ptr < (ptrdiff_t)(len)) \
			return "DN too big"; \
		memcpy(dn_ptr, (ptr), (len)); \
		dn_ptr += (len); \
	}

	/*
	 * insert type and operand length before the operand already in the buffer
	 * Note: on buffer overflow this returns from atodn
	 */
#	define END_OBJ(ty) { \
		size_t len = dn_ptr - *--ppp; \
		unsigned char len_buf[ASN1_MAX_LEN_LEN + 1] = { ty }; \
		chunk_t obj_len = { len_buf + 1, 0 }; \
		code_asn1_length(len, &obj_len); \
		if (dn_redline - dn_ptr < (ptrdiff_t)obj_len.len + 1) \
			return "DN overflow"; \
		memmove(*ppp + obj_len.len + 1, *ppp, len); \
		memcpy(*ppp, len_buf, obj_len.len + 1); \
		dn_ptr += obj_len.len + 1; \
	}

	START_OBJ();	/* 0 ASN1_SEQUENCE */

	for (;;) {
		/* for each Relative DN */

		/* ??? are multiple '/' and ',' OK? */
		src += strspn(src, " /,");	/* skip any separators */
		if (*src == '\0')
			break;	/* finished! */

		/* parse OID */

		START_OBJ();	/* 1 ASN1_SET */
		START_OBJ();	/* 2 ASN1_SEQUENCE */

		size_t ol = strcspn(src, " =");	/* length of OID name */

		x501rdn_t *op;	/* OID description */

		for (op = x501rdns; ; op++) {
			if (op == &x501rdns[elemsof(x501rdns)]) {
				DBGF(DBG_X509, "unknown OID: \"%.*s\"",
					(int)ol, src);
				return "unknown OID in ID_DER_ASN1_DN";
			}
			if (strlen(op->name) == ol && strncaseeq(op->name, src, ol)) {
				break;	/* found */
			}
		}

		src += ol;

		START_OBJ();	/* 3 ASN1_OID */
		EXTEND_OBJ(op->oid_ptr, op->oid_len);
		END_OBJ(ASN1_OID);	/* 3 */

		/* parse name */

		/* ??? are multiple '=' OK? */
		src += strspn(src, " =");	/* skip any separators */

		START_OBJ();	/* 3 op->type or ASN1_T61STRING */

		for (;;) {
			size_t nl = strcspn(src, ",/");

			EXTEND_OBJ(src, nl);
			src += nl;

			if (src[0] == '\0' || src[0] != src[1])
				break;	/* end of name */
			/*
			 * doubled: a form of escape.
			 * Insert a single copy of the char.
			 */
			EXTEND_OBJ(src, 1);
			src += 2;	/* skip both copies */
		}

		/* remove trailing SPaces from name operand */

		unsigned char *ns = ppp[-1];	/* name operand start */

		while (dn_ptr > ns && dn_ptr[-1] == ' ')
			dn_ptr--;

		asn1_t t = op->type == ASN1_PRINTABLESTRING &&
			!is_printablestring(chunk(ns, dn_ptr - ns)) ?
				ASN1_T61STRING : op->type;

		END_OBJ(t);	/* 3 name */

		END_OBJ(ASN1_SEQUENCE);	/* 2 */
		END_OBJ(ASN1_SET);	/* 1 */
	}

	END_OBJ(ASN1_SEQUENCE);	/* 0 */
	dn->len = dn_ptr - dn->ptr;
	DBG_cond_dump_chunk(DBG_X509, "ASCII to DN =>", *dn);
	return NULL;

#	undef START_OBJ
#	undef EXTEND_OBJ
#	undef END_OBJ
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
	chunk_t rdn_a, rdn_b;
	chunk_t attribute_a, attribute_b;
	bool more_a, more_b;

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

	/*
	 * initialize DN parsing.  Stop (silently) on errors.
	 */
	{
		err_t ua = init_rdn(a, &rdn_a, &attribute_a, &more_a);
		if (ua != NULL) {
			DBGF(DBG_X509, "match_dn bad a: %s", ua);
			return FALSE;
		}

		err_t ub = init_rdn(b, &rdn_b, &attribute_b, &more_b);
		if (ub != NULL) {
			DBGF(DBG_X509, "match_dn bad b: %s", ub);
			return FALSE;
		}
	}

	/* fetch next RDN pair */
	for (int n = 1; more_a && more_b; n++) {
		/*
		 * Parse next RDNs and check for errors
		 * but don't report errors.
		 */
		chunk_t oid_a, oid_b;
		asn1_t type_a, type_b;
		chunk_t value_a, value_b;

		{
			err_t ua = get_next_rdn(&rdn_a, &attribute_a, &oid_a,
				 &type_a, &value_a, &more_a);
			if (ua != NULL) {
				DBGF(DBG_X509, "match_dn bad a[%d]: %s", n, ua);
				return FALSE;
			}

			err_t ub = get_next_rdn(&rdn_b, &attribute_b, &oid_b,
				 &type_b, &value_b, &more_b);
			if (ub != NULL) {
				DBGF(DBG_X509, "match_dn bad b[%d]: %s", n, ub);
				return FALSE;
			}
		}

		/* OIDs must agree */
		if (!chunk_eq(oid_a, oid_b))
			return FALSE;

		/* does rdn_b contain a wildcard? */
		/* ??? this does not care whether types match.  Should it? */
		if (wildcards != NULL && value_b.len == 1 && *value_b.ptr == '*') {
			(*wildcards)++;
			continue;
		}

		if (value_a.len != value_b.len)
			return FALSE;	/* lengths must match */

		/*
		 * If the two types treat the high bit differently
		 * or if ASN1_PRINTABLESTRING is involved,
		 * we must forbid the high bit.
		 */
		if (type_a != type_b || type_a == ASN1_PRINTABLESTRING) {
			unsigned char or = 0x00;
			for (size_t i = 0; i != value_a.len; i++)
				or |= value_a.ptr[i] | value_b.ptr[i];
			if (or & 0x80)
				return FALSE;
		}

		/*
		 * even though the types may differ, we assume that
		 * their bits can be compared.
		 */

		/* cheap match, as if case matters */
		if (memeq(value_a.ptr, value_b.ptr, value_a.len))
			continue;

		/*
		 * printableStrings and email RDNs require comparison
		 * ignoring case.
		 * We do require that the types match.
		 * Forbid NUL in such strings.
		 */

		if ((type_a == ASN1_PRINTABLESTRING ||
		     (type_a == ASN1_IA5STRING &&
		      known_oid(oid_a) == OID_PKCS9_EMAIL)) &&
		    strncaseeq((char *)value_a.ptr,
				(char *)value_b.ptr, value_b.len) &&
		    memchr(value_a.ptr, '\0', a.len) == NULL)
		{
			continue;	/* component match */
		}
		return FALSE;	/* not a match */
	}

	/* both DNs must have same number of RDNs */
	if (more_a || more_b) {
		if (wildcards != NULL && *wildcards != 0) {
			/* ??? for some reason we think a failure with wildcards is worth logging */
			char abuf[ASN1_BUF_LEN];
			char bbuf[ASN1_BUF_LEN];

			dntoa(abuf, ASN1_BUF_LEN, a);
			dntoa(bbuf, ASN1_BUF_LEN, b);

			libreswan_log(
				"while comparing A='%s'<=>'%s'=B with a wildcard count of %d, %s had too few RDNs",
				abuf, bbuf, *wildcards,
				(more_a ? "B" : "A"));
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
