/* Support of X.509 certificates and CRLs, for libreswan
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
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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

#include <stdlib.h>	/* for size_t */

#include "oid.h"
#include "x509.h"
#include "asn1.h"
#include "lswlog.h"
#include "id.h"

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
	*attribute = EMPTY_CHUNK;

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
			  chunk_t *value_ber,		/* output */
			  asn1_t *value_type,		/* output */
			  chunk_t *value_content,	/* output */
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

	*value_ber = body;
	*value_type = body.ptr[0];

	/* ??? what types of string are legitimate? */
	switch(*value_type) {
	case ASN1_PRINTABLESTRING:
	case ASN1_T61STRING:
	case ASN1_IA5STRING:
	case ASN1_UTF8STRING:
	case ASN1_BMPSTRING:
		break;
	default:
		dbg("unexpected ASN1 string type 0x%x", *value_type);
		return "unexpected ASN1 string type";
	}

	RETURN_IF_ERR(unwrap(*value_type, &body, value_content));

	if (body.len != 0)
		return "crap after OID and value pair of RDN";

	/* are there any RDNs left? */
	*more = rdn->len > 0 || attribute->len > 0;
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
		chunk_t value_ber;
		asn1_t value_type;
		chunk_t value_content;
		ugh = get_next_rdn(&rdn, &attribute, &oid,
				   &value_ber, &value_type, &value_content,
				   &more);
		if (ugh != NULL)
			return -1;

		if (value_content.len == 1 && value_content.ptr[0] == '*')
			wildcards++;	/* we have found a wildcard RDN */
	}
	return wildcards;
}

/*
 * Formats an ASN.1 Distinguished Name into an ASCII string of
 * OID/value pairs.  If there's a problem, return err_t (buf's
 * contents should be ignored).
 *
 * Since the raw output is fed to CERT_AsciiToName() and that,
 * according to the comments, expects RFC-1485 (1993) (A String
 * Representation of Distinguished Names (OSI-DS 23 (v5))) and
 * successors, this function should be emitting the same.
 *
 * RFC-1485 was obsoleted by RFC-1779 - A String Representation of
 * Distinguished Names - in 1995.
 *
 * XXX: added OID.N.N.N; added '#' prefix; added \ escape; according
 * to NSS bug 210584 this was all added to NSS 2019-12 years ago.

 * RFC-1779 was obsoleted by RFC-2253 - Lightweight Directory Access
 * Protocol (v3): UTF-8 String Representation of Distinguished Names -
 * in 1997.
 *
 * XXX: deprecated OID.N.N.N; according to NSS bug 1342137 this was
 * fixed 2019-2 years ago.
 *
 * RFC-2253 was obsoleted by RFC-4514 - Lightweight Directory Access
 * Protocol (v3): UTF-8 String Representation of Distinguished Names -
 * in 2006.
 *
 * Hence this tries to implement https://tools.ietf.org/html/rfc4514
 * using \<CHAR> for printable and \XX for non-printable.
 */

static err_t format_dn(struct jambuf *buf, chunk_t dn,
		       jam_bytes_fn *jam_bytes, bool nss_compatible)
{
	chunk_t rdn;
	chunk_t attribute;
	bool more;

	RETURN_IF_ERR(init_rdn(dn, &rdn, &attribute, &more));

	for (bool first = TRUE; more; first = FALSE) {
		chunk_t oid;
		chunk_t value_ber;
		asn1_t value_type;
		chunk_t value_content;
		RETURN_IF_ERR(get_next_rdn(&rdn, &attribute, &oid,
					   &value_ber, &value_type, &value_content,
					   &more));
		if (!first)
			jam(buf, ", ");

		/*
		 * 2.3.  Converting AttributeTypeAndValue
		 *
		 * The AttributeTypeAndValue is encoded as the string
		 * representation of the AttributeType, followed by an
		 * equals sign ('=' U+003D) character, followed by the
		 * string representation of the AttributeValue.  The
		 * encoding of the AttributeValue is given in Section
		 * 2.4.
		 *
		 * If the AttributeType is defined to have a short
		 * name (descriptor) [RFC4512] and that short name is
		 * known to be registered [REGISTRY] [RFC4520] as
		 * identifying the AttributeType, that short name, a
		 * <descr>, is used.  Otherwise the AttributeType is
		 * encoded as the dotted-decimal encoding, a
		 * <numericoid>, of its OBJECT IDENTIFIER.  The
		 * <descr> and <numericoid> are defined in [RFC4512].
		 *
		 * XXX: An early RFC defined this as OID.N.N.N but
		 * later the OID prefix was dropped.
		 */

		/* print OID */
		int oid_code = known_oid(oid);
		if (oid_code == OID_UNKNOWN) {
			/*
			 * 2.4.  Converting an AttributeValue from
			 * ASN.1 to a String
			 *
			 * If the AttributeType is of the
			 * dotted-decimal form, the AttributeValue is
			 * represented by an number sign ('#' U+0023)
			 * character followed by the hexadecimal
			 * encoding of each of the octets of the BER
			 * encoding of the X.500 AttributeValue.  This
			 * form is also used when the syntax of the
			 * AttributeValue does not have an LDAP-
			 * specific ([RFC4517], Section 3.1) string
			 * encoding defined for it, or the
			 * LDAP-specific string encoding is not
			 * restricted to UTF-8-encoded Unicode
			 * characters.  This form may also be used in
			 * other cases, such as when a reversible
			 * string representation is desired (see
			 * Section 5.2).
			 *
			 * XXX: i.e., N.M#BER
			 */
			const uint8_t *p = oid.ptr; /* cast void* */
			const uint8_t *end = p + oid.len;
			/* handled above? */
			if (!pexpect(p < end)) {
				return "OID length is zero";
			}
			/* first two nodes encoded in single byte */
			/* ??? where does 40 come from? */
			jam(buf, "%d.%d", *p / 40, *p % 40);
			p++;
			/* runs of 1xxxxxxx+ 0xxxxxxx */
			while (p < end) {
				uintmax_t n = 0;
				for (;;) {
					uint8_t b = *p++;
					if (n > UINTMAX_MAX >> 7)
						return "OID too large";

					n = (n << 7) | (b & 0x7f);
					/* stop at 0xxxxxxx */
					if (b < 0x80)
						break;

					if (p >= end)
						return "corrupt OID run encoding";
				}
				jam(buf, ".%ju", n);
			}
		} else {
			jam(buf, "%s", oid_names[oid_code].name);
		}
		jam(buf, "=");
		if (oid_code == OID_UNKNOWN ||
		    /*
		     * NSS totally screws up a leading '#' - stripping
		     * of the escape and then interpreting it as a
		     * #BER.
		     */
		    (nss_compatible &&
		     ((const char*)value_content.ptr)[0] == '#')) {
			/* BER */
			jam(buf, "#");
			for (unsigned i = 0; i < value_ber.len; i++) {
				uint8_t byte = ((const uint8_t*)value_ber.ptr)[i];
				jam(buf, "%02X", byte);
			}
		} else {

			const char *p = (void*) value_content.ptr; /* cast void */
			const char *end = p + value_content.len;

			/*
			 * - a space (' ' U+0020) or number sign ('#'
			 *   U+0023) occurring at the beginning of the
			 *   string;
			 *
			 * Per below, can be escaped using <ESC>
			 * <CHAR>.
			 *
			 * Note the singuar - a space - presumably
			 * only the first of these needs to be escaped
			 * as after that everything must be part of
			 * the string until either ',' or '+' or ';'
			 * is hit?
			 */
			if (p < end && (*p == ' ' || *p == '#')) {
				jam_bytes(buf, "\\", 1);
				jam_bytes(buf, p, 1);
				p++;
			}

			/*
			 * - a space (' ' U+0020) character occurring
			 *   at the end of the string;
			 *
			 * Again note the singular - a space - I guess
			 * the parser tosses a run of un-escaped
			 * spaces before a separator.
			 */
			unsigned trailing = 0;
			if (p < end && end[-1] == ' ') {
				trailing++;
				end--;
			}

			/*
			 * Emit the body:
			 *
			 * - one of the characters '"', '+', ',', ';',
			 *   '<', '>', or '\' (U+0022, U+002B, U+002C,
			 *   U+003B, U+003C, U+003E, or U+005C,
			 *   respectively);
			 *
			 * - the null (U+0000) character.
			 *
			 * Other characters may be escaped.
			 *
			 * [...]
			 *
			 * Each octet of the character to be escaped
			 * is replaced by a backslash and two hex
			 * digits, which form a single octet in the
			 * code of the character.  Alternatively, if
			 * and only if the character to be escaped is
			 * one of
			 *
			 *   ' ', '"', '#', '+', ',', ';', '<', '=',
			 *   '>', or '\' (U+0020, U+0022, U+0023,
			 *   U+002B, U+002C, U+003B, U+003C, U+003D,
			 *   U+003E, U+005C, respectively)
			 *
			 * it can be prefixed by a backslash ('\'
			 * U+005C).
			 *
			 * XXX: the below uses \XX to encode any
			 * character outside of [U+0020..U+007E].
			 * Since all bytes of a UTF-8 encoded code
			 * point have the top-bit set this works for
			 * UTF-8.
			 *
			 * XXX: following earlier code, the below
			 * tries to micro-optimize calls to
			 * jam_bytes() - runs of un-escaped characters
			 * are accumulated and then written using a
			 * single call.
			 *
			 * XXX: isprint() is affected by locale, and
			 * isascii() isn't considered portable; so use
			 * a simple compare.
			 */
			unsigned run = 0;
			while (p + run < end) {
				uint8_t c = p[run]; /* byte */
				bool needs_prefix = (c == '\\' ||
						     c == '\"' ||
						     c == '+' ||
						     c == ',' ||
						     c == ';' ||
						     c == '<' ||
						     c == '>');
				if (nss_compatible) {
					/*
					 * XXX: Old versions of NSS
					 * also wants these special
					 * characters escaped
					 * everywhere.
					 */
					needs_prefix = (needs_prefix ||
							c == '#' ||
							c == '=');
				}
				bool printable = (c >= 0x20 && c <= 0x7e &&
						  !needs_prefix);
				if (printable) {
					/*
					 * add to run of characters that don't
					 * need to be escaped
					 */
					run++;
				} else {
					/* emit previous run */
					jam_bytes(buf, p, run);
					if (needs_prefix) {
						/* <ESC> <CHAR> */
						jam_bytes(buf, "\\", 1);
						jam_bytes(buf, &c, 1);
					} else {
						/* <ESC> <HEX> <HEX> */
						jam_bytes(buf, "\\", 1);
						jam(buf, "%02X", c);
					}
					/* advance past this escaped character */
					p += run + 1;
					run = 0;
				}
			}
			/* emit final run */
			jam_bytes(buf, p, run);
			/*
			 * Escape any trailing ' ' characters; using \<CHAR>
			 * is ok; remember END had these stripped.
			 */
			for (unsigned i = 0; i < trailing; i++) {
				jam_bytes(buf, "\\", 1);
				jam_bytes(buf, &end[i], 1);
			}
		}
	}
	return NULL;
}

/*
 * Converts a binary DER-encoded ASN.1 distinguished name
 * into LDAP-style human-readable ASCII format
 */

void jam_raw_dn(struct jambuf *buf, chunk_t dn, jam_bytes_fn *jam_bytes,
		bool nss_compatible)
{
	/* save start in case things screw up */
	jampos_t pos = jambuf_get_pos(buf);
	err_t ugh = format_dn(buf, dn, jam_bytes, nss_compatible);
	if (ugh != NULL) {
		/* error: print DN as hex string */
		if (DBGP(DBG_BASE)) {
			dbg("error in DN parsing: %s", ugh);
			DBG_dump_hunk("Bad DN:", dn);
		}
		/* reset the buffer */
		jambuf_set_pos(buf, &pos);
		jam(buf, "0x");
		jam_HEX_bytes(buf, dn.ptr, dn.len);
	}
}

err_t parse_dn(chunk_t dn)
{
	dn_buf dnb;
	struct jambuf buf = ARRAY_AS_JAMBUF(dnb.buf);
	return format_dn(&buf, dn, jam_raw_bytes, true/*nss_compatible*/);
}

void jam_dn_or_null(struct jambuf *buf, chunk_t dn, const char *null_dn,
		    jam_bytes_fn *jam_bytes)
{
	if (dn.ptr == NULL) {
		jam(buf, "%s", null_dn);
	} else {
		jam_raw_dn(buf, dn, jam_bytes, true/*nss_compatible*/);
	}
}

const char *str_dn_or_null(chunk_t dn, const char *null_dn, dn_buf *dst)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(dst->buf);
	jam_dn_or_null(&buf, dn, null_dn, jam_sanitized_bytes);
	return dst->buf;
}

void jam_dn(struct jambuf *buf, chunk_t dn, jam_bytes_fn *jam_bytes)
{
	jam_dn_or_null(buf, dn, "(empty)", jam_bytes);
}

const char *str_dn(chunk_t dn, dn_buf *dst)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(dst->buf);
	jam_dn(&buf, dn, jam_sanitized_bytes);
	return dst->buf;
}

/*
 * Note that there may be as many as six IDs that are temporary at
 * one time before unsharing the two ends of a connection. So we need
 * at least six temporary buffers for DER_ASN1_DN IDs.
 * We rotate them. Be careful!
 */
#define MAX_BUF 6

static unsigned char *temporary_cyclic_buffer(void)
{
	/* MAX_BUF internal buffers */
	static unsigned char buf[MAX_BUF][IDTOA_BUF];
	static int counter;	/* cyclic counter */

	if (++counter == MAX_BUF)
		counter = 0;	/* next internal buffer */
	return buf[counter];	/* assign temporary buffer */
}

/*
 * Converts an LDAP-style human-readable ASCII-encoded
 * ASN.1 distinguished name into binary DER-encoded format.
 *
 * (*DN) is the result, and points at static data allocated by
 * temporary_cyclic_buffer.
 *
 * XXX: since caller is almost immediately calling clone_chunk() (or
 * unshare_id_content()) why not do it here.
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
	dbg("ASCII to DN <= \"%s\"", src);

	/* stack of unfilled lengths */
	unsigned char *(patchpoint[5]);	/* only 4 are actually needed */
	unsigned char **ppp = patchpoint;

	/* space for result */
	dn->ptr = temporary_cyclic_buffer();	/* nasty! */

	unsigned char *dn_ptr = dn->ptr;	/* growth point */
	unsigned char *dn_redline = dn_ptr + IDTOA_BUF;

#	define START_OBJ() { *ppp++ = dn_ptr; }

	/* note: on buffer overflow this returns from atodn */
	/* ??? all but one call has len==1 so we could simplify */
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

		src += strspn(src, " /,");	/* skip any separators */
		if (*src == '\0')
			break;	/* finished! */

		/* parse OID */

		START_OBJ();	/* 1 ASN1_SET */
		START_OBJ();	/* 2 ASN1_SEQUENCE */
		START_OBJ();	/* 3 ASN1_OID */

		x501rdn_t *op;	/* OID description */
		if (*src >= '0' && *src <= '9') {
			op = NULL; /* so #BER is expected */
			char *end;
			uint8_t byte;
			/* B1.B2 */
			unsigned long b0a = strtoul(src, &end, 10);
			/* ??? where does 40 come from? */
			if (src == end || b0a > UINT8_MAX / 40) {
				return "numeric OID has invalid first digit";
			}
			src = end;
			if (src[0] != '.') {
				return "numeric OID missing first '.'";
			}
			src++;
			unsigned long b0b = strtoul(src, &end, 10);
			if (src == end || b0b >= 40) {
				return "numeric OID has invalid second digit";
			}
			src = end;
			byte = b0a * 40 + b0b;
			EXTEND_OBJ(&byte, 1);
			/* .B ... */
			while (src[0] == '.') {
				src++;
				unsigned long b = strtoul(src, &end, 10);
				if (src == end) {
					return "numeric OID has invalid second digit";
				}
				src = end;
				/* XXX: this is neither smart nor efficient */
				while (b >= 128) {
					unsigned long l = b;
					unsigned shifts = 0;
					while (l >= 128) {
						l >>= 7;
						shifts += 7;
					}
					byte = l | 0x80;
					EXTEND_OBJ(&byte, 1);
					b -= l << shifts;
				}
				byte = b;
				EXTEND_OBJ(&byte, 1);
			}
		} else {
			size_t ol = strcspn(src, " =");	/* length of OID name */
			for (op = x501rdns; ; op++) {
				if (op == &x501rdns[elemsof(x501rdns)]) {
					dbg("unknown OID: \"%.*s\"",
					    (int)ol, src);
					return "unknown OID in ID_DER_ASN1_DN";
				}
				if (strlen(op->name) == ol && strncaseeq(op->name, src, ol)) {
					break;	/* found */
				}
			}
			EXTEND_OBJ(op->oid_ptr, op->oid_len);
			src += ol;
		}

		END_OBJ(ASN1_OID);	/* 3 */

		/* = */

		src += strspn(src, " ");	/* skip white space */
		if (*src != '=') {
			return "missing '='";
		}
		src++;
		src += strspn(src, " ");	/* skip white space */

		if (src[0] == '#') {
			/* assume it is a BER and parse the raw hex dump */
			src++;
			while (char_isxdigit(src[0]) && char_isxdigit(src[1])) {
				char hex[3] = { src[0], src[1], };
				uint8_t byte = strtol(hex, NULL, 16);
				EXTEND_OBJ(&byte, 1);
				src += 2;
			}
		} else if (*src == '"') {
			return "obsolete rfc1779 quoting using '\"' not supported";
		} else {
			if (op == NULL) {
				return "numeric OID requires #HEXPAIR BER";
			}
			/* parse value */

			START_OBJ();	/* 3 op->type or ASN1_T61STRING */

			uint8_t *escape_stop = dn_ptr;
			while (src[0] != '\0' &&
			       src[0] != ',' &&
			       /* XXX: where did '/' come from? */
			       src[0] != '/') {
				/* assume nul termination */
				if (src[0] == '\\' && isxdigit(src[1]) && isxdigit(src[2])) {
					char hex[3] = { src[1], src[2], };
					uint8_t byte = strtol(hex, NULL, 16);
					EXTEND_OBJ(&byte, 1);
					src += 3;
					escape_stop = dn_ptr;
				} else if (src[0] == '\\' && src[1] != '\0') {
					EXTEND_OBJ(&src[1], 1);
					src += 2;
					escape_stop = dn_ptr;
				} else if ((src[0] == ',' || src[0] == '/') &&
					   src[0] == src[1]) {
					/*
					 * doubled: a form of escape.  Insert
					 * a single copy of the char.
					 *
					 * XXX: ',,' came from rhbz#868986;
					 * '//' was added shortly after; both
					 * are bogus.
					 */
					EXTEND_OBJ(src, 1);
					src += 2;	/* skip both copies */
					escape_stop = dn_ptr;
				} else {
					EXTEND_OBJ(src, 1);
					src++;
				}
			}

			/* remove trailing SPaces from name operand */
			/* XXX: but not escaped */

			while (dn_ptr > escape_stop && dn_ptr[-1] == ' ')
				dn_ptr--;

			unsigned char *ns = ppp[-1];	/* name operand start */
			asn1_t t = op->type == ASN1_PRINTABLESTRING &&
				!is_printablestring(chunk2(ns, dn_ptr - ns)) ?
				ASN1_T61STRING : op->type;

			END_OBJ(t);	/* 3 value */
		}

		END_OBJ(ASN1_SEQUENCE);	/* 2 */
		END_OBJ(ASN1_SET);	/* 1 */
	}

	END_OBJ(ASN1_SEQUENCE);	/* 0 */
	dn->len = dn_ptr - dn->ptr;
	if (DBGP(DBG_BASE)) {
		DBG_dump_hunk("ASCII to DN =>", *dn);
	}
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
			dbg("match_dn bad a: %s", ua);
			return FALSE;
		}

		err_t ub = init_rdn(b, &rdn_b, &attribute_b, &more_b);
		if (ub != NULL) {
			dbg("match_dn bad b: %s", ub);
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
		chunk_t value_ber_a, value_ber_b;
		asn1_t value_type_a, value_type_b;
		chunk_t value_content_a, value_content_b;

		{
			err_t ua = get_next_rdn(&rdn_a, &attribute_a, &oid_a,
						&value_ber_a, &value_type_a, &value_content_a,
						&more_a);
			if (ua != NULL) {
				dbg("match_dn bad a[%d]: %s", n, ua);
				return FALSE;
			}

			err_t ub = get_next_rdn(&rdn_b, &attribute_b, &oid_b,
						&value_ber_b, &value_type_b, &value_content_b,
						&more_b);
			if (ub != NULL) {
				dbg("match_dn bad b[%d]: %s", n, ub);
				return FALSE;
			}
		}

		/* OIDs must agree */
		if (!hunk_eq(oid_a, oid_b))
			return FALSE;

		/* does rdn_b contain a wildcard? */
		/* ??? this does not care whether types match.  Should it? */
		if (wildcards != NULL &&
		    value_content_b.len == 1 &&
		    value_content_b.ptr[0] == '*') {
			(*wildcards)++;
			continue;
		}

		if (value_content_a.len != value_content_b.len)
			return FALSE;	/* lengths must match */

		/*
		 * If the two types treat the high bit differently
		 * or if ASN1_PRINTABLESTRING is involved,
		 * we must forbid the high bit.
		 */
		if (value_type_a != value_type_b ||
		    value_type_a == ASN1_PRINTABLESTRING) {
			unsigned char or = 0x00;
			for (size_t i = 0; i != value_content_a.len; i++)
				or |= value_content_a.ptr[i] | value_content_b.ptr[i];
			if (or & 0x80)
				return FALSE;
		}

		/*
		 * even though the types may differ, we assume that
		 * their bits can be compared.
		 */

		/* cheap match, as if case matters */
		if (memeq(value_content_a.ptr, value_content_b.ptr, value_content_a.len))
			continue;

		/*
		 * printableStrings and email RDNs require comparison
		 * ignoring case.
		 * We do require that the types match.
		 * Forbid NUL in such strings.
		 */

		if ((value_type_a == ASN1_PRINTABLESTRING ||
		     (value_type_a == ASN1_IA5STRING &&
		      known_oid(oid_a) == OID_PKCS9_EMAIL)) &&
		    strncaseeq((char *)value_content_a.ptr,
				(char *)value_content_b.ptr, value_content_b.len) &&
		    memchr(value_content_a.ptr, '\0', a.len) == NULL)
		{
			continue;	/* component match */
		}
		return FALSE;	/* not a match */
	}

	/* both DNs must have same number of RDNs */
	if (more_a || more_b) {
		if (wildcards != NULL && *wildcards != 0) {
			dn_buf abuf;
			dn_buf bbuf;
			dbg("while comparing A='%s'<=>'%s'=B with a wildcard count of %d, %s had too few RDNs",
			    str_dn(a, &abuf), str_dn(b, &bbuf), *wildcards,
			    (more_a ? "B" : "A"));
		}
		return false;
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
