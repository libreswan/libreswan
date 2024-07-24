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

#include <stddef.h>	/* for size_t */

#include "oid.h"
#include "x509.h"
#include "asn1.h"
#include "lswlog.h"
#include "id.h"
#include "lswalloc.h"

/* coding of X.501 distinguished name */
typedef const struct {
	const char *name;
	const unsigned char *oid_ptr;
	size_t oid_len;
	enum asn1_type type;
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

static err_t init_rdn(asn1_t dn, /* input (copy) */
		      asn1_t *rdn, /* output */
		      asn1_t *attribute, /* output */
		      bool *more) /* output */
{
	*attribute = (asn1_t) NULL_HUNK;

	/* a DN is a SEQUENCE OF RDNs */
	RETURN_IF_ERR(unwrap_asn1_tlv(&dn, ASN1_SEQUENCE, rdn));

	/* the whole DN should be this ASN1_SEQUENCE */
	if (dn.len != 0)
		return "DN has crud after ASN1_SEQUENCE";

	*more = rdn->len != 0;
	return NULL;
}

/*
 * Fetches the next RDN in a DN
 */
static err_t get_next_rdn(asn1_t *rdn,	/* input/output */
			  asn1_t *attribute, /* input/output */
			  asn1_t *oid /* output */,
			  asn1_t *value_ber,		/* output */
			  enum asn1_type *value_type,	/* output */
			  asn1_t *value_content,	/* output */
			  bool *more) /* output */
{
	/* if all attributes have been parsed, get next rdn */
	if (attribute->len == 0) {
		/*
		 * An RDN is a SET OF attributeTypeAndValue.
		 * Strip off the ASN1_set wrapper.
		 */
		RETURN_IF_ERR(unwrap_asn1_tlv(rdn, ASN1_SET, attribute));
	}

	/* An attributeTypeAndValue is a SEQUENCE */
	asn1_t body;
	RETURN_IF_ERR(unwrap_asn1_tlv(attribute, ASN1_SEQUENCE, &body));

	/* extract oid from body */

	RETURN_IF_ERR(unwrap_asn1_tlv(&body, ASN1_OID, oid));

	/* extract string value and its type from body */

	if (body.len == 0)
		return "no room for string's type";

	*value_ber = body;
	RETURN_IF_ERR(unwrap_asn1_type(&body, value_type));

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

	size_t length;
	RETURN_IF_ERR(unwrap_asn1_length(&body, &length));
	RETURN_IF_ERR(unwrap_asn1_value(&body, length, value_content));

	if (body.len != 0)
		return "crap after OID and value pair of RDN";

	/* are there any RDNs left? */
	*more = rdn->len > 0 || attribute->len > 0;
	return NULL;
}

/*
 * Count the number of wildcard RDNs in a distinguished name; -1 signifies error.
 */
bool dn_has_wildcards(asn1_t dn)
{
	asn1_t rdn;
	asn1_t attribute;
	bool more;

	err_t ugh = init_rdn(dn, &rdn, &attribute, &more);
	if (ugh != NULL) {
		return false;
	}

	while (more) {
		asn1_t oid;
		asn1_t value_ber;
		enum asn1_type value_type;
		asn1_t value_content;
		ugh = get_next_rdn(&rdn, &attribute, &oid,
				   &value_ber, &value_type, &value_content,
				   &more);
		if (ugh != NULL) {
			return false;
		}

		if (value_content.len == 1 &&
		    *(const char*)value_content.ptr == '*') {
			return true;	/* we have found a wildcard RDN */
		}
	}

	return false;
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
 * to NSS bug 210584 this was all added in 2007.
 *
 * RFC-1779 was obsoleted by RFC-2253 - Lightweight Directory Access
 * Protocol (v3): UTF-8 String Representation of Distinguished Names -
 * in 1997.
 *
 * XXX: deprecated OID.N.N.N; according to NSS bug 1342137 this was
 * fixed in 2017.
 *
 * RFC-2253 was obsoleted by RFC-4514 - Lightweight Directory Access
 * Protocol (v3): UTF-8 String Representation of Distinguished Names -
 * in 2006.
 *
 * Hence this tries to implement https://tools.ietf.org/html/rfc4514
 * using \<CHAR> for printable and \XX for non-printable.
 *
 * See also NSS bug 1709676.
 */

static err_t format_dn(struct jambuf *buf, asn1_t dn,
		       jam_bytes_fn *jam_bytes, bool nss_compatible,
		       size_t *ss)
{
	asn1_t rdn;
	asn1_t attribute;
	bool more;
	size_t s = 0;

	RETURN_IF_ERR(init_rdn(dn, &rdn, &attribute, &more));

	for (bool first = true; more; first = false) {
		asn1_t oid;
		asn1_t value_ber;
		enum asn1_type value_type;
		asn1_t value_content;
		RETURN_IF_ERR(get_next_rdn(&rdn, &attribute, &oid,
					   &value_ber, &value_type, &value_content,
					   &more));
		if (!first) {
			s += jam_string(buf, ", ");
		}

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
			s += jam(buf, "%d.%d", *p / 40, *p % 40);
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
				s += jam(buf, ".%ju", n);
			}
		} else {
			s += jam_string(buf, oid_names[oid_code].name);
		}
		s += jam_string(buf, "=");
		if (oid_code == OID_UNKNOWN ||
		    /*
		     * NSS totally screws up a leading '#' - stripping
		     * off the escape and then interpreting it as a
		     * #BER.
		     */
		    (nss_compatible &&
		     ((const char*)value_content.ptr)[0] == '#')) {
			/* BER */
			s += jam_string(buf, "#");
			for (unsigned i = 0; i < value_ber.len; i++) {
				uint8_t byte = ((const uint8_t*)value_ber.ptr)[i];
				s += jam(buf, "%02X", byte);
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
				s += jam_bytes(buf, "\\", 1);
				s += jam_bytes(buf, p, 1);
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
					s += jam_bytes(buf, p, run);
					if (needs_prefix) {
						/* <ESC> <CHAR> */
						s += jam_bytes(buf, "\\", 1);
						s += jam_bytes(buf, &c, 1);
					} else {
						/* <ESC> <HEX> <HEX> */
						s += jam_bytes(buf, "\\", 1);
						s += jam(buf, "%02X", c);
					}
					/* advance past this escaped character */
					p += run + 1;
					run = 0;
				}
			}
			/* emit final run */
			s += jam_bytes(buf, p, run);
			/*
			 * Escape any trailing ' ' characters; using \<CHAR>
			 * is ok; remember END had these stripped.
			 */
			for (unsigned i = 0; i < trailing; i++) {
				s += jam_bytes(buf, "\\", 1);
				s += jam_bytes(buf, &end[i], 1);
			}
		}
	}
	*ss = s;
	return NULL;
}

/*
 * Converts a binary DER-encoded ASN.1 distinguished name
 * into LDAP-style human-readable ASCII format
 */

size_t jam_raw_dn(struct jambuf *buf, asn1_t dn, jam_bytes_fn *jam_bytes,
		  bool nss_compatible)
{
	size_t s = 0;
	/* save start in case things screw up */
	jampos_t pos = jambuf_get_pos(buf);
	err_t ugh = format_dn(buf, dn, jam_bytes, nss_compatible, &s);
	if (ugh != NULL) {
		/* error: print DN as hex string */
		if (DBGP(DBG_BASE)) {
			dbg("error in DN parsing: %s", ugh);
			DBG_dump_hunk("Bad DN:", dn);
		}
		/* reset the buffer */
		jambuf_set_pos(buf, &pos);
		s = 0;
		s += jam_string(buf, "0x");
		s += jam_HEX_bytes(buf, dn.ptr, dn.len);
	}
	return s;
}

err_t parse_dn(asn1_t dn)
{
	dn_buf dnb;
	struct jambuf buf = ARRAY_AS_JAMBUF(dnb.buf);
	size_t s;/*ignored*/
	return format_dn(&buf, dn, jam_raw_bytes, true/*nss_compatible*/, &s);
}

size_t jam_dn_or_null(struct jambuf *buf, asn1_t dn, const char *null_dn,
		    jam_bytes_fn *jam_bytes)
{
	if (dn.ptr == NULL) {
		return jam_string(buf, null_dn);
	} else {
		return jam_raw_dn(buf, dn, jam_bytes, true/*nss_compatible*/);
	}
}

const char *str_dn_or_null(asn1_t dn, const char *null_dn, dn_buf *dst)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(dst->buf);
	jam_dn_or_null(&buf, dn, null_dn, jam_sanitized_bytes);
	return dst->buf;
}

size_t jam_dn(struct jambuf *buf, asn1_t dn, jam_bytes_fn *jam_bytes)
{
	return jam_dn_or_null(buf, dn, "(empty)", jam_bytes);
}

const char *str_dn(asn1_t dn, dn_buf *dst)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(dst->buf);
	jam_dn(&buf, dn, jam_sanitized_bytes);
	return dst->buf;
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
 *
 * See https://bugzilla.mozilla.org/show_bug.cgi?id=1709676 for why
 * this doesn't use the NSS code.  Sigh.
 */

err_t atodn(const char *src, chunk_t *dn)
{
	dbg("ASCII to DN <= \"%s\"", src);
	*dn = empty_chunk;

	/* stack of unfilled lengths */
	uint8_t *(patchpoints[5]);	/* only 4 are actually needed */
	uint8_t **patchpointer = patchpoints;

	uint8_t dn_buf[sizeof(id_buf)];	/* space for result */
	uint8_t *dn_ptr = dn_buf;	/* growth point */
	uint8_t *dn_redline = dn_buf + sizeof(dn_buf);

#	define START_OBJ() { *patchpointer++ = dn_ptr; }

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
#	define END_OBJ(ty)						\
	{								\
		size_t len = dn_ptr - *--patchpointer;			\
		unsigned char len_buf[1 + sizeof(len)] = { ty };	\
		chunk_t obj_len = { len_buf + 1, 0 };			\
		/* only handles up to 4 bytes */			\
		code_asn1_length(len, &obj_len);			\
		passert(obj_len.len <= sizeof(len_buf));		\
		if (dn_redline - dn_ptr < (ptrdiff_t)obj_len.len + 1)	\
			return "DN overflow";				\
		memmove(*patchpointer + obj_len.len + 1, *patchpointer, len); \
		memcpy(*patchpointer, len_buf, obj_len.len + 1);	\
		dn_ptr += obj_len.len + 1;				\
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
				if (src[0] == '\\' && char_isxdigit(src[1]) && char_isxdigit(src[2])) {
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

			unsigned char *ns = patchpointer[-1];	/* name operand start */
			enum asn1_type t = (op->type == ASN1_PRINTABLESTRING &&
					    !is_asn1_printablestring(shunk2(ns, dn_ptr - ns)) ?
					    ASN1_T61STRING : op->type);

			END_OBJ(t);	/* 3 value */
		}

		END_OBJ(ASN1_SEQUENCE);	/* 2 */
		END_OBJ(ASN1_SET);	/* 1 */
	}

	END_OBJ(ASN1_SEQUENCE);	/* 0 */

	*dn = clone_bytes_as_chunk(dn_buf, dn_ptr - dn_buf, "atodn");
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
bool same_dn(asn1_t a, asn1_t b)
{
	return match_dn(a, b, NULL);	/* degenerate case of match_dn() */
}

/*
 * compare two distinguished names by comparing the individual RDNs.
 * A single '*' character designates a wildcard RDN in DN b.
 * If wildcards is NULL, exact match is required.
 */
bool match_dn(asn1_t a, asn1_t b, int *wildcards)
{
	asn1_t rdn_a, rdn_b;
	asn1_t attribute_a, attribute_b;
	bool more_a, more_b;

	if (wildcards != NULL) {
		/* initialize wildcard counter */
		*wildcards = 0;
	} else {
		/* fast checks possible without wildcards */
		/* same lengths for the DNs */
		if (a.len != b.len)
			return false;

		/* try a binary comparison first */
		if (memeq(a.ptr, b.ptr, b.len))
			return true;
	}

	/*
	 * initialize DN parsing.  Stop (silently) on errors.
	 */
	{
		err_t ua = init_rdn(a, &rdn_a, &attribute_a, &more_a);
		if (ua != NULL) {
			dbg("match_dn bad a: %s", ua);
			return false;
		}

		err_t ub = init_rdn(b, &rdn_b, &attribute_b, &more_b);
		if (ub != NULL) {
			dbg("match_dn bad b: %s", ub);
			return false;
		}
	}

	/* fetch next RDN pair */
	for (int n = 1; more_a && more_b; n++) {
		/*
		 * Parse next RDNs and check for errors
		 * but don't report errors.
		 */
		asn1_t oid_a, oid_b;
		asn1_t value_ber_a, value_ber_b;
		enum asn1_type value_type_a, value_type_b;
		asn1_t value_content_a, value_content_b;

		{
			err_t ua = get_next_rdn(&rdn_a, &attribute_a, &oid_a,
						&value_ber_a, &value_type_a, &value_content_a,
						&more_a);
			if (ua != NULL) {
				dbg("match_dn bad a[%d]: %s", n, ua);
				return false;
			}

			err_t ub = get_next_rdn(&rdn_b, &attribute_b, &oid_b,
						&value_ber_b, &value_type_b, &value_content_b,
						&more_b);
			if (ub != NULL) {
				dbg("match_dn bad b[%d]: %s", n, ub);
				return false;
			}
		}

		/* OIDs must agree */
		if (!hunk_eq(oid_a, oid_b))
			return false;

		/* does rdn_b contain a wildcard? */
		/* ??? this does not care whether types match.  Should it? */
		if (wildcards != NULL &&
		    value_content_b.len == 1 &&
		    *(const char *)value_content_b.ptr == '*') {
			(*wildcards)++;
			continue;
		}

		if (value_content_a.len != value_content_b.len)
			return false;	/* lengths must match */

		/*
		 * If the two types treat the high bit differently
		 * or if ASN1_PRINTABLESTRING is involved,
		 * we must forbid the high bit.
		 */
		if (value_type_a != value_type_b ||
		    value_type_a == ASN1_PRINTABLESTRING) {
			uint8_t or = 0x00;
			for (size_t i = 0; i != value_content_a.len; i++) {
				or |= ((const uint8_t*)value_content_a.ptr)[i];
				or |= ((const uint8_t*)value_content_b.ptr)[i];
			}
			if (or & 0x80)
				return false;
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
		return false;	/* not a match */
	}

	/* both DNs must have same number of RDNs */
	if (more_a || more_b) {
		if (wildcards != NULL && *wildcards != 0) {
			dn_buf abuf;
			dn_buf bbuf;
			dbg("while comparing A='%s'<=>'%s'=B with a wildcard count of %d, %s had too few RDNs",
			    str_dn(a, &abuf),
			    str_dn(b, &bbuf),
			    *wildcards,
			    (more_a ? "B" : "A"));
		}
		return false;
	}

	/* the two DNs match! */
	return true;
}

/*
 * match an equal number of RDNs, in any order
 * if wildcards != NULL, wildcard matches are enabled
 */

static bool match_rdn(const CERTRDN *const rdn_a, const CERTRDN *const rdn_b, bool *const has_wild)
{
	if (rdn_a == NULL || rdn_b == NULL)
		return false;

	int matched = 0;
	int ava_num = 0;

	CERTAVA *const *avas_b;
	for (avas_b = rdn_b->avas; *avas_b != NULL; avas_b++) {
		CERTAVA *const ava_b = *avas_b;
		const SECOidTag tag_b = CERT_GetAVATag(ava_b);

		ava_num++;

		CERTAVA *const *avas_a;
		for (avas_a = rdn_a->avas; *avas_a != NULL; avas_a++) {
			CERTAVA *const ava_a = *avas_a;

			if (CERT_GetAVATag(ava_a) == tag_b) {
				SECItem *val_b = CERT_DecodeAVAValue(&ava_b->value);

				/* XXX Can CERT_DecodeAVAValue() return NULL? No man page :( */
				if (val_b != NULL) {
					if (has_wild != NULL &&
					    val_b->len == 1 &&
					    val_b->data[0] == '*') {
						*has_wild = true;
						matched++;
						SECITEM_FreeItem(val_b, PR_TRUE);
						break;
					}
					SECITEM_FreeItem(val_b, PR_TRUE);
				}
				if (CERT_CompareAVA(ava_a, ava_b) == SECEqual) {
					matched++;
					break;
				}
			}
		}
	}

	return matched > 0 && matched == ava_num;
}

static bool match_dn_unordered(const char *prefix, asn1_t a, asn1_t b, int *const wildcards)
{
	dn_buf a_dnbuf = { "", };
	dn_buf b_dnbuf = { "", };


	/*
	 * Escape the ASN.1 into RFC-1485 (actually RFC-4514 and
	 * printable ASCII) so that that it is suitable for NSS's
	 * CERT_AsciiToName().
	 */
	const char *abuf = str_dn(a, &a_dnbuf); /* RFC1485 for NSS */
	const char *bbuf = str_dn(b, &b_dnbuf); /* RFC1485 for NSS */

	/*
	 * ABUF and BBUF, set by dntoa(), contain an RFC 1485(?)
	 * encoded string and that can contain UTF-8 (i.e.,
	 * !isprint()).  Strip that out before logging.
	 */
	dbg("%smatching unordered DNs A: '%s' B: '%s'", prefix, abuf, bbuf);

	CERTName *const a_name = CERT_AsciiToName(abuf);
	CERTName *const b_name = CERT_AsciiToName(bbuf);

	if (a_name == NULL || b_name == NULL) {
		/* NULL is ignored; see NSS commit 206 */
		CERT_DestroyName(a_name);
		CERT_DestroyName(b_name);
		return false;
	}

	int rdn_num = 0;
	int matched = 0;
	CERTRDN *const *rdns_b;
	for (rdns_b = b_name->rdns; *rdns_b != NULL; rdns_b++) {
		CERTRDN *const rdn_b = *rdns_b;

		rdn_num++;

		CERTRDN *const *rdns_a;
		for (rdns_a = a_name->rdns; *rdns_a != NULL; rdns_a++) {
			CERTRDN *const rdn_a = *rdns_a;
			bool has_wild = false;

			if (match_rdn(rdn_a, rdn_b,
				      wildcards != NULL ? &has_wild : NULL)) {
				matched++;
				if (wildcards != NULL && has_wild)
					(*wildcards)++;
				break;
			}
		}
	}

	CERT_DestroyName(a_name);
	CERT_DestroyName(b_name);
	dbg("%s%s matched: %d, rdn_num: %d, wc %d",
	    prefix, __func__, matched, rdn_num, wildcards ? *wildcards : 0);

	return matched > 0 && rdn_num > 0 && matched == rdn_num;
}

bool match_dn_any_order_wild(const char *prefix, asn1_t a, asn1_t b, int *wildcards)
{
	bool ret = match_dn(a, b, wildcards);

	if (!ret) {
		dbg("%s%s: not an exact match, now checking any RDN order with %d wildcards",
		    prefix, __func__, *wildcards);
		/* recount wildcards */
		*wildcards = 0;
		ret = match_dn_unordered(prefix, a, b, wildcards);
	}
	return ret;
}

/*
 * free the dynamic memory used to store generalNames
 */
void free_generalNames(generalName_t *gn, bool free_name)
{
	while (gn != NULL) {
		generalName_t *gn_top = gn;

		if (free_name)
			free_chunk_content(&gn->name);
		gn = gn->next;
		pfree(gn_top);
	}
}
