/* test *time_t code, for libreswan
 *
 * Copyright (C) 2019 Andrew Cagney
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/lgpl-2.1.txt>.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 *
 */

#include <stdio.h>
#include <stdint.h>

#include <cert.h>

#include "lswtool.h"		/* for tool_init_log() */

#include "x509.h"
#include "asn1.h"
#include "lswalloc.h"		/* for leak_detective; */

int fails = 0;

#define PRINT(FILE, FMT, ...)						\
	fprintf(FILE, "%s[%zu]:"FMT"\n", __func__, ti,##__VA_ARGS__)

#define FAIL(FMT, ...)				\
	PRINT(stderr, FMT,##__VA_ARGS__);	\
	fails++;				\
	continue;

static void dn_check(void)
{
	static /*const*/ struct test {
		const char *out;
		size_t len;
		uint8_t in[20];
		const char *nss;
	} tests[] = {
		/* reference point */
		{
			"CN=012345",
			19,
			{ ASN1_SEQUENCE, 17,
			  ASN1_SET, 15,
			  ASN1_SEQUENCE, 13,
			  ASN1_OID, 3, /*OID*/85, 4, 3,
			  ASN1_PRINTABLESTRING, 6,
			  '0',  '1',  '2',  '3',  '4',  '5', },
			NULL,
		},
		/* escape leading '#' and ' ' and trailing ' ' */
		{
			"CN=\\ # # #",
			19,
			{ ASN1_SEQUENCE, 17,
			  ASN1_SET, 15,
			  ASN1_SEQUENCE, 13,
			  ASN1_OID, 3, /*OID*/85, 4, 3,
			  ASN1_PRINTABLESTRING, 6,
			  ' ',  '#',  ' ',  '#',  ' ',  '#', },
			.nss = "CN=\\ \\# \\# \\#", /* NSS needs '#' escaped */
		},
		{
			"CN=\\# # #\\ ",
			19,
			{ ASN1_SEQUENCE, 17,
			  ASN1_SET, 15,
			  ASN1_SEQUENCE, 13,
			  ASN1_OID, 3, /*OID*/85, 4, 3,
			  ASN1_PRINTABLESTRING, 6,
			  '#',  ' ',  '#',  ' ',  '#', ' ', },
			.nss = "CN=#1306232023202320", /* NSS totally screws up leading '#' */
		},
		{
			"CN=.    \\ ",
			19,
			{ ASN1_SEQUENCE, 17,
			  ASN1_SET, 15,
			  ASN1_SEQUENCE, 13,
			  ASN1_OID, 3, /*OID*/85, 4, 3,
			  ASN1_PRINTABLESTRING, 6,
			  '.',  ' ',  ' ',  ' ',  ' ',  ' ', },
			NULL,
		},
		{
			/* don't escape trailing '#' */
			"CN=.#####",
			19,
			{ ASN1_SEQUENCE, 17,
			  ASN1_SET, 15,
			  ASN1_SEQUENCE, 13,
			  ASN1_OID, 3, /*OID*/85, 4, 3,
			  ASN1_PRINTABLESTRING, 6,
			  '.',  '#',  '#',  '#',  '#',  '#', },
			.nss = "CN=.\\#\\#\\#\\#\\#", /* NSS needs '#' escaped */
		},
		/* escaping non printable ascii */
		{
			"CN=\\00y\\00\\00z\\00",
			19, /* NULs */
			{ ASN1_SEQUENCE, 17,
			  ASN1_SET, 15,
			  ASN1_SEQUENCE, 13,
			  ASN1_OID, 3, /*OID*/85, 4, 3,
			  ASN1_UTF8STRING, 6,
			  0,  'y',  0,  0,  'z',  0, },
			NULL,
		},
		{
			/* 31->32 */
			"CN=\\1D\\1E\\1F !\\\"",
			19,
			{ ASN1_SEQUENCE, 17,
			  ASN1_SET, 15,
			  ASN1_SEQUENCE, 13,
			  ASN1_OID, 3, /*OID*/ 85, 4, 3,
			  ASN1_UTF8STRING, 6, 29, 30,  31,  32,  33,  34, },
			NULL,
		},
		{
			/* 126->128 */
			"CN=|}~\\7F\\80\\81",
			19,
			{ ASN1_SEQUENCE, 17,
			  ASN1_SET, 15,
			  ASN1_SEQUENCE, 13,
			  ASN1_OID, 3, /*OID*/ 85, 4, 3,
			  ASN1_UTF8STRING, 6, 124, 125,  126,  127, 128, 129, },
			NULL,
		},
		{
			"CN=\\+\\,\\;\\<\\>\\\\", 19, /* reserved */
			{ ASN1_SEQUENCE, 17,
			  ASN1_SET, 15,
			  ASN1_SEQUENCE, 13,
			  ASN1_OID, 3, /*OID*/85, 4, 3,
			  ASN1_PRINTABLESTRING, 6, '+',  ',',  ';',  '<',  '>',  '\\', },
			NULL,
		},
		{
			/* not reserved */
			"CN==#':$#",
			19,
			{ ASN1_SEQUENCE, 17,
			  ASN1_SET, 15,
			  ASN1_SEQUENCE, 13,
			  ASN1_OID, 3, /*OID*/85, 4, 3,
			  ASN1_PRINTABLESTRING, 6, '=',  '#',  '\'',  ':',  '$',  '#', },
			.nss = "CN=\\=\\#':$\\#", /* NSS needs '=' escaped */
		},
		/* unknown OIDs - dump #BER */
		{ /* 1-byte */
			"2.39=#1306303132333435",
			17,
			{ ASN1_SEQUENCE, 15,
			  ASN1_SET, 13,
			  ASN1_SEQUENCE, 11,
			  ASN1_OID, 1, /*OID*/ 40*2+39, /* see encoding schema */
			  ASN1_PRINTABLESTRING, 6, '0',  '1',  '2',  '3',  '4',  '5', },
			NULL,
		},
		{ /* 3-bytes */
			"2.39.1.2=#1306303132333435",
			19,
			{ ASN1_SEQUENCE, 17,
			  ASN1_SET, 15,
			  ASN1_SEQUENCE, 13,
			  ASN1_OID, 3, /*OID*/ 40*2+39, 1, 2,
			  ASN1_PRINTABLESTRING, 6, '0',  '1',  '2',  '3',  '4',  '5', },
			NULL,
		},
		{ /*1+2-bytes */
			"2.39.16383=#1306303132333435",
			19,
			{ ASN1_SEQUENCE, 17,
			  ASN1_SET, 15,
			  ASN1_SEQUENCE, 13,
			  ASN1_OID, 3, /*OID*/ 40*2+39, 0x80|(16383>>7), 16383&0x7f,
			  ASN1_PRINTABLESTRING, 6, '0',  '1',  '2',  '3',  '4',  '5', },
			NULL,
		},
	};

	for (size_t ti = 0; ti < elemsof(tests); ti++) {
		/*const*/ struct test *t = &tests[ti];
		PRINT(stdout, " -> rfc4514: '%s'%s%s%s", t->out,
		      t->nss != NULL ? " NSS: '" : "",
		      t->nss != NULL ? t->nss : "",
		      t->nss != NULL ? "'" : "");
		chunk_t dn = chunk2(t->in, t->len); /* shunk2() */

		/* convert it to a string */

#define CHECK_JAM_DN(OUT, NSS_COMPATIBLE)				\
		{							\
			dn_buf dnbuf = { "", };				\
			struct jambuf dnjam = ARRAY_AS_JAMBUF(dnbuf.buf);	\
			jam_raw_dn(&dnjam, ASN1(dn), jam_raw_bytes, NSS_COMPATIBLE); \
			if (!streq(dnbuf.buf, OUT)) {			\
				FAIL(" jam_raw_dn(NSS_COMPATIBLE=%s) returned '%s', expecting '%s'", \
				     bool_str(NSS_COMPATIBLE),		\
				     dnbuf.buf, OUT);			\
			}						\
		}

		CHECK_JAM_DN(t->out, false);
		if (t->nss != NULL) {
			CHECK_JAM_DN(t->nss, true);
		}

		/* Can NSS can parse its variant? */

		{
			const char *nss_dn = t->nss != NULL ? t->nss : t->out;
			CERTName *nss_name = CERT_AsciiToName(nss_dn);
			if (nss_name == NULL) {
				/* PORT_Error()? */
				FAIL(" CERT_AsciiToName() unexpectedly failed to parse '%s'",
				     nss_dn);
			}
			CERT_DestroyName(nss_name);
		}

		/* see if libreswan can parse it */

#define CHECK_ATODN(IN)							\
		{							\
			chunk_t adn;					\
			err_t err = atodn(IN, &adn); /* static data */	\
			if (err != NULL) {				\
				FAIL(" atodn('%s') unexpectedly failed: %s", \
				     IN, err);				\
			} else {					\
				dn_buf adnbuf = { "", };		\
				struct jambuf adnjam = ARRAY_AS_JAMBUF(adnbuf.buf); \
				jam_raw_dn(&adnjam, ASN1(adn), jam_raw_bytes, false); \
				if (!streq(adnbuf.buf, t->out)) {	\
					FAIL(" jam_dn(atodn('%s')) returned '%s', expecting '%s'", \
					     IN, adnbuf.buf, t->out);	\
				}					\
				free_chunk_content(&adn);		\
			}						\
		}

		CHECK_ATODN(t->out);
		if (t->nss != NULL) {
			CHECK_ATODN(t->nss);
		}

	}
}

int main(int argc UNUSED, char *argv[])
{
	leak_detective = true;
	struct logger *logger = tool_logger(argc, argv);

	dn_check();

	if (report_leaks(logger)) {
		fails++;
	}

	if (fails > 0) {
		fprintf(stderr, "TOTAL FAILURES: %d\n", fails);
		return 1;
	}

	return 0;
}
