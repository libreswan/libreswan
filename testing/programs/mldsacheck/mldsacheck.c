/* Test ML-DSA plumbing, for libreswan
 *
 * Copyright (C) 2026 Sahana Prasad <sahana@redhat.com>
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
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "lswtool.h"
#include "lswalloc.h"
#include "lswlog.h"
#include "constants.h"
#include "ietf_constants.h"
#include "authby.h"
#include "auth.h"
#include "secrets.h"
#include "ike_alg.h"
#include "ike_alg_hash.h"
#include "names_constant.h"
#include "names.h"

unsigned fails;

#define PRINTF(FILE, FMT, ...)				\
	{						\
		fprintf(FILE, "%s:%d: "FMT,		\
			HERE_FILENAME, __LINE__,	\
			##__VA_ARGS__);			\
	}

#define PRINT(FMT, ...)				\
	PRINTF(stdout, FMT"\n", ##__VA_ARGS__)

#define FAIL(FMT, ...)					\
	{						\
		PRINTF(stderr, "FAIL: "FMT"\n", ##__VA_ARGS__);	\
		fails++;				\
	}

/*
 * Test 1: ASN.1 blob byte-level correctness
 *
 * Verify the ML-DSA AlgorithmIdentifier DER blobs encode the correct OIDs:
 *   ML-DSA-44: 2.16.840.1.101.3.4.3.17 (last byte 0x11)
 *   ML-DSA-65: 2.16.840.1.101.3.4.3.18 (last byte 0x12)
 *   ML-DSA-87: 2.16.840.1.101.3.4.3.19 (last byte 0x13)
 *
 * DER format: SEQUENCE { OID } with no parameters
 *   0x30 0x0b  -- SEQUENCE, length 11
 *   0x06 0x09  -- OID, length 9
 *   0x60 0x86 0x48 0x01 0x65 0x03 0x04 0x03 0xNN
 */
static void asn1_blob_check(void)
{
	static const struct {
		const char *name;
		uint8_t last_byte;
		uint8_t blob[ASN1_MLDSA_IDENTITY_SIZE];
	} tests[] = {
		{ "ML-DSA-44", 0x11, { ASN1_MLDSA_IDENTITY_44_BLOB } },
		{ "ML-DSA-65", 0x12, { ASN1_MLDSA_IDENTITY_65_BLOB } },
		{ "ML-DSA-87", 0x13, { ASN1_MLDSA_IDENTITY_87_BLOB } },
	};

	/* common prefix: SEQUENCE tag, length, OID tag, OID length, OID body minus last byte */
	static const uint8_t expected_prefix[] = {
		0x30, 0x0b, 0x06, 0x09,
		0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03,
	};

	for (size_t ti = 0; ti < sizeof(tests)/sizeof(tests[0]); ti++) {
		PRINT("asn1_blob_check: %s", tests[ti].name);

		/* check total size */
		if (ASN1_MLDSA_IDENTITY_SIZE != 13) {
			FAIL("ASN1_MLDSA_IDENTITY_SIZE is %d, expected 13",
			     ASN1_MLDSA_IDENTITY_SIZE);
		}

		/* check prefix (first 12 bytes are identical across all three) */
		if (memcmp(tests[ti].blob, expected_prefix, sizeof(expected_prefix)) != 0) {
			FAIL("%s: prefix mismatch", tests[ti].name);
		}

		/* check distinguishing last byte */
		if (tests[ti].blob[12] != tests[ti].last_byte) {
			FAIL("%s: last byte is 0x%02x, expected 0x%02x",
			     tests[ti].name, tests[ti].blob[12], tests[ti].last_byte);
		}
	}

	/* verify all three blobs differ only in the last byte */
	uint8_t blob44[] = { ASN1_MLDSA_IDENTITY_44_BLOB };
	uint8_t blob65[] = { ASN1_MLDSA_IDENTITY_65_BLOB };
	uint8_t blob87[] = { ASN1_MLDSA_IDENTITY_87_BLOB };
	if (memcmp(blob44, blob65, 12) != 0) {
		FAIL("ML-DSA-44 and ML-DSA-65 blobs differ before last byte");
	}
	if (memcmp(blob65, blob87, 12) != 0) {
		FAIL("ML-DSA-65 and ML-DSA-87 blobs differ before last byte");
	}
	if (blob44[12] == blob65[12] || blob65[12] == blob87[12]) {
		FAIL("ML-DSA blobs have duplicate last bytes");
	}
}

/*
 * Test 2: ASN.1 blob registration in ike_alg_hash_identity
 */
#ifdef USE_MLDSA
static void asn1_blob_registration_check(void)
{
	static const struct {
		const char *name;
		enum digital_signature_blob index;
	} tests[] = {
		{ "ML-DSA-44", DIGITAL_SIGNATURE_MLDSA_IDENTITY_44_BLOB },
		{ "ML-DSA-65", DIGITAL_SIGNATURE_MLDSA_IDENTITY_65_BLOB },
		{ "ML-DSA-87", DIGITAL_SIGNATURE_MLDSA_IDENTITY_87_BLOB },
	};

	for (size_t ti = 0; ti < sizeof(tests)/sizeof(tests[0]); ti++) {
		PRINT("asn1_blob_registration_check: %s", tests[ti].name);

		shunk_t blob = ike_alg_hash_identity.digital_signature_blob[tests[ti].index];
		if (blob.ptr == NULL || blob.len == 0) {
			FAIL("%s: blob not registered (NULL or empty)", tests[ti].name);
			continue;
		}

		/* blob should be 1 (length prefix) + 13 (DER) = 14 bytes */
		if (blob.len != 1 + ASN1_MLDSA_IDENTITY_SIZE) {
			FAIL("%s: blob length is %zu, expected %d",
			     tests[ti].name, blob.len, 1 + ASN1_MLDSA_IDENTITY_SIZE);
			continue;
		}

		/* first byte is the length prefix */
		const uint8_t *p = blob.ptr;
		if (p[0] != ASN1_MLDSA_IDENTITY_SIZE) {
			FAIL("%s: length prefix byte is %u, expected %d",
			     tests[ti].name, p[0], ASN1_MLDSA_IDENTITY_SIZE);
		}
	}
}
#endif

/*
 * Test 3: authby round-trip
 */
static void authby_roundtrip_check(void)
{
	PRINT("authby_roundtrip_check: AUTH_MLDSA -> authby -> auth");

	struct authby authby = authby_from_auth(AUTH_MLDSA);
	if (!authby.mldsa) {
		FAIL("authby_from_auth(AUTH_MLDSA).mldsa is false");
	}

	enum auth auth = auth_from_authby((struct authby) { .mldsa = true, });
	if (auth != AUTH_MLDSA) {
		FAIL("auth_from_authby({.mldsa=true}) returned %d, expected %d",
		     auth, AUTH_MLDSA);
	}
}

/*
 * Test 4: authby string formatting
 */
static void authby_string_check(void)
{
	PRINT("authby_string_check: str_authby({.mldsa=true})");

	authby_buf ab;
	str_authby((struct authby) { .mldsa = true, }, &ab);
	if (!streq(ab.buf, "MLDSA")) {
		FAIL("str_authby({.mldsa=true}) returned \"%s\", expected \"MLDSA\"",
		     ab.buf);
	}
}

/*
 * Test 5: AUTH_MLDSA in AUTHBY_DIGITAL_SIGNATURE
 */
static void authby_digital_signature_check(void)
{
	PRINT("authby_digital_signature_check: AUTH_MLDSA in AUTHBY_DIGITAL_SIGNATURE");

	if (!auth_in_authby(AUTH_MLDSA, AUTHBY_DIGITAL_SIGNATURE)) {
		FAIL("auth_in_authby(AUTH_MLDSA, AUTHBY_DIGITAL_SIGNATURE) is false");
	}
}

/*
 * Test 6: AUTH_MLDSA in AUTHBY_ALL
 */
static void authby_all_check(void)
{
	PRINT("authby_all_check: AUTH_MLDSA in AUTHBY_ALL");

	if (!auth_in_authby(AUTH_MLDSA, AUTHBY_ALL)) {
		FAIL("auth_in_authby(AUTH_MLDSA, AUTHBY_ALL) is false");
	}
}

/*
 * Test 7: Signer struct wiring
 */
#ifdef USE_MLDSA
static void signer_wiring_check(void)
{
	static const struct {
		const char *expected_name;
		const struct pubkey_signer *signer;
		enum digital_signature_blob expected_blob;
	} tests[] = {
		{ "ML-DSA-44", &pubkey_signer_digsig_mldsa_44,
		  DIGITAL_SIGNATURE_MLDSA_IDENTITY_44_BLOB },
		{ "ML-DSA-65", &pubkey_signer_digsig_mldsa_65,
		  DIGITAL_SIGNATURE_MLDSA_IDENTITY_65_BLOB },
		{ "ML-DSA-87", &pubkey_signer_digsig_mldsa_87,
		  DIGITAL_SIGNATURE_MLDSA_IDENTITY_87_BLOB },
	};

	for (size_t ti = 0; ti < sizeof(tests)/sizeof(tests[0]); ti++) {
		PRINT("signer_wiring_check: %s", tests[ti].expected_name);

		const struct pubkey_signer *s = tests[ti].signer;

		if (!streq(s->name, tests[ti].expected_name)) {
			FAIL("%s: name is \"%s\"", tests[ti].expected_name, s->name);
		}
		if (s->type != &pubkey_type_mldsa) {
			FAIL("%s: type is not &pubkey_type_mldsa", tests[ti].expected_name);
		}
		if (s->digital_signature_blob != tests[ti].expected_blob) {
			FAIL("%s: digital_signature_blob is %d, expected %d",
			     tests[ti].expected_name,
			     s->digital_signature_blob,
			     tests[ti].expected_blob);
		}
		if (s->sign_message == NULL) {
			FAIL("%s: sign_message is NULL", tests[ti].expected_name);
		}
		if (s->authenticate_message_signature == NULL) {
			FAIL("%s: authenticate_message_signature is NULL",
			     tests[ti].expected_name);
		}
	}
}
#endif

/*
 * Test 8: Secret kind string
 */
static void secret_kind_name_check(void)
{
	PRINT("secret_kind_name_check: SECRET_MLDSA");

	name_buf nb;
	const char *name = str_enum_long(&secret_kind_names, SECRET_MLDSA, &nb);
	if (name == NULL) {
		FAIL("str_enum_long(&secret_kind_names, SECRET_MLDSA, ...) returned NULL");
	} else if (!streq(name, "SECRET_MLDSA")) {
		FAIL("str_enum_long(&secret_kind_names, SECRET_MLDSA, ...) returned \"%s\", expected \"SECRET_MLDSA\"",
		     name);
	}
}

int main(int argc, char *argv[])
{
	leak_detective = true;
	struct logger *logger = tool_logger(argc, argv);

	/* Tests that work without USE_MLDSA (constants always defined) */
	asn1_blob_check();
	authby_roundtrip_check();
	authby_string_check();
	authby_digital_signature_check();
	authby_all_check();
	secret_kind_name_check();

	/* Tests that require USE_MLDSA (signer structs, blob registration) */
#ifdef USE_MLDSA
	asn1_blob_registration_check();
	signer_wiring_check();
#endif

	if (report_leaks(logger)) {
		fails++;
	}

	if (fails > 0) {
		fprintf(stderr, "TOTAL FAILURES: %u\n", fails);
		return 1;
	}

	return 0;
}
