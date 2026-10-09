/* test jambuf_t, for libreswan
 *
 * Copyright (C) 2019-2026 Andrew Cagney
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
#include <stdarg.h>
#include <string.h>

#include "jambuf.h"		/* for struct jambuf */
#include "constants.h"		/* for streq() */
#include "lswalloc.h"		/* for leaks */
#include "lswtool.h"		/* for tool_init_log() */
#include "lswlog.h"		/* for cur_debugging; */

#include "authby.h"
#include "auth.h"

#include "ike_alg_hash.h"

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
		continue;				\
	}

int main(int argc, char *argv[])
{
	leak_detective = true;
	struct logger *logger = tool_logger(argc, argv);

	if (argc > 1) {
		cur_debugging = -1;
	}

	leak_detective = true;

	for (enum auth auth = AUTH_FLOOR; auth < AUTH_ROOF; auth++) {
		PRINT("authby_from_auth(%u)", auth);
		struct authby authby = authby_from_auth(auth);

		if (!authby_is_set(authby)) {
			FAIL("authby_is_set(%u*)", auth);
		}
		if (!authby_has_auth(authby, auth)) {
			FAIL("authby_has_auth(%u, %u*)", auth, auth);
		}

		struct authby not_authby = authby_not(authby);
		if (!authby_is_set(not_authby)) {
			FAIL("authby_is_set(not(%u*)) == %u", auth, false);
		}
		if (authby_has_auth(not_authby, auth)) {
			FAIL("authby_has_auth(not(%u*), %u) == %u", auth, auth, false);
		}

		authby_buf ab;
		str_authby(authby, &ab);
		if (streq(ab.buf, "none")) {
			FAIL("str_authby(%u) != none", auth);
		}

		for (enum auth alt = AUTH_FLOOR; alt < AUTH_ROOF; alt++) {

			struct authby altby = authby_from_auth(alt);

			PRINT("authby_eq(%u,%u)", auth, alt);
			bool eq = (auth == alt);
			if (!(authby_eq(authby, altby) == eq)) {
				FAIL("authby_eq(%u*,%u*) == %u", auth, alt, eq);
			}

			PRINT("authby_and(%u,%u)", auth, alt);
			if (!(authby_is_set(authby_and(authby, altby)) == eq)) {
				FAIL("authby_is_set(and(%u*,%u*)) == %u", auth, alt, eq);
			}
			PRINT("authby_or(%u*,%u*)", auth, alt);
			if (!authby_is_set(authby_or(authby, altby))) {
				FAIL("authby_is_set(or(%u*, %u*))", auth, alt);
			}

			PRINT("authby_and_auth(%u,%u)", auth, alt);
			if (!(authby_is_set(authby_and_auth(authby, alt)) == eq)) {
				FAIL("authby_is_set(and_auth(%u*,%u)) == %u", auth, alt, eq);
			}

			PRINT("authby_or_auth(%u*,%u)", auth, alt);
			if (!authby_is_set(authby_or_auth(authby, alt))) {
				FAIL("authby_is_set(or_auth(%u*, %u))", auth, alt);
			}
			/* check for individual bits from OR */
			if (!(authby_has_auth(authby_or_auth(authby, alt), auth))) {
				FAIL("authby_has_auth(authby_or_auth(%u*,%u), %u)", auth, alt, auth);
			}
			if (!(authby_has_auth(authby_or_auth(authby, alt), alt))) {
				FAIL("authby_has_auth(authby_or_auth(%u*,%u), %u)", auth, alt, alt);
			}

			/**/

			if (!(authby_has_all(authby_or(authby, altby), authby) == true)) {
				FAIL("authby_has_all(or(%u*,%u*), %u*) == %u", auth, alt, auth, true);
			}
			if (!(authby_has_all(authby, authby_or(authby, altby)) == eq)) {
				FAIL("authby_has_all(%u*, or(%u*,%u*)) == %u", auth, auth, alt, eq);
			}

			/**/

			if (!(authby_has_any(authby_or(authby, altby), authby) == true)) {
				FAIL("authby_has_any(or(%u*,%u*), %u*) == %u", auth, alt, auth, true);
			}
			if (!(authby_has_any(authby, authby_or(authby, altby)) == true)) {
				FAIL("authby_has_any(%u*, or(%u*,%u*)) == %u", auth, auth, alt, true);
			}

			/**/

			if (!(authby_has_none(authby, altby) == !eq)) {
				FAIL("authby_has_none(%u*,%u*) == %u", auth, alt, false);
			}

		}
	}

	const struct authby all_authby_bits_set = authby_not((struct authby) {0});

	for (enum auth auth = AUTH_FLOOR; auth < AUTH_ROOF; auth++) {
		if (!authby_has_auth(all_authby_bits_set, auth)) {
			FAIL("authby_has_auth(AUTHBY_ALL, %u) failed", auth);
		}
	}

	do { /* hack so FAIL() works */
		struct authby authby_sha2_256 =
			authby_and_hash(all_authby_bits_set,
					&ike_alg_hash_sha2_256);
		/* XXX: legacy RSA is allowed with SHA2 */
		if (!authby_sha2_256.authby_rsasig_v1_5_sha2_256 ||
		    !authby_sha2_256.authby_ecdsa_sha2_256_raw ||
		    !authby_sha2_256.authby_ecdsa_sha2_256_blob ||
		    !authby_sha2_256.authby_rsasig_sha2_256 ||
		    authby_has_any(authby_sha2_256, (struct authby) {
				    AUTHBY_EDDSA,
			    })) {
			FAIL("authby_and_hash(sha2_256)");
		}
		struct authby authby_sha1 =
			authby_and_hash(all_authby_bits_set, &ike_alg_hash_sha1);
		if (!authby_has_all(authby_sha1, (struct authby) {
					AUTHBY_RSASIG_V1_5_SHA1,
				}) ||
		    authby_has_any(authby_sha1, (struct authby) {
				    AUTHBY_RSASIG_V1_5_SHA2,
				    AUTHBY_ECDSA_SHA2,
				    AUTHBY_RSASIG_SHA2,
				    AUTHBY_EDDSA,
			    })) {
			FAIL("authby_and_hash(sha1");
		}
		struct authby authby_identity =
			authby_and_hash(all_authby_bits_set, &ike_alg_hash_identity);
		if (!authby_has_all(authby_identity, (struct authby) {
					AUTHBY_EDDSA,
				}) ||
		    authby_has_any(authby_identity, (struct authby) {
				    AUTHBY_RSASIG_V1_5,
				    AUTHBY_ECDSA_SHA2,
				    AUTHBY_RSASIG_SHA2,
			    })) {
			FAIL("authby_and_hash(identity)");
		}
	} while (false);

	if (report_leaks(logger)) {
		fails++;
	}

	if (fails > 0) {
		fprintf(stderr, "TOTAL FAILURES: %u\n", fails);
		return 1;
	} else {
		return 0;
	}
}
