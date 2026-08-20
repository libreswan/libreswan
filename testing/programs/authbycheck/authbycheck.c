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

		bool authby_set = (auth != AUTH_EAPONLY);
		if (authby_is_set(authby) != authby_set) {
			FAIL("authby_is_set(%u*) == %u", auth, authby_set);
		}
		if (auth_in_authby(auth, authby) != authby_set) {
			FAIL("auth_in_authby(%u, %u*) == %u", auth, auth, authby_set);
		}

		struct authby not_authby = authby_not(authby);
		if (!authby_is_set(not_authby)) {
			FAIL("authby_is_set(not(%u*)) == %u", auth, false);
		}
		if (auth_in_authby(auth, not_authby)) {
			FAIL("auth_in_authby(%u, not(%u*)) == %u", auth, auth, false);
		}

		authby_buf ab;
		str_authby(authby, &ab);
		if (auth == AUTH_EAPONLY) {
			if (!streq(ab.buf, "none")) {
				FAIL("str_authby(%u) == none", auth);
			}
		} else {
			if (streq(ab.buf, "none")) {
				FAIL("str_authby(%u) != none", auth);
			}
		}

		if (auth == AUTH_EAPONLY) {
			continue;
		}

		for (enum auth alt = AUTH_FLOOR; alt < AUTH_ROOF; alt++) {

			if (alt == AUTH_EAPONLY) {
				continue;
			}

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
			if (!(auth_in_authby(auth, authby_and(authby, altby)) == eq)) {
				FAIL("auth_in_authby(%u, and(%u*,%u*)) == %u", auth, auth, alt, eq);
			}

			PRINT("authby_or(%u,%u)", auth, alt);
			if (!authby_is_set(authby_or(authby, altby))) {
				FAIL("authby_is_set(or(%u*,%u*))", auth, alt);
			}
			if (!auth_in_authby(auth, authby_or(authby, altby))) {
				FAIL("auth_in_authby(%u, or(%u*,%u*))", auth, auth, alt);
			}

			PRINT("authby_xor(%u,%u)", auth, alt);
			bool xor = (auth != alt);
			if (!(authby_is_set(authby_xor(authby, altby)) == xor)) {
				FAIL("authby_is_set(xor(%u,%u)) == %u", auth, alt, xor);
			}
			if (!(auth_in_authby(auth, authby_xor(authby, altby)) == (xor && authby_set))) {
				FAIL("auth_in_authby(%u, xor(%u,%u)) == %u", auth, alt, auth, xor && authby_set);
			}

			if (!(authby_le(authby_or(authby, altby), authby) == eq)) {
				FAIL("orby: authby: authby_le(or(%u*,%u*), %u) == %u", auth, alt, auth, eq);
			}
			if (!(authby_le(authby_or(authby, altby), altby) == eq)) {
				FAIL("orby:altby: authby_le(or(%u*,%u*), %u) == %u", auth, alt, alt, eq);
			}

			if (!authby_le(authby, authby_or(authby, altby))) {
				FAIL("authby:orby: authby_le(%u*, or(%u*,%u*))", auth, auth, alt);
			}
			if (!authby_le(altby, authby_or(authby, altby))) {
				FAIL("altby:orby: authby_le(%u*, or(%u*,%u*))", alt, auth, alt);
			}

			/**/

			if (!(authby_has_all(authby_or(authby, altby), authby) == true)) {
				FAIL("authby_has_all(or(%u*,%u*), %u*) == %u", auth, alt, auth, true);
			}
			if (!(authby_has_all(authby, authby_or(authby, altby)) == eq)) {
				FAIL("authby_has_all(%u*, or(%u*,%u*)) == %u", auth, auth, alt, eq);
			}

			if (!(authby_has_all(authby_xor(authby, altby), authby) == !eq)) {
				FAIL("authby_has_all(xor(%u*,%u*), %u*) == %u", auth, alt, auth, !eq);
			}
			if (!(authby_has_all(authby, authby_xor(authby, altby)) == eq)) {
				FAIL("authby_has_all(%u*, xor(%u*,%u*)) == %u", auth, auth, alt, eq);
			}

			/**/

			if (!(authby_has_some(authby_or(authby, altby), authby) == true)) {
				FAIL("authby_has_some(or(%u*,%u*), %u*) == %u", auth, alt, auth, true);
			}
			if (!(authby_has_some(authby, authby_or(authby, altby)) == true)) {
				FAIL("authby_has_some(%u*, or(%u*,%u*)) == %u", auth, auth, alt, true);
			}

			if (!(authby_has_some(authby_xor(authby, altby), authby) == !eq)) {
				FAIL("authby_has_some(xor(%u*,%u*), %u*) == %u", auth, alt, auth, !eq);
			}
			if (!(authby_has_some(authby, authby_xor(authby, altby)) == !eq)) {
				FAIL("authby_has_some(%u*, xor(%u*,%u*)) == %u", auth, auth, alt, !eq);
			}

			/**/

			if (!(authby_has_none(authby, altby) == !eq)) {
				FAIL("authby_has_none(%u*,%u*) == %u", auth, alt, false);
			}

		}
	}

	for (enum auth auth = DIGITAL_SIGNATURE_AUTH_FLOOR;
	     auth < DIGITAL_SIGNATURE_AUTH_ROOF; auth++) {
		if (!auth_in_authby(auth, AUTHBY_DIGITAL_SIGNATURE)) {
			FAIL("auth_in_authby(%u, AUTHBY_DIGITAL_SIGNATURE) failed", auth);
		}
	}

	for (enum auth auth = AUTH_FLOOR; auth < AUTH_ROOF; auth++) {
		if (auth == AUTH_EAPONLY) {
			continue;
		}
		if (!auth_in_authby(auth, AUTHBY_ALL)) {
			FAIL("auth_in_authby(%u, AUTHBY_ALL) failed", auth);
		}
	}

	do { /* hack so FAIL() works */
		struct authby authby_sha2_256 =
			authby_and_hash(AUTHBY_ALL, &ike_alg_hash_sha2_256);
		/* XXX: legacy RSA is allowed with SHA2 */
		if (!authby_sha2_256.rsasig_v1_5 ||
		    !authby_sha2_256.ecdsa_sha2_256 ||
		    !authby_sha2_256.rsasig_sha2_256 ||
		    authby_sha2_256.eddsa) {
			FAIL("authby_and_hash(sha2_256)");
		}
		struct authby authby_sha1 =
			authby_and_hash(AUTHBY_ALL, &ike_alg_hash_sha1);
		if (!authby_sha1.rsasig_v1_5 ||
		    authby_has_some(authby_sha1, AUTHBY_ALL_ECDSA_SHA2) ||
		    authby_has_some(authby_sha1, AUTHBY_ALL_RSASIG_SHA2) ||
		    authby_sha1.eddsa) {
			FAIL("authby_and_hash(sha1");
		}
		struct authby authby_identity =
			authby_and_hash(AUTHBY_ALL, &ike_alg_hash_identity);
		if (!authby_identity.eddsa ||
		    authby_identity.rsasig_v1_5 ||
		    authby_has_some(authby_identity, AUTHBY_ALL_ECDSA_SHA2) ||
		    authby_has_some(authby_identity, AUTHBY_ALL_RSASIG_SHA2)) {
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
