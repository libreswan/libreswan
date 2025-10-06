/* test jambuf_t, for libreswan
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
#include <stdarg.h>
#include <string.h>

#include "jambuf.h"		/* for struct jambuf */
#include "constants.h"		/* for streq() */
#include "lswalloc.h"		/* for leaks */
#include "lswtool.h"		/* for tool_init_log() */
#include "lswlog.h"		/* for cur_debugging; */

#include "authby.h"
#include "auth.h"

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

		bool set = (auth != AUTH_EAPONLY);

		if (authby_is_set(authby) != set) {
			FAIL("authby_is_set(%u) == %u", auth, set);
		}
		if (authby_has(authby, auth) != set) {
			FAIL("authby_has(%u, %u) == %u", auth, auth, set);
		}

		struct authby notby = authby_not(authby);
		if (!authby_is_set(notby)) {
			FAIL("authby_is_set(not(%u)) == %u", auth, false);
		}
		if (authby_has(notby, auth)) {
			FAIL("authby_has(not(%u), %u) == %u", auth, auth, false);
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

			PRINT("authby_and(%u,%u)", auth, alt);
			struct authby andby = authby_and(authby, altby);
			bool and = (auth == alt);
			if (authby_is_set(andby) != and) {
				FAIL("authby_is_set(and(%u,%u)) == %u", auth, alt, and);
			}
			if (authby_has(andby, auth) != and) {
				FAIL("authby_has(and(%u,%u), %u) == %u", auth, alt, auth, and);
			}

			PRINT("authby_or(%u,%u)", auth, alt);
			struct authby orby = authby_or(authby, altby);
			if (!authby_is_set(orby)) {
				FAIL("authby_is_set(or(%u,%u))", auth, alt);
			}
			if (!authby_has(orby, auth)) {
				FAIL("authby_has(or(%u,%u), %u)", auth, alt, auth);
			}
			if (authby_le(orby, authby) != and) {
				FAIL("orby: authby: authby_le(or(%u,%u), %u) == %u", auth, alt, auth, and);
			}
			if (authby_le(orby, altby) != and) {
				FAIL("orby:altby: authby_le(or(%u,%u), %u) == %u", auth, alt, alt, and);
			}
			if (!authby_le(altby, orby)) {
				FAIL("altby:orby: authby_le(or(%u,%u), %u)", auth, alt, alt);
			}
			if (!authby_le(authby, orby)) {
				FAIL("authby:orby: authby_le(or(%u,%u), %u)", auth, alt, alt);
			}

			PRINT("authby_xor(%u,%u)", auth, alt);
			struct authby xorby = authby_xor(authby, altby);
			bool xor = (auth != alt);
			if (authby_is_set(xorby) != xor) {
				FAIL("authby_is_set(xor(%u,%u)) == %u", auth, alt, xor);
			}
			if (authby_has(xorby, auth) != (xor && set)) {
				FAIL("authby_has(xor(%u,%u), %u) == %u", auth, alt, auth, xor && set);
			}

			PRINT("authby_eq(%u,%u)", auth, alt);
			bool eqby = authby_eq(authby, altby);
			bool eq = (auth == alt);
			if (eqby != eq) {
				FAIL("authby_eq(%u,%u) == %u", auth, alt, eq);
			}
		}
	}

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
