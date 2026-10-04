/* flags check, for libreswan
 *
 * Copyright (C) 2026 Andrew Cagney
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

#include "flags.h"

#include "lswtool.h"
#include "lswalloc.h"
#include "enum_names.h"
#include "lswlog.h"

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
		exit(1);					\
	}

enum flag {
	FLAG_0,
	FLAG_1,
	FLAG_2,
#define FLAG_ROOF (FLAG_2+1)
};

static const char *const flag_name[FLAG_ROOF] = {
#define S(E) [E] = #E
	S(FLAG_0),
	S(FLAG_1),
	S(FLAG_2),
#undef S
};

static const struct enum_names flag_enum_names = {
	0, FLAG_ROOF-1,
	ARRAY_PTR(flag_name),
	"FLAG_",
	NULL,
};

static const struct names flag_names = {
	.enum_names = &flag_enum_names,
};

struct flags {
#define flag_0 flags[FLAG_0]
#define flag_1 flags[FLAG_1]
#define flag_2 flags[FLAG_2]
	bool flags[FLAG_ROOF];
};

int main(int argc, char *argv[])
{
	leak_detective = true;
	struct logger *logger = tool_logger(argc, argv);

	struct flags flags = {0};

	diag_t d = ttoflags("0,2", flags.flags, &flag_names);
	passert(d == NULL);

	LLOG_JAMBUF(ALL_STREAMS, logger, buf) {
		jam_flags(buf, flags.flags, &flag_names);
		jam_string(buf, " ");
		jam_flags_human(buf, flags.flags, &flag_names);
	}

	for (enum flag flag = 0; flag < FLAG_ROOF; flag++) {

		PRINT("flags_from_flag(%u)", flag);
		struct flags flags = flags_from_flag(flags, flag);
		if (!flags_has_flag(flags, flags, flag)) {
			FAIL("flags_has_flag(%u, %u*)", flag, flag);
		}

		PRINT("flags_not(%u*)", flag);
		struct flags not = flags_not(flags, flags);
		if (flags_has_flag(flags, not, flag)) {
			FAIL("!flags_has_flag(not(%u*), %u)", flag, flag);
		}

		for (enum flag alt = 0; alt < FLAG_ROOF; alt++) {

			struct flags alts = flags_from_flag(flags, alt);

			PRINT("flags_eq(%u*,%u*)", flag, alt);
			bool eq = (flag == alt);
			if (!(flags_eq(flags, flags, alts) == eq)) {
				FAIL("flags_eq(%u*,%u*) == %u", flag, alt, eq);
			}

			/**/

			PRINT("flags_and(%u*,%u*)", flag, alt);
			struct flags and = flags_and(flags, flags, alts);
			if (flags_has_flag(flags, and, flag) != eq) {
				FAIL("flags_has_flag(and(%u*,%u*), %u) == %u", flag, alt,flag, eq);
			}

			PRINT("flags_or(%u*,%u*)", flag, alt);
			struct flags or = flags_or(flags, flags, alts);
			if (!flags_has_flag(flags, or, flag)) {
				FAIL("flags_has_flag(or(%u*, %u*), %u)", flag, alt, flag);
			}
			if (!flags_has_flag(flags, or, alt)) {
				FAIL("flags_has_flag(or(%u*, %u*), %u)", flag, alt, alt);
			}

			/**/

			PRINT("flags_and_flag(%u*,%u)", flag, alt);
			struct flags and_flag = flags_and_flag(flags, flags, alt);
			if (flags_has_flag(flags, and_flag, flag) != eq) {
				FAIL("flags_has_flag(and_flag(%u*,%u), %u) == %u", flag, alt,flag, eq);
			}

			PRINT("flags_or_flag(%u*,%u)", flag, alt);
			struct flags or_flag = flags_or_flag(flags, flags, alt);
			if (!flags_has_flag(flags, or_flag, flag)) {
				FAIL("flags_has_flag(or_flag(%u*, %u), %u)", flag, alt, flag);
			}
			if (!flags_has_flag(flags, or_flag, alt)) {
				FAIL("flags_has_flag(or_flag(%u*, %u), %u)", flag, alt, alt);
			}

			/**/

			PRINT("flags_has_all()");
			if (!(flags_has_all(flags, or, flags) == true)) {
				FAIL("flags_has_all(or(%u*,%u*), %u*) == %u", flag, alt, flag, eq);
			}
			if (!(flags_has_all(flags, flags, alts) == eq)) {
				FAIL("flags_has_all(%u*,%u*) == %u", flag, alt, eq);
			}

			PRINT("flags_has_any()");
			if (!(flags_has_any(flags, or, flags) == true)) {
				FAIL("flags_has_any(or(%u*,%u*), %u*) == %u", flag, alt, flag, eq);
			}
			if (!(flags_has_any(flags, flags, alts) == eq)) {
				FAIL("flags_has_any(%u*,%u*) == %u", flag, alt, true);
			}

			PRINT("flags_has_none()");
			if (!(flags_has_none(flags, or, flags) == false)) {
				FAIL("flags_has_none(or(%u*,%u*), %u*) == %u", flag, alt, flag, eq);
			}
			if (!(flags_has_none(flags, flags, alts) == !eq)) {
				FAIL("flags_has_none(%u*,%u*) == %u", flag, alt, false);
			}

		}
	}

	if (report_leaks(logger)) {
		FAIL("leak detective");
	}

	exit(0);
}
