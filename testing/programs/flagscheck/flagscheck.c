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

enum test_flag {
	TEST_FLAG_0,
	TEST_FLAG_1,
	TEST_FLAG_2,
#define TEST_FLAG_ROOF (TEST_FLAG_2+1)
};

static const char *const test_flag_name[TEST_FLAG_ROOF] = {
#define S(E) [E] = #E
	S(TEST_FLAG_0),
	S(TEST_FLAG_1),
	S(TEST_FLAG_2),
#undef S
};

static const struct enum_names test_flag_names = {
	0, TEST_FLAG_ROOF-1,
	ARRAY_REF(test_flag_name),
	"TEST_FLAG_",
	NULL,
};

struct test_flags {
#define test_flag_0 test_flags[TEST_FLAG_0]
#define test_flag_1 test_flags[TEST_FLAG_1]
#define test_flag_2 test_flags[TEST_FLAG_2]
	bool test_flags[TEST_FLAG_ROOF];
};


int main(int argc, char *argv[])
{
	leak_detective = true;
	struct logger *logger = tool_logger(argc, argv);

	struct test_flags flags = {0};

	diag_t d = ttoflags("0,2", flags.test_flags, &test_flag_names);
	passert(d == NULL);

	LLOG_JAMBUF(ALL_STREAMS, logger, buf) {
		jam_flags(buf, flags.test_flags, &test_flag_names);
		jam_string(buf, " ");
		jam_flags_human(buf, flags.test_flags, &test_flag_names);
	}
}
