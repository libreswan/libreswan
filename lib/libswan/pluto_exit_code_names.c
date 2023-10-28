/* tables of names for values defined in constants.h
 *
 * Copyright (C) 2022 Andrew Cagney
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

#include "lswcdefs.h"		/* for ARRAY_REF() */
#include "enum_names.h"
#include "constants.h"	/* for enum pluto_exit_code in pluto_constants.h */

static const char *pluto_exit_code_name_hi[] = {
#define S(E) [E - PLUTO_EXIT_GIT_BISECT_CAN_NOT_TEST] = #E
	S(PLUTO_EXIT_GIT_BISECT_CAN_NOT_TEST),
	S(PLUTO_EXIT_SHELL_COMMAND_NOT_FOUND),
	S(PLUTO_EXIT_SHELL_COMMAND_NOT_EXECUTABLE),
#undef S
};

static enum_names pluto_exit_code_names_hi = {
	PLUTO_EXIT_GIT_BISECT_CAN_NOT_TEST,
	PLUTO_EXIT_SHELL_COMMAND_NOT_EXECUTABLE,
	ARRAY_REF(pluto_exit_code_name_hi),
	NULL, NULL,
};

static const char *pluto_exit_code_name[] = {
#define S(E) [E] = #E
	S(PLUTO_EXIT_OK),
	S(PLUTO_EXIT_FAIL),
	S(PLUTO_EXIT_SOCKET_FAIL),
	S(PLUTO_EXIT_FORK_FAIL),
	S(PLUTO_EXIT_FIPS_FAIL),
	S(PLUTO_EXIT_KERNEL_FAIL),
	S(PLUTO_EXIT_NSS_FAIL),
	S(PLUTO_EXIT_AUDIT_FAIL),
	S(PLUTO_EXIT_SECCOMP_FAIL),
	S(PLUTO_EXIT_UNBOUND_FAIL),
	S(PLUTO_EXIT_LOCK_FAIL),
	S(PLUTO_EXIT_SELINUX_FAIL),
#undef S
};

enum_names pluto_exit_code_names = {
	PLUTO_EXIT_OK, PLUTO_EXIT_SELINUX_FAIL,
	ARRAY_REF(pluto_exit_code_name),
	"PLUTO_EXIT_", /* prefix */
	&pluto_exit_code_names_hi,
};
