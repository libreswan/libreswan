/*
 * unit tests for cryptographic helper function - calculate KE and nonce
 *             using the memory mapped hifn 7956.
 *
 * Copyright (C) 2006 Michael C. Richardson <mcr@xelerance.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <fcntl.h>

#define VULCAN_PK 1
#define PK_DH_REGRESS 1

int pkdh_verbose = 0;

#include <stdio.h>

#include "../../../programs/pluto/hmac.c"
#include "../../../programs/pluto/crypto.c"
#include "../../../programs/pluto/ike_alg.c"
#include "../../../programs/pluto/crypt_utils.c"
#include "../../../programs/pluto/crypt_dh.c"

#include "crypto.h"

char *progname;

void exit_log(const char *message, ...)
{
	va_list args;
	char m[LOG_WIDTH];      /* longer messages will be truncated */

	va_start(args, message);
	vsnprintf(m, sizeof(m), message, args);
	va_end(args);

	fprintf(stderr, "FATAL ERROR: %s\n", m);
	exit(0);
}

void exit_tool(int code)
{
	exit(code);
}

#include "../pk-dh-01/tc2.c"

int main(int argc, char *argv[])
{
	progname = argv[0];

	/* initialize list of moduli */
	init_crypto();

	vulcanpk_mapping = mapvulcanpk();
	/* initialize chip */
	vulcanpk_init(vulcanpk_mapping);

	if (argc > 1)
		pk_verbose_execute = 1;

	calc_dh_shared = calc_dh_shared_vulcanpk;

	perform_t2_test();

	/* shut down */
	unmapvulcanpk(vulcanpk_mapping);

	exit(0);
}

