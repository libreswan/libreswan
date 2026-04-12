/* Check that optarg_seedbits() updates KBF_SEEDBITS, for libreswan.
 *
 * Copyright (C) 2026 Anish Singh Rawat
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

#include <stdlib.h>
#include <stdio.h>

#include "lswtool.h"
#include "optarg.h"
#include "ipsecconf/setup.h"
#include "lswlog.h"

enum opt {
	OPT_NSSDIR = 256,
	OPT_PASSWORD,
	OPT_SEEDDEV,
	OPT_SEEDBITS,
	OPT_HELP,
};

const struct option optarg_options[] = {
	NSSDIR_OPTS,
	{ OPT("help"), no_argument, NULL, OPT_HELP },
	{ 0, 0, NULL, 0 }
};

int main(int argc, char **argv)
{
	struct logger *logger = tool_logger(argc, argv);
	bool seen_seedbits = false;
	uintmax_t expected_seedbits = 0;
	bool seen_seeddev = false;
	const char *expected_seeddev = NULL;

	while (true) {
		int c = optarg_getopt(logger, argc, argv);
		if (c < 0) {
			break;
		}

		switch ((enum opt)c) {
		case OPT_NSSDIR:
			optarg_nssdir(logger);
			continue;
		case OPT_PASSWORD:
			/* Not used in this test, but required for NSSDIR_OPTS */
			continue;
		case OPT_SEEDBITS:
			expected_seedbits = optarg_seedbits(logger);
			seen_seedbits = true;
			continue;
		case OPT_SEEDDEV:
			optarg_seeddev(logger);
			expected_seeddev = optarg;
			seen_seeddev = true;
			continue;
		case OPT_HELP:
			optarg_usage("ipsec _seedbitscheck", "[--seedbits <number>] [--seeddev <device>]", "");
		default:
			bad_case(c);
		}
	}

	if (!seen_seedbits) {
		fprintf(stderr, "seedbits option not provided\n");
		exit(1);
	}

	uintmax_t seedbits = config_setup_option(KBF_SEEDBITS);
	printf("seedbits=%ju\n", seedbits);
	if (seedbits == 0) {
		exit(1);
	}
	if (seedbits != expected_seedbits) {
		fprintf(stderr, "seedbits mismatch: expected %ju, got %ju\n",
			expected_seedbits, seedbits);
		exit(1);
	}

	if (seen_seeddev) {
		const char *seeddev = config_setup_string(KSF_SEEDDEV);
		printf("seeddev=%s\n", seeddev ? seeddev : "(null)");
		if (seeddev == NULL) {
			fprintf(stderr, "seeddev not stored in config\n");
			exit(1);
		}
		if (expected_seeddev && strcmp(seeddev, expected_seeddev) != 0) {
			fprintf(stderr, "seeddev mismatch: expected %s, got %s\n",
				expected_seeddev, seeddev);
			exit(1);
		}
	}

	exit(0);
}
