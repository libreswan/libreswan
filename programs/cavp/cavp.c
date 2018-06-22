/* Parse CAVP test vectors, for libreswan (CAVP)
 *
 * Copyright (C) 2015-2018, Andrew Cagney
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

#include <stdio.h>

#include "lswtool.h"
#include "lswfips.h"
#include "lswnss.h"
#include "lswlog.h"
#include "ike_alg.h"

#include "cavp.h"
#include "cavps.h"
#include "cavp_parser.h"
#include "cavp_entry.h"
#include "cavp_print.h"
#include "acvp.h"

#define I "  "
#define II I I
#define III I I I
#define IOPT " " "       " "  "
#define OPT  "-%-7s  %s\n"

static void help(void)
{
#define HELP_OPTIONS "-?|-h|-help"
#define GLOBAL_OPTIONS "[-fips] [-json] [-v]"
	printf("Usage: cavp ["HELP_OPTIONS"] " GLOBAL_OPTIONS " <test-option> ...\n");
	printf("\n");
	printf(I"Run CAVP/ACVP tests as specified either in a file or from the\n");
	printf(I"command line:\n");
	printf("\n");
	printf(II""OPT, "fips", "force FIPS mode; must be the first option");
	printf(II""IOPT"by default NSS determines FIPS mode\n"); 
	printf(II""OPT, "json", "output each test result as a json record");
	printf(II""OPT, "v", "verbose output");
	printf(II"-h, -help, -?\n"II""IOPT"Print this help message\n");

#define USAGE_FILE "cavp " GLOBAL_OPTIONS " [-<test>] <test-file>|-"
	printf("\n");
	printf("File mode: "USAGE_FILE"\n");
	printf("\n");
	printf(I"Run <test> using test vectors from <test-file> ('-' for stdin).\n");
	printf(I"If -<test> is omitted then the <test> is determined by pattern\n");
	printf(I"matching the <test-file> header:\n");
	printf("\n");
	for (const struct cavp **cavpp = cavps; *cavpp != NULL; cavpp++) {
		printf(II""OPT, (*cavpp)->alias, (*cavpp)->description);
		for (const char *const *matchp = (*cavpp)->match; *matchp; matchp++) {
			printf(II""IOPT"Match: %s\n", *matchp);
		}
	}

#define USAGE_PARAM "cavp " GLOBAL_OPTIONS " -<test> -<acvp-key> <acvp-value> ..."
	printf("\n");
	printf("Command mode: "USAGE_PARAM"\n");
	printf("\n");
	printf(I"Run <test> using <acvp-key>-<acvp-value> pairs specified on the\n");
	printf(I"command line:\n");
	printf("\n");
	for (const struct cavp **cavpp = cavps; *cavpp != NULL; cavpp++) {
		printf(II""OPT, (*cavpp)->alias, (*cavpp)->description);
		bool supported = false;
		/* PRF? */
		const char *sep = NULL;
		for (const struct cavp_entry *config = (*cavpp)->config; config->key != NULL; config++) {
			if (config->prf != NULL) {
				supported = true;
				if (sep == NULL) {
					printf(III"-"ACVP_PRF_OPTION" ");
					sep = "";
				}
				printf("%s%s", sep, config->key);
				sep = "|";
			}
		}
		if (sep != NULL) {
			printf("\n");
		}
		/* keylen */
		for (const struct cavp_entry *config = (*cavpp)->config; config->key != NULL; config++) {
			if (strstr(config->key, "DKM") != NULL) {
				supported = true;
				printf(III"-"ACVP_DKM_OPTION" <length-in-bits>\n");
				break;
			}
		}
		/* data */
		for (const struct cavp_entry *entry = (*cavpp)->data; entry->key != NULL; entry++) {
			if (entry->opt != NULL) {
				supported = true;
				printf(III"-%s <%s>\n", entry->opt, entry->key);
			}
		}
		if (!supported) {
			printf(III"Not supported\n");
		}
	}
}

#undef OPT
#undef III
#undef II
#undef I

static void usage(void)
{
	printf("Usage: cavp "HELP_OPTIONS"\n");
	printf("       "USAGE_FILE"\n");
	printf("       "USAGE_PARAM"\n");
}

int main(int argc, char *argv[])
{
	log_to_stderr = false;
	tool_init_log(argv[0]);

	if (argc <= 1) {
		usage();
		exit(1);
	}

	const struct cavp *cavp = NULL;
	bool use_acvp = false;
	bool verbose = false;

	char **argp = argv + 1;

	/* help must be at the front! */
	if (strcmp(*argp, "-help") == 0 || strcmp(*argp, "--help") == 0 ||
	    strcmp(*argp, "-?") == 0 || strcmp(*argp, "--?") == 0 ||
	    strcmp(*argp, "-h") == 0 || strcmp(*argp, "--h") == 0) {
		help();
		return 0;
	}

	/* -fips must come first! */
	if (strcmp(*argp, "-fips") == 0 || strcmp(*argp, "--fips") == 0) {
		lsw_set_fips_mode(LSW_FIPS_ON);
		argp++;
	}

	/* start NSS so crypto works while args are being parsed */
	lsw_nss_buf_t err;
	if (!lsw_nss_setup(NULL, 0, NULL, err)) {
		fprintf(stderr, "unexpected %s\n", err);
		return 1;
	}

	for (; *argp != NULL; argp++) {
		const char *arg = *argp;
		/* end options? */
		if (strcmp(arg, "--") == 0) {
			argp++;
			break;
		}
		/* read from stdin? */
		if (strcmp(arg, "-") == 0) {
			break;
		}
		/* assume file? */
		if (*arg != '-') {
			break;
		}

		/* strip leading '-' */
		do {
			arg++;
		} while (arg[0] == '-');

		/* First: try non-arg options */

		const struct cavp **cavpp;
		for (cavpp = cavps; *cavpp != NULL; cavpp++) {
			if (strcmp(arg, (*cavpp)->alias) == 0) {
				cavp = *cavpp;
				fprintf(stderr, "test: %s\n", cavp->description);
				break;
			}
		}
		if (*cavpp != NULL) {
			continue;
		}

		if (strcmp(arg, "json") == 0) {
			cavp_print_json = true;
			continue;
		}
		if (strcmp(arg, "v") == 0) {
			verbose = true;
			continue;
		}
		if (strcmp(arg, "fips") == 0) {
			fprintf(stderr, "option '%s' must appear first\n", *argp);
			return 0;
		}

		/* Second: try options with args */

		if (argp[1] == NULL) {
			fprintf(stderr, "missing argument for option '%s'\n", *argp);
			return 0;
		}

		if (cavp != NULL && acvp_option(cavp, arg, argp[1])) {
			argp++;
			use_acvp = true;
			continue;
		} else {
			fprintf(stderr, "option '%s' not recognized or invalid\n", *argp);
			return 0;
		}
	}

	if (!use_acvp && cavp == NULL) {
		libreswan_log("Guessing test type ...");
	}

	if (use_acvp) {
		libreswan_log("Using CMVP");
	} else if (*argp == NULL) {
		fprintf(stderr, "missing test file\n");
		exit(1);
	} else if (strcmp(*argp, "-") == 0) {
		fprintf(stderr, "Reading from stdin\n");
		argp++;
	} else {
		fprintf(stderr, "Reading from %s\n", *argp);
		if (freopen(*argp, "r", stdin) == NULL) {
			perror("freopen");
			exit(1);
		}
		argp++;
	}

	if (*argp != NULL) {
		fprintf(stderr, "unexpected option '%s'\n", *argp);
		exit(1);
	}

	setbuf(stdout, NULL);

	log_to_stderr = verbose;
	init_ike_alg();

	if (use_acvp) {
		passert(cavp != NULL);
		print_begin();
		cavp->run_test();
		print_end();
	} else {
		cavp_parser(cavp);
	}

	lsw_nss_shutdown();
	exit(0);
}
