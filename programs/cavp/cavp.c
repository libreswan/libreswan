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
#define IOPT "        "
#define OPT "-%-7s  %s\n"

#define USAGE_GLOBAL "[-fips] [-json]"

static void help_global()
{
	printf(II""OPT, "fips", "force FIPS mode (else determined from machine configuration)");
	printf("\n");
	printf(II""OPT, "json", "format output as json like records");
}

static void help(void)
{
#define USAGE_HELP "cavp -?|-h|-help"
	printf("Usage: "USAGE_HELP"\n");
	printf("\n");
	printf(I"print this help message\n");
	printf("\n");

#define USAGE_FILE "cavp " USAGE_GLOBAL " [-<test>] <test-file>|-"
	printf("Usage: "USAGE_FILE"\n");
	printf("\n");
	printf(I"Run <test> using test vectors from <test-file> ('-' for stdin).\n");
	printf("\n");
	help_global();
	printf("\n");
	for (const struct cavp **cavpp = cavps; *cavpp != NULL; cavpp++) {
		printf(II""OPT, (*cavpp)->alias, (*cavpp)->description);
	}
	printf("\n");
	printf(I"If -<algorithm> is omitted then it is determined by matching\n");
	printf(I"the <test-file> header with one of the following patterns:\n");
	printf("\n");
	for (const struct cavp **cavpp = cavps; *cavpp != NULL; cavpp++) {
		for (const char *const *matchp = (*cavpp)->match; *matchp; matchp++) {
			printf(II""OPT, (*cavpp)->alias, *matchp);
		}
	}
	printf("\n");

#define USAGE_PARAM "cavp " USAGE_GLOBAL " -<test> -<acvp-key> <acvp-value> ..."
	printf("Usage: "USAGE_PARAM"\n");
	printf("\n");
	printf(I"Specify test using command line options (options names from ACVP)\n");
	printf("\n");
	help_global();
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
					printf(III"-"ACVP_PRF_OPTION" <prf>\n");
					sep = III""IOPT"<prf>: ";
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
				printf(III"-"ACVP_DKM_OPTION" <length>\n");
				printf(III""IOPT"<length>: key deriviation length in bits\n");
				break;
			}
		}
		/* data */
		for (const struct cavp_entry *entry = (*cavpp)->data; entry->key != NULL; entry++) {
			if (entry->opt[0] != NULL) {
				supported = true;
				printf(III"-%s <data>\n", entry->opt[0]);
				printf(III""IOPT"%s\n", entry->key);
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
	printf("Usage: "USAGE_HELP"\n");
	printf("       "USAGE_FILE"\n");
	printf("       "USAGE_PARAM"\n");
}

int main(int argc, char *argv[])
{
	tool_init_log(argv[0]);

	if (argc <= 1) {
		usage();
		exit(1);
	}

	const struct cavp *cavp = NULL;
	bool use_acvp = false;

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
			fprintf(stderr, "option '%s' not recognized\n", *argp);
			return 0;
		}
	}

	if (!use_acvp && cavp == NULL) {
		fprintf(stderr, "Guessing test type ...\n");
	}

	if (use_acvp) {
		fprintf(stderr, "Using CMVP\n");
	} else if (*argp == NULL) {
		fprintf(stderr, "missing test file\n");
		usage();
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

	init_ike_alg();

	if (use_acvp) {
		passert(cavp != NULL);
		cavp->run_test();
	} else {
		cavp_parser(cavp);
	}

	lsw_nss_shutdown();
	exit(0);
}
