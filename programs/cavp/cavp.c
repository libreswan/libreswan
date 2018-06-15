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
#include "ike_alg.h"

#include "cavp.h"
#include "cavps.h"
#include "cavp_parser.h"
#include "acvp.h"

#define I "  "
#define II I I
#define OPT1 II"-%-8s  %s\n"
#define OPT2V II"-%s <value>, -%s <value>\n"II"           %s\n"
#define OPT3V II"-%s <value>, -%s <value>, -%s <value>\n"II"           %s\n"

static void help(void)
{
#define USAGE_HELP "cavp -?|-h|-help"
	printf("Usage: "USAGE_HELP"\n");
	printf("\n");
	printf(I"print this help message\n");
	printf("\n");

#define USAGE_FILE "cavp [-fips] [-<algorithm>] <test-file>|-"
	printf("Usage: "USAGE_FILE"\n");
	printf("\n");
	printf(I"Test <algorithm> using test vectors from <test-file> ('-' for stdin).\n");
	printf("\n");
	printf(OPT1, "fips", "force FIPS mode (else determined by machine configuration)");
	printf("\n");
	for (struct cavp **cavpp = cavps; *cavpp != NULL; cavpp++) {
		printf(OPT1, (*cavpp)->alias, (*cavpp)->description);
	}
	printf("\n");
	printf(I"If -<algorithm> is omitted then it will be determined by matching one\n");
	printf(I"the <test-file> header with one of the following patterns:\n");
	printf("\n");
	for (struct cavp **cavpp = cavps; *cavpp != NULL; cavpp++) {
		for (const char **matchp = (*cavpp)->match; *matchp; matchp++) {
			printf(OPT1, (*cavpp)->alias, *matchp);
		}
	}
	printf("\n");

#define USAGE_PARAM "cavp -<param> <value> ..."
	printf("Usage: "USAGE_PARAM"\n");
	printf("\n");
	printf(OPT2V, "gir", "g", "shared secret from IKE DH exchange (g^ir)");
	printf(OPT2V, "girnew", "n", "shared secret from child DH exchange (g^ir (new))");
	printf(OPT2V, "ni", "a", "initiator nonce (Ni)");
	printf(OPT2V, "nr", "b", "responder nonce (Nr)");
	printf(OPT2V, "spii", "c", "initiator security parameter index (SPIi");
	printf(OPT2V, "spir", "d", "responder security parameter index (SPIr)");
	printf(OPT2V, "dkmlen", "l", "size of derived keying material in bytes");
	printf(OPT3V, "prf", "p", "hash", "pseudo-random-function used to implement PRF+");
}

#undef OPT1
#undef OPT2V
#undef OPT3V
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

	struct cavp *cavp = NULL;
	struct acvp p = { .use = false, };

	char **argp = argv + 1;
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

		/* First try non-arg options */

		struct cavp **cavpp;
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
		if (strcmp(arg, "fips") == 0) {
			lsw_set_fips_mode(LSW_FIPS_ON);
		} else if (strcmp(arg, "help") == 0 || strcmp(arg, "?") == 0 || strcmp(arg, "h") == 0) {
			help();
			return 0;
		} else if (argp[1] == NULL) {
			fprintf(stderr, "missing argument for option '%s'\n", *argp);
			return 0;
		} else if (strcmp(arg, "g") == 0 || strcmp(arg, "gir") == 0) {
			p.g_ir = *++argp;
			p.use = true;
		} else if (strcmp(arg, "n") == 0 || strcmp(arg, "girnew") == 0) {
			p.g_ir_new = *++argp;
			p.use = true;
		} else if (strcmp(arg, "a") == 0 || strcmp(arg, "ni") == 0) {
			p.ni = *++argp;
			p.use = true;
		} else if (strcmp(arg, "b") == 0 || strcmp(arg, "nr") == 0) {
			p.nr = *++argp;
			p.use = true;
		} else if (strcmp(arg, "c") == 0 || strcmp(arg, "spii") == 0) {
			p.spi_i = *++argp;
			p.use = true;
		} else if (strcmp(arg, "d") == 0 || strcmp(arg, "spir") == 0) {
			p.spi_r = *++argp;
			p.use = true;
		} else if (strcmp(arg, "l") == 0 || strcmp(arg, "dkmlen") == 0) {
			p.dkm_length = *++argp;
			p.use = true;
		} else if (strcmp(arg, "p") == 0 || strcmp(arg, "prf") == 0 || strcmp(arg, "hash") == 0) {
			p.prf = *++argp;
			p.use = true;
		} else {
			fprintf(stderr, "option '%s' not recognized\n",
				*argp);
		}
	}

	if (!p.use && cavp == NULL) {
		fprintf(stderr, "Guessing test type ...\n");
	}

	if (p.use) {
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

	lsw_nss_buf_t err;
	if (!lsw_nss_setup(NULL, 0, NULL, err)) {
		fprintf(stderr, "unexpected %s\n", err);
		exit(1);
	}

	init_ike_alg();

	if (p.use) {
		acvp(&p);
	} else {
		cavp_parser(cavp);
	}

	lsw_nss_shutdown();
	exit(0);
}
