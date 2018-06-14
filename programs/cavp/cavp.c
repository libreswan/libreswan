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

static void usage(void)
{
	fprintf(stderr, "Usage:\n\n");
	fprintf(stderr, "    cavp [ -TEST ] <test-vector>|-\n\n");
	fprintf(stderr, "Where -TEST specifies the test type:\n\n");
	for (struct cavp **cavpp = cavps; *cavpp != NULL; cavpp++) {
		fprintf(stderr, "    -%-8s %s\n",
			(*cavpp)->alias,
			(*cavpp)->description);
	}
	fprintf(stderr, "\n");
	fprintf(stderr, "If -TEST is omitted then the test type is determined from the\n");
	fprintf(stderr, "file header by matching one of the patterns:\n\n");
	for (struct cavp **cavpp = cavps; *cavpp != NULL; cavpp++) {
		const char *sep = (*cavpp)->alias;
		for (const char **matchp = (*cavpp)->match; *matchp; matchp++) {
			fprintf(stderr, "    %-8s  '%s'\n", sep, *matchp);
			sep = "";
		}
	}
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
		} else if (strcmp(arg, "h") == 0 || strcmp(arg, "hash") == 0) {
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
