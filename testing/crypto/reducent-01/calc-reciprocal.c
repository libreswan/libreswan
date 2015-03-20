/*
 * unit tests for cryptographic helper function - calculate KE and nonce
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
 *
 * This code was developed with the support of IXIA communications.
 */

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

/*
 * assumes that the group has been initialized, that is, that the
 * str_modulus has been copied and turned into an MP_INT already.
 *
 *
 * This algorithm will not work if the top bits of the modulus are
 * 0x80000, but all of the IETF moduli have been chosen such that the
 * top bits are 0xffffffff 0xffffffff.
 *
 */
void calc_reciprocal(const struct oakley_group_desc *group)
{
	mpz_t n, one, reciprocal;
	int nlen = 2 * group->bytes * BITS_PER_BYTE - 1;
	int tries = 1000000;

	mpz_init(one);
	mpz_init(reciprocal);
	mpz_init(n);

	mpz_set_ui(one, 1);

	/* calculate 1 followed by 2 times number of bits, minus 1 */
	mpz_mul_2exp(n, one, nlen);

	/* now reciprocal is n divied by group */
	mpz_tdiv_q(reciprocal, n, group->modulus);

	mpz_mul(n, group->modulus, reciprocal);

	/* make sure that result has a 1 bit in highest position */
	while (mpz_tstbit(n, nlen) == 1 && tries-- > 0) {

		mpz_sub_ui(reciprocal, reciprocal, 1);
		mpz_mul(n, group->modulus, reciprocal);
	}

	fprintf(stdout, "Group %d Tries: %d\nModulus: ", group->group, tries);
	mpz_out_str(stdout, 16, group->modulus);

	fprintf(stdout, "\nReciprocal: ");
	mpz_out_str(stdout, 16, reciprocal);

	fprintf(stdout, "\nProduct: ");

	mpz_out_str(stdout, 16, n);
	fprintf(stdout, "\n\n");

	mpz_clear(n);
	mpz_clear(reciprocal);
	mpz_clear(one);
}

int main(int argc, char *argv[])
{
	int i;

	progname = argv[0];

	/* initialize list of moduli */
	init_crypto();

	for (i = 0; i != elemsof(oakley_group); i++)
		calc_reciprocal(&oakley_group[i]);

	exit(0);
}

