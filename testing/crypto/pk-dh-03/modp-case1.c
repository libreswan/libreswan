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
 */

#include <fcntl.h>

#define VULCAN_PK 1
#define PK_DH_REGRESS 1

#include "../../../programs/pluto/hmac.c"
#include "../../../programs/pluto/crypto.c"
#include "../../../programs/pluto/ike_alg.c"
#include "../../../programs/pluto/crypt_utils.c"
#include "../../../programs/pluto/vulcan/vulcanpk_funcs.c"

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
 * Input/output data for modp operation.
 *
 */
u_int32_t aModExpOperandA[] = {
	0x80000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
};

/* Operand_B */
u_int32_t aModExpOperandB[] = {
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000004
};

/* ExpectedResult */
u_int32_t aModExpExpectedRes[] = {
	0x7FFFFFFC, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000001
};

/******************* MODULUS data *******************/
u_int32_t aModulus[] = {
	0x80000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000
};

/******************* RECIPROCAL of MODULUS data *******************/
u_int32_t aReciprocal[] = {
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
};

void bigendianize(u_int32_t *data, int len)
{
	while (len-- > 0) {
		*data = htonl(*data);
		data++;
	}
}

int main(int argc, char *argv[])
{
	u_int8_t *mapping;
	u_int8_t aModExpOperandA_l[192];
	u_int8_t aModExpOperandB_l[192];
	u_int8_t aModExpExpectedRes_l[192];
	u_int8_t aModulus_l[192];
	u_int8_t aReciprocal_l[192];
	u_int8_t gtothex[192];
	struct pkprogram expModP;

	memset(&expModP, 0, sizeof(expModP));

	progname = argv[0];

	mapping = mapvulcanpk();

	/* initialize chip */
	vulcanpk_init(mapping);

	memcpy(aModExpOperandA_l, aModExpOperandA, 192);
	bigendianize((u_int32_t *)aModExpOperandA_l, 192 / sizeof(u_int32_t));

	memcpy(aModExpOperandB_l, aModExpOperandB, 192);
	bigendianize((u_int32_t *)aModExpOperandB_l, 192 / sizeof(u_int32_t));

	memcpy(aModExpExpectedRes_l, aModExpExpectedRes, 192);
	bigendianize((u_int32_t *)aModExpExpectedRes_l, 192 /
		     sizeof(u_int32_t));

	memcpy(aModulus_l, aModulus, 192);
	bigendianize((u_int32_t *)aModulus_l, 192 / sizeof(u_int32_t));

	memcpy(aReciprocal_l, aReciprocal, 192);
	bigendianize((u_int32_t *)aReciprocal_l, 192 / sizeof(u_int32_t));

	expModP.valuesLittleEndian = FALSE;

	/* g-value */
	expModP.aValues[0]  = aModExpOperandA_l;
	expModP.aValueLen[0] = 192;

	/* ^x-value */
	expModP.aValues[2]  = aModExpOperandB_l;
	expModP.aValueLen[2] = 192;

	/* register 2 is result. */
	/* register 3 is scratch */

	/* M = modulus */
	expModP.aValues[8]  = aModulus_l;
	expModP.aValueLen[8] = 192;

	/* reciprocal M(1) */
	expModP.aValues[9]  = aReciprocal_l;
	expModP.aValueLen[9] = 192;

	/* registers 6,7,8 is M(2),M(3),M(4), scratch */

	expModP.chunksize = 3;  /* *64 = 192 bytes/chunk */
	expModP.oOffset   = 3;  /* B(1) is result */
	expModP.oValue    = gtothex;
	expModP.oValueLen = sizeof(gtothex);

	/* ask to have the exponentiation done now! */
	expModP.pk_program[0] = /* sizes are ModLen=48(*32=1536),
	                           EXP_len=1535+1, RED_len=0 */
				(0 << 24) | (1535 << 8) | (48);
	expModP.pk_program[1] = /* opcode 1100=0xC (mod-exp),
	                           with A=0, B=2(6),M=8(24)*/
				(0xC << 24) | (24 << 16) | (6 << 8) | (0 << 0);

	expModP.pk_proglen = 2;
	execute_pkprogram(mapping, &expModP);

	printf("got: \n");
	hexdump(gtothex, 0, 192);

	printf("expected: \n");
	hexdump(aModExpExpectedRes_l, 0, 192);

	if (memeq(gtothex, aModExpExpectedRes_l, 192))
		printf("SUCCESS\n");

	exit(0);
}

