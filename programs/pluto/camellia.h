/*
 * Copyright (C) 2014 Paul Wouters <pwouters@redhat.com>
 * Based on aes.h
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

#ifndef _CAMELLIA_H
#define _CAMELLIA_H

/* Camellia is a drop-in replacement for AES */

#include <sys/types.h>

#ifndef CAMELLIA_BLOCK_SIZE
# define CAMELLIA_BLOCK_SIZE  16
#endif

#if CAMELLIA_BLOCK_SIZE == 32
#define CAMELLIA_KS_LENGTH   120
#define CAMELLIA_RC_LENGTH    29
#else
#define CAMELLIA_KS_LENGTH   (4 * CAMELLIA_BLOCK_SIZE)
#define CAMELLIA_RC_LENGTH   ((9 * CAMELLIA_BLOCK_SIZE) / 8 - 8)
#endif

typedef struct {
	u_int32_t camellia_Nkey;                     // the number of words in the key input block
	u_int32_t camellia_Nrnd;                     // the number of cipher rounds
	u_int32_t camellia_e_key[CAMELLIA_KS_LENGTH];     // the encryption key schedule
	u_int32_t camellia_d_key[CAMELLIA_KS_LENGTH];     // the decryption key schedule
} camellia_context;

#endif  // _CAMELLIA_H
