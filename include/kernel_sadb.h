/* Kernel specific RFC 2367 - SADB algorithm routines, for libreswan
 *
 * Copyright (C) 2018 Andrew Cagney
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

#ifndef KERNEL_SADB_H
#define KERNEL_SADB_H

#include <stddef.h>	/* for size_t */

struct sadb_msg;
struct sadb_alg;

/*
 * Helper routines for code following RFC 2367 - PF_KEY - when
 * manipulating the kernel.
 *
 * This file is deliberately called ..._sadb and _not_ PF_KEY because:
 *
 * - all relevant structures have SADB as a prefix
 *
 * - PF_KEY can mean many things - the BSDs ship with a library while
 *   linux seems to use code bundled with pluto
 *
 * - kernel_pfkey.[hc] is already taken
 */

/*
 * Multiplier for converting .sadb_msg_len (in 64-bit words) to
 * size_t.
 */
#define KERNEL_SADB_WORD_SIZE (64/8)

/* Registration messages from pluto */
extern void kernel_add_sadb_algs(const struct sadb_msg *msg, size_t sizeof_msg);

extern void kernel_add_sadb_alg(int satype, int exttype, const struct sadb_alg *sadb_alg);

#endif
