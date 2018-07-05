/* Kernel specific RFC 2367 - SADB algorithm routines, for libreswan
 *
 * Copyright (C) 2018 Andrew Cagney
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

#ifndef KERNEL_SADB_H
#define KERNEL_SADB_H

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

#include <stddef.h>	/* for size_t */

#ifdef linux
#include <linux/pfkeyv2.h>
#else
#include <net/pfkeyv2.h>
#endif

/*
 * Multiplier for converting .sadb_msg_len (in 64-bit words) to
 * size_t.
 */
#define KERNEL_SADB_WORD_SIZE (64/8)

/* Registration messages from pluto */
extern void kernel_alg_register_pfkey(const struct sadb_msg *msg, size_t sizeof_msg);

#endif
