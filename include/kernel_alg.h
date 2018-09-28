/* Kernel algorithm DB, for libreswan
 *
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 * Copyright (C) 2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2017-2018 Andrew Cagney
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

#ifndef KERNEL_ALG_H
#define KERNEL_ALG_H

/*
 * This is a database of algorithms supported by the kernel and,
 * hence, can be negotiated for ESP and AH.  For instance, using
 * PF_KEY (rfc2367), it is theoretically possible to query the kernel
 * for supported algorithms and key sizes and use that to populate
 * this database.
 *
 * Of course reality steps in:
 *
 * - there's a race between the kernel loading a crypto module and
 *   this database being populated (suspect it gets populated when the
 *   first connection is initiated?)
 *
 * - there's often a gap between what PF_KEY returns and what the
 *   kernel can support (linux works around this by hardwiring
 *   entries)
 *
 * - there's often a gap between what the PF_KEY headers say is
 *   supported and what the kernel supports (linux works around this
 *   by having pluto local headers)
 *
 * - is there an XFRM way to query what the kernel supports?  I
 *   suspect linux still uses PF_KEY.
 *
 * - while PF_KEY returns key sizes (minbits, maxbits), the
 *   information is ignored and instead the ike_alg DB is consulted
 *   for this information (suspect that while PF_KEY was written to
 *   support variable length keys only fix sized keys have ever been
 *   used - 128 192 256 - and PF_KEY can't describe that
 *
 */

#include "libreswan/pfkeyv2.h"

struct ike_alg; /* forward declaration */

struct alg_info;	/* forward declaration */
struct esp_info;	/* forward declaration */
struct alg_info_ike;	/* forward declaration */
struct alg_info_esp;	/* forward declaration */
struct oakley_group_desc;
struct encrypt_desc;
struct integ_desc;

extern bool kernel_alg_is_ok(const struct ike_alg *alg);

extern bool kernel_alg_dh_ok(const struct oakley_group_desc *dh);
extern bool kernel_alg_encrypt_ok(const struct encrypt_desc *encrypt);
extern bool kernel_alg_integ_ok(const struct integ_desc *integ);

bool kernel_alg_encrypt_key_size(const struct encrypt_desc *encrypt,
				 int keylen, size_t *key_size);

int kernel_alg_encrypt_count(void);
int kernel_alg_integ_count(void);

const struct encrypt_desc **next_kernel_encrypt_desc(const struct encrypt_desc **last);
const struct integ_desc **next_kernel_integ_desc(const struct integ_desc **last);

extern void kernel_alg_init(void);

void kernel_integ_add(const struct integ_desc *integ);
void kernel_encrypt_add(const struct encrypt_desc *encrypt);

#endif
