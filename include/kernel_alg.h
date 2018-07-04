/*
 * Kernel runtime algorithm handling interface definitions
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 * Copyright (C) 2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2017 Andrew Cagney
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

#ifndef _KERNEL_ALG_H
#define _KERNEL_ALG_H
#include "libreswan/pfkeyv2.h"

struct ike_alg; /* forward declaration */
struct sadb_msg; /* forward definition */

/* Registration messages from pluto */
extern void kernel_alg_register_pfkey(const struct sadb_msg *msg);

struct alg_info;	/* forward declaration */
struct esp_info;	/* forward declaration */
struct alg_info_ike;	/* forward declaration */
struct alg_info_esp;	/* forward declaration */

extern bool kernel_alg_is_ok(const struct ike_alg *alg);

extern bool kernel_alg_dh_ok(const struct oakley_group_desc *dh);
extern bool kernel_alg_encrypt_ok(const struct encrypt_desc *encrypt);
extern bool kernel_alg_integ_ok(const struct integ_desc *integ);

/* ESP interface */
extern struct sadb_alg *kernel_alg_esp_sadb_alg(int alg_id);

/* get sadb_alg for passed args */
extern const struct sadb_alg *kernel_alg_sadb_alg_get(unsigned satype, unsigned exttype,
						       unsigned alg_id);

bool kernel_alg_encrypt_key_size(const struct encrypt_desc *encrypt,
				 int keylen, size_t *key_size);

int kernel_alg_encrypt_count(void);
int kernel_alg_integ_count(void);

struct sadb_alg *next_kernel_encrypt_alg(struct sadb_alg *last);
struct sadb_alg *next_kernel_integ_alg(struct sadb_alg *last);

extern void kernel_alg_init(void);

extern int kernel_alg_add(int satype, int exttype,
			  const struct sadb_alg *sadb_alg);

void kernel_integ_add(const struct integ_desc *integ);
void kernel_encrypt_add(const struct encrypt_desc *encrypt);

#endif /* _KERNEL_ALG_H */
