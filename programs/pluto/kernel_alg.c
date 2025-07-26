/* Kernel runtime algorithm, for libreswan
 *
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 * Copyright (C) 2018  Andrew Cagney
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
 *
 * Fixes by:
 *	ML: Mathieu Lafon <mlafon@arkoon.net>
 *
 */

#include <string.h>

#include "constants.h"
#include "kernel_alg.h"
#include "lswlog.h"
#include "ike_alg.h"
#include "ike_alg_encrypt.h"

/*
 * ALG storage.  Maintain several arrays.
 *
 * These arrays are sorted by alg's FQN.
 *
 * XXX: These arrays are grosely oversized.
 */

#define MAX_ALGS 32

static const struct integ_desc *integ_by_fqn[MAX_ALGS];
static const struct encrypt_desc *encrypt_by_fqn[MAX_ALGS];
static const struct ipcomp_desc *ipcomp_by_fqn[MAX_ALGS];
static size_t integ_num = 0;
static size_t encrypt_num = 0;
static size_t ipcomp_num = 0;

/*
 *      Forget previous registration
 *
 * XXX: Needed????
 */
void kernel_alg_init(void)
{
	dbg("kernel_alg_init()");
	/* ??? do these zero calls do anything useful? */
	zero(&integ_by_fqn);
	zero(&encrypt_by_fqn);
	zero(&ipcomp_by_fqn);
	encrypt_num = integ_num = ipcomp_num = 0;
}

/*
 * Make use of the fact that the table is kept sorted.
 */

#define ADD(ALG, DESC)							\
	dbg("adding %s to kernel algorithm db",				\
	     alg->common.fqn);						\
	size_t i;							\
	for (i = 0; i < DESC##_num; i++) {				\
		int cmp = strcmp(DESC##_by_fqn[i]->common.fqn,		\
				 alg->common.fqn);			\
		if (cmp == 0) {						\
			dbg("dropping %s kernel algorithm db duplicate found at %zu", \
			    alg->common.fqn, i);			\
			return;						\
		} else if (cmp > 0) {					\
			break; /* insertion point found */		\
		}							\
	}								\
	passert(DESC##_num < elemsof(DESC##_by_fqn));			\
	/* make space by moving the overlapping tail */			\
	memmove(&DESC##_by_fqn[i+1], &DESC##_by_fqn[i],			\
		(DESC##_num - i) * sizeof(DESC##_by_fqn[0]));		\
	DESC##_num++;							\
	/* insert */							\
	DESC##_by_fqn[i] = ALG;


void kernel_integ_add(const struct integ_desc *alg)
{
	ADD(alg, integ);
}

void kernel_encrypt_add(const struct encrypt_desc *alg)
{
	ADD(alg, encrypt);
}

void kernel_ipcomp_add(const struct ipcomp_desc *alg)
{
	ADD(alg, ipcomp);
}

void kernel_alg_add(const struct ike_alg *alg)
{
	if (alg->algo_type == &ike_alg_encrypt) {
		kernel_encrypt_add(encrypt_desc(alg));
	} else if (alg->algo_type == &ike_alg_integ) {
		kernel_integ_add(integ_desc(alg));
	} else if (alg->algo_type == &ike_alg_ipcomp) {
		kernel_ipcomp_add(ipcomp_desc(alg));
	} else {
		passert(0);
	}
}

bool kernel_alg_dh_ok(const struct kem_desc *dh)
{
	if (dh == NULL) {
		llog_pexpect(&global_logger, HERE,
			     "DH needs to be valid (non-NULL)");
		return false;
	}
	/* require an in-process/ike implementation of DH */
	return ike_alg_is_ike(&dh->common);
}

#define KERNEL_ALG_OK(ALG, DESC)\
	if (!pexpect(ALG != NULL)) {			\
		return false;				\
	}						\
	for (unsigned i = 0; i < DESC##_num; i++) {	\
		if (DESC##_by_fqn[i] == ALG) {		\
			return true;			\
		}					\
	}						\
	return false;


bool kernel_alg_encrypt_ok(const struct encrypt_desc *alg)
{
	KERNEL_ALG_OK(alg, encrypt);
}

bool kernel_alg_integ_ok(const struct integ_desc *alg)
{
	KERNEL_ALG_OK(alg, integ);
}

bool kernel_alg_ipcomp_ok(const struct ipcomp_desc *alg)
{
	KERNEL_ALG_OK(alg, ipcomp);
}

bool kernel_alg_is_ok(const struct ike_alg *alg)
{
	if (alg == NULL) {
		llog_pexpect(&global_logger, HERE,
			     "algorithm needs to be valid (non-NULL)");
		return false;
	} else if (alg->algo_type == &ike_alg_dh) {
		return kernel_alg_dh_ok(dh_desc(alg));
	} else if (alg->algo_type == &ike_alg_encrypt) {
		return kernel_alg_encrypt_ok(encrypt_desc(alg));
	} else if (alg->algo_type == &ike_alg_integ) {
		return kernel_alg_integ_ok(integ_desc(alg));
	} else if (alg->algo_type == &ike_alg_ipcomp) {
		return kernel_alg_ipcomp_ok(ipcomp_desc(alg));
	} else {
		llog_passert(&global_logger, HERE,
			     "algorithm %s of type %s is not valid in the kernel",
			     alg->fqn, ike_alg_type_name(alg->algo_type));
	}
}

bool kernel_alg_encrypt_key_size(const struct encrypt_desc *encrypt,
				 int keylen, size_t *key_size)
{
	/*
	 * Assume the two ENUMs are the same!
	 */
	enum ikev1_esp_transform transid = encrypt->common.id[IKEv1_IPSEC_ID];
	int sadb_ealg = transid;

	/*
	 * XXX: Is KEYLEN ever zero for any case other than 'null'
	 * encryption?  If it is, patch it up and then log it to find
	 * out.
	 */
	if (keylen == 0) {
		if (encrypt != &ike_alg_encrypt_null) {
			keylen = encrypt_min_key_bit_length(encrypt);
			dbg("XXX: %s has key length of 0, adjusting to %d",
			    encrypt->common.fqn, keylen);
		}
	}

	/*
	 * This is all this function should be doing, which isn't
	 * much.
	 */
	*key_size = keylen / BITS_IN_BYTE;
	dbg("encrypt %s keylen=%d transid=%d, key_size=%zu, encryptalg=%d",
	    encrypt->common.fqn, keylen, transid, *key_size, sadb_ealg);
	return true;
}

#define NEXT(LAST, DESC)						\
	if (LAST == NULL) {						\
		return &DESC##_by_fqn[0];				\
	} else if (LAST < &DESC##_by_fqn[DESC##_num-1]) {		\
		return LAST+1;						\
	} else {							\
		return NULL;						\
	}

const struct encrypt_desc **next_kernel_encrypt_desc(const struct encrypt_desc **last)
{
	NEXT(last, encrypt)
}

const struct integ_desc **next_kernel_integ_desc(const struct integ_desc **last)
{
	NEXT(last, integ)
}

const struct ipcomp_desc **next_kernel_ipcomp_desc(const struct ipcomp_desc **last)
{
	NEXT(last, ipcomp)
}

int kernel_alg_encrypt_count(void)
{
	return encrypt_num;
}

int kernel_alg_integ_count(void)
{
	return integ_num;
}

int kernel_alg_ipcomp_count(void)
{
	return ipcomp_num;
}
