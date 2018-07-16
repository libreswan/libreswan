/*
 * Kernel runtime algorithm handling interface
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
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
 * Fixes by:
 *	ML: Mathieu Lafon <mlafon@arkoon.net>
 *
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/queue.h>

#include <libreswan.h>

#include <libreswan/pfkeyv2.h>
#include <libreswan/pfkey.h>

#include "constants.h"
#include "alg_info.h"
#include "kernel_alg.h"
#include "lswlog.h"
#include "lswalloc.h"
#include "ietf_constants.h"

#include "ike_alg.h"
#include "ike_alg_encrypt.h"
#include "ike_alg_integ.h"

/*
 * The kernel algorithm database is indexed by SADB (PRF) kernel
 * values and assumes there is a value for every single supported
 * algorithm.
 *
 * The assumption isn't valid.  Magic SADB values have been added when
 * no official value was available.
 *
 * The code should instead be rewritten to use 'struct ike_alg*' as a
 * kernel interface agnostic way of identifying algorithms.  Later.
 */

/* ALG storage */
static const struct integ_desc *esp_aalg[K_SADB_AALG_MAX + 1];
static const struct encrypt_desc *esp_ealg[K_SADB_EALG_MAX + 1];
static int esp_ealg_num = 0;
static int esp_aalg_num = 0;

#define ESP_EALG_PRESENT(algo) ((algo) <= K_SADB_EALG_MAX && \
				esp_ealg[algo] != NULL)

#define ESP_EALG_FOR_EACH(algo) \
	for ((algo) = 1; (algo) <= K_SADB_EALG_MAX; (algo)++) \
		if (ESP_EALG_PRESENT(algo))

#define ESP_AALG_PRESENT(algo) ((algo) <= SADB_AALG_MAX && \
				esp_aalg[algo] != NULL)

#define ESP_AALG_FOR_EACH(algo) \
	for ((algo) = 1; (algo) <= SADB_AALG_MAX; (algo)++) \
		if (ESP_AALG_PRESENT(algo))

/*
 *      Forget previous registration
 */
void kernel_alg_init(void)
{
	DBG(DBG_KERNEL, DBG_log("kernel_alg_init()"));
	/* ??? do these zero calls do anything useful? */
	zero(&esp_aalg);
	zero(&esp_ealg);
	esp_ealg_num = esp_aalg_num = 0;
}

void kernel_integ_add(const struct integ_desc *alg)
{
	const struct integ_desc **dest = &esp_aalg[alg->integ_sadb_aalg_id];
	if (*dest == NULL) {
		*dest = alg;
		esp_aalg_num++;
	} else {
		DBGF(DBG_KERNEL,
		     "dropping duplicate %s kernel integrity algorithm",
		     alg->common.fqn);
	}
}

void kernel_encrypt_add(const struct encrypt_desc *alg)
{
	const struct encrypt_desc **dest = &esp_ealg[alg->encrypt_sadb_ealg_id];
	if (*dest == NULL) {
		*dest = alg;
		esp_ealg_num++;
	} else {
		DBGF(DBG_KERNEL,
		     "dropping duplicate %s kernel encryption algorithm",
		     alg->common.fqn);
	}
}

bool kernel_alg_dh_ok(const struct oakley_group_desc *dh)
{
	if (dh == NULL) {
		PEXPECT_LOG("%s", "DH needs to be valid (non-NULL)");
		return false;
	}
	/* require an in-process/ike implementation of DH */
	return ike_alg_is_ike(&dh->common);
}

bool kernel_alg_encrypt_ok(const struct encrypt_desc *encrypt)
{
	if (encrypt == NULL) {
		PEXPECT_LOG("%s", "encryption needs to be valid (non-NULL)");
		return false;
	}
	return ESP_EALG_PRESENT(encrypt->encrypt_sadb_ealg_id);
}

bool kernel_alg_integ_ok(const struct integ_desc *integ)
{
	if (integ == NULL) {
		PEXPECT_LOG("%s", "integrity needs to be valid (non-NULL)");
		return false;
	}
	return ESP_AALG_PRESENT(integ->integ_sadb_aalg_id);
}

bool kernel_alg_is_ok(const struct ike_alg *alg)
{
	if (alg == NULL) {
		PEXPECT_LOG("%s", "algorithm needs to be valid (non-NULL)");
		return false;
	} else if (alg->algo_type == &ike_alg_dh) {
		return kernel_alg_dh_ok(dh_desc(alg));
	} else if (alg->algo_type == &ike_alg_encrypt) {
		return kernel_alg_encrypt_ok(encrypt_desc(alg));
	} else if (alg->algo_type == &ike_alg_integ) {
		return kernel_alg_integ_ok(integ_desc(alg));
	} else {
		PASSERT_FAIL("algorithm %s of type %s is not valid in the kernel",
			     alg->fqn, ike_alg_type_name(alg->algo_type));
	}
}

bool kernel_alg_encrypt_key_size(const struct encrypt_desc *encrypt,
				 int keylen, size_t *key_size)
{
	/*
	 * Assume the two ENUMs are the same!
	 */
	enum ipsec_cipher_algo transid = encrypt->common.id[IKEv1_ESP_ID];
	int sadb_ealg = transid;

	/*
	 * XXX: Is KEYLEN ever zero for any case other than 'null'
	 * encryption?  If it is, patch it up and then log it to find
	 * out.
	 */
	if (keylen == 0) {
		if (encrypt != &ike_alg_encrypt_null) {
			keylen = encrypt_min_key_bit_length(encrypt);
			DBG(DBG_KERNEL,
			    DBG_log("XXX: %s has key length of 0, adjusting to %d",
				    encrypt->common.fqn, keylen));
		}
	}

	/*
	 * This is all this function should be doing, which isn't
	 * much.
	 */
	*key_size = keylen / BITS_PER_BYTE;
	DBG(DBG_PARSING,
	    DBG_log("encrypt %s keylen=%d transid=%d, key_size=%zu, encryptalg=%d",
		    encrypt->common.fqn, keylen, transid, *key_size, sadb_ealg));
	return true;
}

const struct encrypt_desc **next_kernel_encrypt_desc(const struct encrypt_desc **last)
{
	if (last == NULL) {
		last = &esp_ealg[1];
	} else {
		last++;
	}
	for (; last < &esp_ealg[elemsof(esp_ealg)]; last++) {
		if (*last != NULL) {
			return last;
		}
	}
	return NULL;
}

const struct integ_desc **next_kernel_integ_desc(const struct integ_desc **last)
{
	if (last == NULL) {
		last = &esp_aalg[1];
	} else {
		last++;
	}
	for (; last < &esp_aalg[elemsof(esp_aalg)]; last++) {
		if (*last != NULL) {
			return last;
		}
	}
	return NULL;
}

int kernel_alg_encrypt_count(void)
{
	return esp_ealg_num;
}

int kernel_alg_integ_count(void)
{
	return esp_aalg_num;
}
