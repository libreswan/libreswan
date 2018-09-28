/* Test algorithms, for libreswan
 *
 * Copyright (C) 2018 Andrew Cagney <cagney@gnu.org>
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

#include "lswlog.h"
#include "ike_alg.h"
#include "ike_alg_encrypt.h"
#include "ike_alg_prf.h"

#include "ike_alg_test_ctr.h"
#include "ike_alg_test_cbc.h"
#include "ike_alg_test_gcm.h"
#include "ike_alg_test_prf.h"

void test_ike_alg(void)
{
#ifdef USE_CAMELLIA
	passert(test_cbc_vectors(&ike_alg_encrypt_camellia_cbc,
				 camellia_cbc_tests));
#endif
#ifdef USE_AES
	passert(test_gcm_vectors(&ike_alg_encrypt_aes_gcm_16,
				 aes_gcm_tests));
	passert(test_ctr_vectors(&ike_alg_encrypt_aes_ctr,
				 aes_ctr_tests));
	passert(test_cbc_vectors(&ike_alg_encrypt_aes_cbc,
				 aes_cbc_tests));
	passert(test_prf_vectors(&aes_xcbc_prf_tests));
#endif
}
