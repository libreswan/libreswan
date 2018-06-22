/*
 * AES, for libreswan.
 *
 * Copyright (C) 2016 Andrew Cagney <andrew.cagney@gmail.com>
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

extern const struct encrypt_desc ike_alg_encrypt_aes_cbc;
extern const struct encrypt_desc ike_alg_encrypt_aes_ctr;
extern const struct encrypt_desc ike_alg_encrypt_aes_gcm_8;
extern const struct encrypt_desc ike_alg_encrypt_aes_gcm_12;
extern const struct encrypt_desc ike_alg_encrypt_aes_gcm_16;
extern const struct encrypt_desc ike_alg_encrypt_aes_ccm_8;
extern const struct encrypt_desc ike_alg_encrypt_aes_ccm_12;
extern const struct encrypt_desc ike_alg_encrypt_aes_ccm_16;
extern const struct encrypt_desc ike_alg_encrypt_null_integ_aes_gmac;

extern const struct prf_desc ike_alg_prf_aes_xcbc;

extern const struct integ_desc ike_alg_integ_aes_xcbc;
extern const struct integ_desc ike_alg_integ_aes_cmac;
