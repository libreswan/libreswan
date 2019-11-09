/* encryption algorithms, for libreswan
 *
 * Copyright (C) 2016 Andrew Cagney <andrew.cagney@gmail.com>
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

#ifdef USE_AES
extern const struct encrypt_desc ike_alg_encrypt_aes_cbc;
extern const struct encrypt_desc ike_alg_encrypt_aes_ctr;
extern const struct encrypt_desc ike_alg_encrypt_aes_gcm_8;
extern const struct encrypt_desc ike_alg_encrypt_aes_gcm_12;
extern const struct encrypt_desc ike_alg_encrypt_aes_gcm_16;
extern const struct encrypt_desc ike_alg_encrypt_aes_ccm_8;
extern const struct encrypt_desc ike_alg_encrypt_aes_ccm_12;
extern const struct encrypt_desc ike_alg_encrypt_aes_ccm_16;
extern const struct encrypt_desc ike_alg_encrypt_null_integ_aes_gmac;
#endif

#ifdef USE_CAMELLIA
extern const struct encrypt_desc ike_alg_encrypt_camellia_cbc;
extern const struct encrypt_desc ike_alg_encrypt_camellia_ctr;
#endif

#ifdef USE_TWOFISH
extern const struct encrypt_desc ike_alg_encrypt_twofish_ssh;
extern const struct encrypt_desc ike_alg_encrypt_twofish_cbc;
#endif

#ifdef USE_3DES
extern const struct encrypt_desc ike_alg_encrypt_3des_cbc;
#endif

#ifdef USE_SERPENT
extern const struct encrypt_desc ike_alg_encrypt_serpent_cbc;
#endif

extern const struct encrypt_desc ike_alg_encrypt_null;

#ifdef USE_CAST
extern const struct encrypt_desc ike_alg_encrypt_cast_cbc;
#endif

#ifdef USE_CHACHA
extern const struct encrypt_desc ike_alg_encrypt_chacha20_poly1305;
#endif
