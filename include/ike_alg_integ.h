/* integ algorithms, for libreswan
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
extern const struct integ_desc ike_alg_integ_aes_xcbc;
extern const struct integ_desc ike_alg_integ_aes_cmac;
#endif

#ifdef USE_SHA1
extern const struct integ_desc ike_alg_integ_sha1;
#endif

#ifdef USE_SHA2
extern const struct integ_desc ike_alg_integ_sha2_256;
extern const struct integ_desc ike_alg_integ_sha2_384;
extern const struct integ_desc ike_alg_integ_sha2_512;
extern const struct integ_desc ike_alg_integ_hmac_sha2_256_truncbug;
#endif

#ifdef USE_MD5
extern const struct integ_desc ike_alg_integ_md5;
#endif

#ifdef USE_RIPEMD
extern const struct integ_desc ike_alg_integ_hmac_ripemd_160_96;
#endif

/*
 * IKEv2 RFC 7296 uses the term "NONE" when referring to no integrity.
 * For instance: ... MUST either offer no integrity algorithm or a
 * single integrity algorithm of "NONE"
 */
extern const struct integ_desc ike_alg_integ_none;
