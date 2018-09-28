/* PRF algorithms, for libreswan
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
extern const struct prf_desc ike_alg_prf_aes_xcbc;
#endif

#ifdef USE_SHA1
extern const struct prf_desc ike_alg_prf_sha1;
#endif

#ifdef USE_SHA2
extern const struct prf_desc ike_alg_prf_sha2_256;
extern const struct prf_desc ike_alg_prf_sha2_384;
extern const struct prf_desc ike_alg_prf_sha2_512;
#endif

#ifdef USE_MD5
extern const struct prf_desc ike_alg_prf_md5;
#endif
