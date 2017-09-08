/*
 * NULL, for libreswan.
 *
 * Copyright (C) 2017 Andrew Cagney <cagney@gnu.org>
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

extern const struct encrypt_desc ike_alg_encrypt_null;

/*
 * IKEv2 RFC 7296 uses the term "NONE" when refering to no integrity.
 * For instance: ... MUST either offer no integrity algorithm or a
 * single integrity algorithm of "NONE"
 */
extern const struct integ_desc ike_alg_integ_none;
