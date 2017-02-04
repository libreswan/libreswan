/*
 * Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
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

struct encrypt_desc;

bool ike_alg_nss_gcm(const struct encrypt_desc *alg UNUSED,
		     u_int8_t *salt, size_t salt_size,
		     u_int8_t *wire_iv, size_t wire_iv_size,
		     u_int8_t *aad, size_t aad_size,
		     u_int8_t *text_and_tag,
		     size_t text_size, size_t tag_size,
		     PK11SymKey *sym_key, bool enc);
