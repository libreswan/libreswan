/*
 * Copyright (C) 2015 Andrew Cagney <andrew.cagney@gmail.com>
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

bool test_aes_gcm(void);

bool do_aes_gcm(u_int8_t *salt, size_t salt_size,
		u_int8_t *wire_iv, size_t wire_iv_size,
		u_int8_t *aad, size_t aad_size,
		u_int8_t *text_and_tag,
		size_t text_size, size_t tag_size,
		PK11SymKey *key, bool enc);
