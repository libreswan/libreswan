/*
 * SYMKEY debug functions, for libreswan
 *
 * Copyright (C) 2015, 2016 Andrew Cagney <cagney@gnu.org>
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

#include "libreswan.h"
#include "lswalloc.h"
#include "lswlog.h"
#include "ike_alg.h"
#include "crypt_dbg.h"
#include "crypt_symkey.h"

#include "crypto.h"
#include "lswnss.h"
#include "lswfips.h"

void DBG_dump_symkey(const char *prefix, PK11SymKey *key)
{
	DBG_symkey(prefix, key);
	if (key != NULL) {
		if (DBGP(DBG_PRIVATE)) {
			if (libreswan_fipsmode()) {
				DBG_log("%s secured by FIPS", prefix);
			} else {
				chunk_t bytes = chunk_from_symkey(prefix, 0, key);
				/* NULL suppresses the dump header */
				DBG_dump_chunk(NULL, bytes);
				freeanychunk(bytes);
			}
		}
	}
}
