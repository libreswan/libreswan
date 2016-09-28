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

#ifndef crypt_misc_h
#define crypt_misc_h

#include <stdio.h>
#include <pk11pub.h>
#include "lswalloc.h"


/*
 * Log the full details of a SYMKEY.
 *
 * When DBG_PRIVATE and not FIPS, the full contents of the symkey are
 * included in the dump.
 */
void DBG_dump_symkey(const char *prefix, PK11SymKey *key);

/*
 * Low-level routine to return a SYMKEY.
 *
 * It is used by CAVP testing.
 */
PK11SymKey *chunk_to_symkey(CK_MECHANISM_TYPE cipher_mechanism, chunk_t raw_key);

/*
 * Return contents of a symkey.  If BYTES is non-NULL then store the
 * contents into that buffer.  If the operation fails then NULL or
 * "empty_chunk" is returned.
 */
void *bytes_from_symkey(const char *prefix, PK11SymKey *symkey, void *bytes);
chunk_t chunk_from_symkey(const char *prefix, PK11SymKey *symkey);

#endif
