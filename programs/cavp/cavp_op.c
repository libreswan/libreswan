/* parse operations, for libreswan (CAVP)
 *
 * Copyright (C) 2015-2016, Andrew Cagney <cagney@gnu.org>
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

#include "cavp.h"
#include "cavp_op.h"
#include "test_buffer.h"
#include "crypt_symkey.h"

void op_entry(struct cavp_entry *entry,
	      const char *value UNUSED)
{
	passert(entry->entry != NULL);
	*(entry->entry) = entry;
}

void op_chunk(struct cavp_entry *entry,
	      const char *value)
{
	passert(entry->chunk != NULL);
	freeanychunk(*(entry->chunk));
	*(entry->chunk) = decode_hex_to_chunk(entry->key, value);
}

void op_symkey(struct cavp_entry *entry,
	       const char *value)
{
	passert(entry->symkey != NULL);
	release_symkey(__func__, "entry", entry->symkey);
	*(entry->symkey) = decode_hex_to_symkey(entry->key, value);
}

void op_signed_long(struct cavp_entry *entry,
		    const char *value)
{
	passert(entry->signed_long != NULL);
	*(entry->signed_long) = strtol(value, NULL, 10);
}

void op_unsigned_long(struct cavp_entry *entry,
		      const char *value)
{
	passert(entry->unsigned_long != NULL);
	*(entry->unsigned_long) = strtoul(value, NULL, 10);
}

void op_ignore(struct cavp_entry *entry UNUSED,
	       const char *value UNUSED)
{
}
