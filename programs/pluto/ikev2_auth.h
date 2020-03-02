/* IKEv2 authentication, for libreswan
 *
 * Copyright (C) 2019  Andrew Cagney
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

#ifndef IKEV2_SIGHASH_H
#define IKEV2_SIGHASH_H

#include <stdbool.h>

#include "chunk.h"

struct crypt_mac;
struct state;
struct ike_sa;

struct crypt_mac v2_calculate_sighash(const struct state *st,
				      enum original_role role,
				      const struct crypt_mac *idhash,
				      const chunk_t firstpacket,
				      const struct hash_desc *hasher);

enum keyword_authby v2_auth_by(struct ike_sa *ike);
enum ikev2_auth_method v2_auth_method(struct ike_sa *ike, enum keyword_authby authby);
const struct hash_desc *v2_auth_hash_desc(enum notify_payload_hash_algorithms hash_algo);

#endif
