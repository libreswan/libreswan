/* Key Exchange Method algorithms, for libreswan
 *
 * Copyright (C) 2025 Andrew Cagney
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

#ifndef CRYPT_KEM_H
#define CRYPT_KEM_H

#include <pk11pub.h>

#include "shunk.h"
#include "chunk.h"
#include "diag.h"

struct logger;
struct kem_desc;

struct kem_initiator {
	/* set by crypt_kem_key_gen() */
	const struct kem_desc *kem;
	shunk_t ke;
	/* set by crypt_kem_decapsulate() */
	PK11SymKey *shared_key; /* aka SK(N) aka shared-secret */
	/* internal use only */
	struct {
		SECKEYPrivateKey *private_key;
		SECKEYPublicKey *public_key;
	} internal;
};

struct kem_responder {
	/* set by crypt_kem_encapsulate() */
	const struct kem_desc *kem;
	shunk_t ke;
	PK11SymKey *shared_key; /* aka SK(N) aka shared-secret */
	/* internal use only */
	struct {
		/* only used by legacy code, may be NULL, do not touch */
		SECKEYPrivateKey *private_key;
		SECKEYPublicKey *public_key;
	} internal;
};

diag_t crypt_kem_key_gen(const struct kem_desc *kem,
			 struct kem_initiator **kemk,
			 struct logger *logger);

diag_t crypt_kem_encapsulate(const struct kem_desc *kem,
			     shunk_t initiator_ke,
			     struct kem_responder **responder,
			     struct logger *logger);

diag_t crypt_kem_decapsulate(struct kem_initiator *kemk,
			     shunk_t responder_ke,
			     struct logger *logger);

void free_kem_initiator(struct kem_initiator **initiator,
			const struct logger *logger);

void free_kem_responder(struct kem_responder **responder,
			const struct logger *logger);

#endif
