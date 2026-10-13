/* signers, for libreswan
 *
 * Copyright (C) 2026  Andrew Cagney
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

#include "lswcdefs.h"
#include "secrets.h"

static const struct pubkey_signer *pubkey_blob_signer[] = {
	&signer_pubkey_rsassa_pss_blob,
	&signer_pubkey_ecdsa_blob,
	&signer_pubkey_eddsa_ed25519_blob,
	&signer_pubkey_rsassa_pkcs1_1_5_blob,
};

const struct pubkey_signers pubkey_blob_signers = {
	LIST_REF(pubkey_blob_signer),
};
