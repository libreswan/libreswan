/* hmac interface for pluto ciphers.
 *
 * Copyright (C) 2006  Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012-2015 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2015, Andrew Cagney <cagney@gnu.org>
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
 *
 */

#include <sys/types.h>
#include <libreswan.h>

#include "constants.h"
#include "defs.h"
#include "crypto.h"
#include "alg_info.h"
#include "ike_alg.h"

#include <nss.h>
#include <pkcs11t.h>
#include <pk11pub.h>
#include <prlog.h>
#include <prmem.h>
#include <pk11priv.h>
#include <secport.h>
#include "lswconf.h"
#include "lswlog.h"
#include "crypt_symkey.h"
#include "crypt_prf.h"

/* HMAC package
 * rfc2104.txt specifies how HMAC works.
 */

void hmac_init(struct hmac_ctx *ctx,
	       const struct prf_desc *prf_desc,
	       /*const*/ PK11SymKey *symkey)	/* NSS doesn't like const! */
{
	/*
	 * Note: The SYMKEY passed to crypt_prf_init is used to
	 * generate secure keying material from nothing.
	 * crypt_prf_init_symkey() establishes the actual key.
	 */
	ctx->prf = crypt_prf_init_symkey("hmac", DBG_CRYPT,
					 prf_desc,
					 "symkey", symkey);
	ctx->hmac_digest_len = prf_desc->prf_output_size;
}

void hmac_update(struct hmac_ctx *ctx,
		 const u_char *data, size_t data_len)
{
	crypt_prf_update_bytes("data", ctx->prf, data, data_len);
}

void hmac_final(u_char *output, struct hmac_ctx *ctx)
{
	crypt_prf_final_bytes(&ctx->prf, output, ctx->hmac_digest_len);
}
