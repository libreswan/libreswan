/* crypto interfaces
 * Copyright (C) 1998, 1999  D. Hugh Redelmeier.
 * Copyright (C) 2003-2008 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
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

#ifndef _CRYPTO_H
#define _CRYPTO_H

#include <nss.h>
#include <pk11pub.h>

extern void init_crypto(void);

/* unification of cryptographic encoding/decoding algorithms
 *
 * The IV is taken from and returned to st->st_new_iv.
 * This allows the old IV to be retained.
 * Use update_iv to commit to the new IV (for example, once a packet has
 * been validated).
 */

#define MAX_OAKLEY_KEY_LEN_OLD  (3 * DES_CBC_BLOCK_SIZE)
#define MAX_OAKLEY_KEY_LEN  (256 / BITS_PER_BYTE)

/* macros to manipulate IVs in state */

#define update_iv(st)	{ \
	passert((st)->st_new_iv_len <= sizeof((st)->st_iv)); \
	(st)->st_iv_len = (st)->st_new_iv_len; \
	memcpy((st)->st_iv, (st)->st_new_iv, (st)->st_new_iv_len); \
    }

#define set_ph1_iv_from_new(st)	{ \
	passert((st)->st_new_iv_len <= sizeof((st)->st_ph1_iv)); \
	(st)->st_ph1_iv_len = (st)->st_new_iv_len; \
	memcpy((st)->st_ph1_iv, (st)->st_new_iv, (st)->st_ph1_iv_len); \
 }

#define save_iv(st, tmp, tmp_len) { \
	passert((st)->st_iv_len <= sizeof((tmp))); \
	(tmp_len) = (st)->st_iv_len; \
	memcpy((tmp), (st)->st_iv, (tmp_len)); \
    }

#define restore_iv(st, tmp, tmp_len) { \
	passert((tmp_len) <= sizeof((st)->st_iv)); \
	(st)->st_iv_len = (tmp_len); \
	memcpy((st)->st_iv, (tmp), (tmp_len)); \
    }

#define save_new_iv(st, tmp, tmp_len)	{ \
	passert((st)->st_new_iv_len <= sizeof((tmp))); \
	(tmp_len) = (st)->st_new_iv_len; \
	memcpy((tmp), (st)->st_new_iv, (tmp_len)); \
    }

#define restore_new_iv(st, tmp, tmp_len)	{ \
	passert((tmp_len) <= sizeof((st)->st_new_iv)); \
	(st)->st_new_iv_len = (tmp_len); \
	memcpy((st)->st_new_iv, (tmp), (tmp_len)); \
    }

/*
 * HMAC package (new code should use crypt_prf).
 */

struct crypt_prf;
struct prf_desc;        /* opaque */

struct hmac_ctx {
	struct crypt_prf *prf;
	size_t hmac_digest_len;
};

extern void hmac_init(struct hmac_ctx *ctx,
		      const struct prf_desc *prf_desc,
		      /*const*/ PK11SymKey *symkey);

extern void hmac_update(struct hmac_ctx *ctx,
			const u_char *data,
			size_t data_len);

#define hmac_update_chunk(ctx, ch) hmac_update((ctx), (ch).ptr, (ch).len)

extern void hmac_final(u_char *output, struct hmac_ctx *ctx);

struct connection;

void ike_alg_show_connection(const struct connection *c, const char *instance);

void ike_alg_show_status(void);

#endif /* _CRYPTO_H */
