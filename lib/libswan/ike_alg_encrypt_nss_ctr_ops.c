/*
 * Copyright (C) 2005-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2014 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Florian Weimer <fweimer@redhat.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2014-2016 Andrew Cagney <andrew.cagney@gmail.com>
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

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <sys/types.h>

#include <pk11pub.h>
#include <prmem.h>
#include <prerror.h>
#include <blapit.h>

#include "constants.h"
#include "lswlog.h"
#include "ike_alg.h"
#include "lswnss.h"
#include "ike_alg_encrypt_ops.h"
#include "crypt_cipher.h"
#include "rnd.h"
#include "hunk.h"

struct cipher_op_context {
	uint64_t v2_wire_iv;
	uint64_t v2_wire_count;
};

static struct cipher_op_context *cipher_op_context_create_ctr_nss(const struct encrypt_desc *cipher UNUSED,
								  enum cipher_op op UNUSED,
								  enum cipher_iv_source iv_source,
								  PK11SymKey *symkey UNUSED,
								  shunk_t salt UNUSED,
								  struct logger *logger)
{
	struct cipher_op_context *context = alloc_thing(struct cipher_op_context, __func__);
	switch (iv_source) {
	case FILL_WIRE_IV:
		context->v2_wire_iv = get_rnd_uintmax();
		context->v2_wire_count = 0;
		ldbgf(DBG_CRYPT, logger, "%s() initial wire_iv %"PRIx64" count %"PRIu64,
		      __func__, context->v2_wire_iv, context->v2_wire_count);
		break;
	case USE_WIRE_IV:
	case USE_IKEv1_IV:
		break;
	}
	return context;
}

static void cipher_op_ctr_nss(const struct encrypt_desc *cipher,
			      struct cipher_op_context *context,
			      enum cipher_op op,
			      enum cipher_iv_source iv_source,
			      PK11SymKey *sym_key,
			      shunk_t salt,
			      chunk_t wire_iv,
			      chunk_t text,
			      struct crypt_mac *ikev1_iv/*possbly-NULL*/,
			      struct logger *logger)
{
	ldbgf(DBG_CRYPT, logger, "%s() enter %s %p %s wire_iv %"PRIx64" count %"PRIu64,
	      __func__, cipher->common.fqn, context,
	      str_cipher_iv_source(iv_source),
	      context->v2_wire_iv, context->v2_wire_count);

	passert(sym_key);
	if (sym_key == NULL) {
		llog_passert(logger, HERE, "%s", "NSS derived enc key in NULL");
	}

	CK_AES_CTR_PARAMS ctr_params = {
		.ulCounterBits = sizeof(uint32_t) * 8, /* Per RFC 3686 */
		.cb = {0}, /* be explicit */
	};

	switch (iv_source) {
	case USE_WIRE_IV:
		PASSERT(logger, ikev1_iv == NULL);
		PASSERT(logger, salt.len + wire_iv.len + ctr_params.ulCounterBits / 8 == sizeof(ctr_params.cb));
		memcpy(ctr_params.cb, salt.ptr, salt.len);
		memcpy(ctr_params.cb + salt.len, wire_iv.ptr, wire_iv.len);
		ctr_params.cb[sizeof(ctr_params.cb) - 1] = 1;
		break;
	case FILL_WIRE_IV:
		PASSERT(logger, ikev1_iv == NULL);
		PASSERT(logger, salt.len + wire_iv.len + ctr_params.ulCounterBits / 8 == sizeof(ctr_params.cb));
		PASSERT(logger, wire_iv.len > 0);
		PASSERT(logger, context->v2_wire_iv != 0);
		PASSERT(logger, sizeof(context->v2_wire_iv) >= wire_iv.len);
		/* like AEAD, use RND ^ COUNT++ */
		hton_chunk(context->v2_wire_iv ^ context->v2_wire_count, wire_iv);
		context->v2_wire_count++;
		memcpy(ctr_params.cb, salt.ptr, salt.len);
		memcpy(ctr_params.cb + salt.len, wire_iv.ptr, wire_iv.len);
		ctr_params.cb[sizeof(ctr_params.cb) - 1] = 1;
		break;
	case USE_IKEv1_IV:
		PASSERT(logger, ikev1_iv != NULL);
		PASSERT(logger, ikev1_iv->len == sizeof(ctr_params.cb));
		memcpy(ctr_params.cb, ikev1_iv->ptr, sizeof(ctr_params.cb));
		break;
	}

	LDBGP_JAMBUF(DBG_CRYPT, logger, buf) {
		jam(buf, "ctr_param: count %lu iv ", ctr_params.ulCounterBits);
		jam_hex_bytes(buf, ctr_params.cb, sizeof(ctr_params.cb));
	}

	SECItem param;
	param.type = siBuffer;
	param.data = (void*)&ctr_params;
	param.len = sizeof(ctr_params);

	/* Output buffer for transformed data. */
	uint8_t *out_ptr = PR_Malloc(text.len);
	unsigned int out_len = 0; /* not size_t; ulgh! */

	switch (op) {
	case ENCRYPT:
	{
		SECStatus rv = PK11_Encrypt(sym_key, CKM_AES_CTR, &param,
					    out_ptr, &out_len, text.len,
					    text.ptr, text.len);
		if (rv != SECSuccess) {
			passert_nss_error(logger, HERE, "PK11_Encrypt failure");
		}
		break;
	}
	case DECRYPT:
	{
		SECStatus rv = PK11_Decrypt(sym_key, CKM_AES_CTR, &param,
					    out_ptr, &out_len, text.len,
					    text.ptr, text.len);
		if (rv != SECSuccess) {
			passert_nss_error(logger, HERE, "PK11_Decrypt failure");
		}
		break;
	}
	default:
		bad_case(op);
	}

	memcpy(text.ptr, out_ptr, text.len);
	PR_Free(out_ptr);


	if (iv_source == USE_IKEv1_IV) {
		/*
		 * Finally update the counter located at the end of
		 * the counter_block. It is incremented by 1 for every
		 * full or partial block encoded/decoded.
		 *
		 * There's a portability assumption here that the IV
		 * buffer is at least sizeof(uint32_t) (4-byte)
		 * aligned.
		 */
		uint32_t *counter = (uint32_t*)(ikev1_iv->ptr + AES_BLOCK_SIZE - sizeof(uint32_t));
		uint32_t old_counter = ntohl(*counter);
		size_t increment = (text.len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
		uint32_t new_counter = old_counter + increment;
		ldbgf(DBG_CRYPT, logger,
		      "%s() counter-block updated from 0x%" PRIx32 " to 0x%" PRIx32 " for %zd bytes",
		      __func__, old_counter, new_counter, text.len);
		/* Wrap ... */
		passert(new_counter >= old_counter);
		*counter = htonl(new_counter);
	}

	ldbgf(DBG_CRYPT, logger, "do_aes_ctr: exit");
}

static void cipher_op_context_destroy_ctr_nss(struct cipher_op_context **context,
					      struct logger *logger)
{
	ldbgf(DBG_CRYPT, logger, "%s()", __func__);
	pfreeany(*context);
}

static void cipher_check_ctr_nss(const struct encrypt_desc *cipher,
				 struct logger *logger)
{
	ldbgf(DBG_CRYPT, logger, "%s() nothing to do with %p",
	      __func__, cipher);
}

const struct encrypt_ops ike_alg_encrypt_nss_ctr_ops = {
	.backend = "NSS(CTR)",
	.cipher_check = cipher_check_ctr_nss,
	.cipher_op_context_create = cipher_op_context_create_ctr_nss,
	.cipher_op_normal = cipher_op_ctr_nss,
	.cipher_op_context_destroy = cipher_op_context_destroy_ctr_nss,
};
