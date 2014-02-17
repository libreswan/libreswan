/*
 * Loading of PEM encoded files with optional encryption
 *
 * Copyright (C) 2001-2004 Andreas Steffen, Zuercher Hochschule Winterthur
 * Copyright (C) 2003-2005 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
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
 *
 * Decryption support removed - we only supported private key files via NSS
 * (if we do an openssl port, it needs to use native openssl functions for this)
 */

/*
 * decrypt a PEM encoded data block using DES-EDE3-CBC
 * see RFC 1423 PEM: Algorithms, Modes and Identifiers
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stddef.h>
#include <sys/types.h>

#include <libreswan.h>
#define HEADER_DES_LOCL_H	/*
				 * stupid trick to force prototype decl in
				 * <des.h>
				 */
#include "sysdep.h"
#include "constants.h"
#include "lswalloc.h"
#include "lswtime.h"
#include "lswlog.h"
#include "md5.h"
#include "pem.h"

#include <pk11pub.h>
#include <prmem.h>
#include <prerror.h>
#include "lswconf.h"

#include "lswcrypto.h"

/*
 * check the presence of a pattern in a character string
 */
static bool present(const char* pattern, chunk_t* ch)
{
	u_int pattern_len = strlen(pattern);

	if (ch->len >= pattern_len &&
		strncmp((char *)ch->ptr, pattern, pattern_len) == 0) {
		ch->ptr += pattern_len;
		ch->len -= pattern_len;
		return TRUE;
	}
	return FALSE;
}

/*
 * compare string with chunk
 */
static bool match(const char *pattern, const chunk_t *ch)
{
	return ch->len == strlen(pattern) &&
		strncmp(pattern, (char *)ch->ptr, ch->len) == 0;
}

/*
 * find a boundary of the form -----tag name-----
 */
static bool find_boundary(const char* tag, chunk_t *line)
{
	chunk_t name = empty_chunk;

	if (!present("-----", line))
		return FALSE;

	if (!present(tag, line))
		return FALSE;

	if (*line->ptr != ' ')
		return FALSE;

	line->ptr++;
	line->len--;

	/* extract name */
	name.ptr = line->ptr;
	while (line->len > 0) {
		if (present("-----", line)) {
			DBG(DBG_PARSING,
				DBG_log("  -----%s %.*s-----",
					tag, (int)name.len, name.ptr)
				);
			return TRUE;
		}
		line->ptr++;
		line->len--;
		name.len++;
	}
	return FALSE;
}

/*
 * eat whitespace
 */
static void eat_whitespace(chunk_t *src)
{
	while (src->len > 0 && (*src->ptr == ' ' || *src->ptr == '\t')) {
		src->ptr++;
		src->len--;
	}
}

/*
 * extracts a token ending with a given termination symbol
 */
static bool extract_token(chunk_t *token, char termination, chunk_t *src)
{
	u_char *eot = memchr(src->ptr, termination, src->len);

	/* initialize empty token */
	*token = empty_chunk;

	if (eot == NULL)	/* termination symbol not found */
		return FALSE;

	/* extract token */
	token->ptr = src->ptr;
	token->len = (u_int)(eot - src->ptr);

	/* advance src pointer after termination symbol */
	src->ptr = eot + 1;
	src->len -= (token->len + 1);

	return TRUE;
}

/*
 * extracts a name: value pair from the PEM header
 */
static bool extract_parameter(chunk_t *name, chunk_t *value, chunk_t *line)
{
	DBG(DBG_PARSING,
		DBG_log("  %.*s", (int)line->len, line->ptr);
		);

	/* extract name */
	if (!extract_token(name, ':', line))
		return FALSE;

	eat_whitespace(line);

	/* extract value */
	*value = *line;
	return TRUE;
}

/*
 *  fetches a new line terminated by \n or \r\n
 */
static bool fetchline(chunk_t *src, chunk_t *line)
{
	if (src->len == 0)	/* end of src reached */
		return FALSE;

	if (extract_token(line, '\n', src)) {
		if (line->len > 0 && *(line->ptr + line->len - 1) == '\r')
			line->len--;	/* remove optional \r */
	} else {	/*last line ends without newline */
		*line = *src;
		src->ptr += src->len;
		src->len = 0;
	}
	return TRUE;
}

/*
 * Converts a PEM encoded file into its binary form
 *
 * RFC 1421 Privacy Enhancement for Electronic Mail, February 1993
 * RFC 934 Message Encapsulation, January 1985
 *
 * We no longer support decrypting PEM files - those can only come in via NSS
 */
err_t pemtobin(chunk_t *blob)
{
	typedef enum {
		PEM_PRE    = 0,
		PEM_MSG    = 1,
		PEM_HEADER = 2,
		PEM_BODY   = 3,
		PEM_POST   = 4,
		PEM_ABORT  = 5
	} state_t;

	state_t state  = PEM_PRE;

	chunk_t src    = *blob;
	chunk_t dst    = *blob;
	chunk_t line   = empty_chunk;

	/* zero size of converted blob */
	dst.len = 0;

	while (fetchline(&src, &line)) {
		if (state == PEM_PRE) {
			if (find_boundary("BEGIN", &line)) {
				state = PEM_MSG;
			}
			continue;
		} else {
			if (find_boundary("END", &line)) {
				state = PEM_POST;
				break;
			}
			if (state == PEM_MSG) {
				state =
					(memchr(line.ptr, ':',
						line.len) == NULL) ?
					PEM_BODY : PEM_HEADER;
			}
			if (state == PEM_HEADER) {
				chunk_t name  = empty_chunk;
				chunk_t value = empty_chunk;

				/* an empty line separates HEADER and BODY */
				if (line.len == 0) {
					state = PEM_BODY;
					continue;
				}

				/* we are looking for a name: value pair */
				if (!extract_parameter(&name, &value, &line))
					continue;

				if (match("Proc-Type",
						&name) && *value.ptr == '4')
					return "Proc-Type: encrypted files no longer supported outside of the NSS database, please import these into NSS";

				else if (match("DEK-Info", &name))
					return "DEK-Info: encrypted files no longer supported outside of the NSS database, please import these into NSS";

			} else { /* state is PEM_BODY */
				const char *ugh = NULL;
				size_t len = 0;
				chunk_t data;

				/* remove any trailing whitespace */
				if (!extract_token(&data, ' ', &line))
					data = line;

				ugh = ttodata((char *)data.ptr, data.len, 64,
					(char *)dst.ptr,
					blob->len - dst.len, &len);
				if (ugh) {
					DBG(DBG_PARSING,
						DBG_log("  %s", ugh);
						);
					state = PEM_ABORT;
					break;
				} else {
					dst.ptr += len;
					dst.len += len;
				}
			}
		}
	}
	/* set length to size of binary blob */
	blob->len = dst.len;

	if (state != PEM_POST)
		return "file coded in unknown format, discarded";

	return NULL;
}

void do_3des_nss(u_int8_t *buf, size_t buf_len,
		u_int8_t *key, size_t key_size, u_int8_t *iv, bool enc)
{
	u_int8_t *tmp_buf;
	u_int8_t *new_iv;

	CK_MECHANISM_TYPE ciphermech;
	SECItem ivitem;
	SECItem *secparam;
	PK11SymKey *symkey = NULL;
	PK11Context *enccontext = NULL;
	SECStatus rv;
	int outlen;

	DBG(DBG_CRYPT,
		DBG_log("NSS: do_3des init start");
		);
	passert(key != NULL);

	ciphermech = CKM_DES3_CBC;	/* libreswan provides padding */

	memcpy(&symkey, key, key_size);
	if (symkey == NULL) {
		loglog(RC_LOG_SERIOUS,
			"do_3des: NSS derived enc key is NULL\n");
		abort();
	}

	ivitem.type = siBuffer;
	ivitem.data = iv;
	ivitem.len = DES_CBC_BLOCK_SIZE;

	secparam = PK11_ParamFromIV(ciphermech, &ivitem);
	if (secparam == NULL) {
		loglog(RC_LOG_SERIOUS,
			"do_3des: Failure to set up PKCS11 param (err %d)\n",
			PR_GetError());
		abort();
	}

	outlen = 0;
	tmp_buf = PR_Malloc((PRUint32)buf_len);
	new_iv = (u_int8_t*)PR_Malloc((PRUint32)DES_CBC_BLOCK_SIZE);

	if (!enc)
		memcpy(new_iv, (char*) buf + buf_len - DES_CBC_BLOCK_SIZE,
			DES_CBC_BLOCK_SIZE);

	enccontext = PK11_CreateContextBySymKey(ciphermech,
						enc ? CKA_ENCRYPT :
						CKA_DECRYPT, symkey,
						secparam);
	if (enccontext == NULL) {
		loglog(RC_LOG_SERIOUS,
			"do_3des: PKCS11 context creation failure (err %d)\n",
			PR_GetError());
		abort();
	}
	rv = PK11_CipherOp(enccontext, tmp_buf, &outlen, buf_len, buf,
			buf_len);
	if (rv != SECSuccess) {
		loglog(RC_LOG_SERIOUS,
			"do_3des: PKCS11 operation failure (err %d)\n",
			PR_GetError());
		abort();
	}

	if (enc)
		memcpy(new_iv, (char*) tmp_buf + buf_len - DES_CBC_BLOCK_SIZE,
			DES_CBC_BLOCK_SIZE);

	memcpy(buf, tmp_buf, buf_len);
	memcpy(iv, new_iv, DES_CBC_BLOCK_SIZE);
	PK11_DestroyContext(enccontext, PR_TRUE);
	PR_Free(tmp_buf);
	PR_Free(new_iv);

	if (secparam != NULL)
		SECITEM_FreeItem(secparam, PR_TRUE);

	DBG(DBG_CRYPT,
		DBG_log("NSS: do_3des init end");
		);
}
