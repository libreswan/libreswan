/*
 * NSS boilerplate stuff, for libreswan.
 *
 * Copyright (C) 2016,2020 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2018 Sahana Prasad <sahana.prasad07@gmail.com>
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

#ifndef CKAID_H
#define CKAID_H

#include <stdbool.h>		/* for bool */
#include <stdint.h>		/* for uint8_t */
#include <secitem.h>		/* for SECItem */
#include <stddef.h>		/* for size_t */

#include "err.h"
#include "chunk.h"
#include "jambuf.h"

/*
 * For rationale behind *_t? Blame chunk_t.
 *
 * Field names are so that it is chunk_t like.
 *
 * Assume SHA1 is being used for the CKAID
 */
#define CKAID_SIZE BYTES_FOR_BITS(160)

typedef struct {
	size_t len;
	uint8_t ptr[CKAID_SIZE];
} ckaid_t;

bool ckaid_starts_with(const ckaid_t *ckaid, const char *start);

err_t string_to_ckaid(const char *string, ckaid_t *ckaid);

 /* raw bytes in lower-case hex */
typedef struct {
	char buf[CKAID_SIZE * 2 + 1/*nul*/ + 1/*canary*/];
} ckaid_buf;
const char *str_ckaid(const ckaid_t *ckaid, ckaid_buf *buf);
size_t jam_ckaid(jambuf_t *buf, const ckaid_t *ckaid);

err_t form_ckaid_rsa(chunk_t modulus, ckaid_t *ckaid);
err_t form_ckaid_ecdsa(chunk_t pub_value, ckaid_t *ckaid);
bool ckaid_eq_nss(const ckaid_t *l, const SECItem *r);

ckaid_t ckaid_from_secitem(const SECItem *const nss_ckaid);
SECItem same_ckaid_as_secitem(const ckaid_t *ciaid);

#endif
