/*
 * NSS boilerplate stuff, for libreswan.
 *
 * Copyright (C) 2016, Andrew Cagney <cagney@gnu.org>
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
#include <secitem.h>		/* for SECItem */

#include "err.h"
#include "chunk.h"

/*
 * For rationale behind *_t? Blame chunk_t.
 */
typedef struct {
	SECItem *nss;
} ckaid_t;

bool ckaid_starts_with(ckaid_t ckaid, const char *start);
char *ckaid_as_string(ckaid_t ckaid);
err_t form_ckaid_rsa(chunk_t modulus, ckaid_t *ckaid);
err_t form_ckaid_ecdsa(chunk_t pub_value, ckaid_t *ckaid);
err_t form_ckaid_nss(const SECItem *const nss_ckaid, ckaid_t *ckaid);
void freeanyckaid(ckaid_t *ckaid);
void DBG_log_ckaid(const char *prefix, ckaid_t ckaid);

#endif
