/*
 * NSS boilerplate stuff, for libreswan.
 *
 * Copyright (C) 2016, Andrew Cagney <cagney@gnu.org>
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

#ifndef _LSWCKAID_H_
#define _LSWCKAID_H_

/*
 * For rationale behind *_t? Blame chunk_t.
 */
typedef struct {
	SECItem *nss;
} ckaid_t;

const char *ckaid_starts_with(ckaid_t ckaid, const char *start);
char *ckaid_as_string(ckaid_t ckaid);
err_t form_ckaid_rsa(chunk_t modulus, ckaid_t *ckaid);
err_t form_ckaid_nss(const SECItem *const nss_ckaid, ckaid_t *ckaid);
void freeanyckaid(ckaid_t *ckaid);
void DBG_log_ckaid(const char *prefix, ckaid_t ckaid);

#endif
