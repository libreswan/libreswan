/* CRL fetch queue, for libreswan
 *
 * Copyright (C) 2018 Andrew Cagney
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

#ifndef CRL_QUEUE
#define CRL_QUEUE

#include <stdbool.h>

#include <secitem.h>

#include "chunk.h"
#include "shunk.h"
#include "realtime.h"
#include "lswlog.h"

struct crl_fetch_request;

void submit_crl_fetch_request(asn1_t issuer_dn, struct logger *logger);
void submit_crl_fetch_requests(struct crl_fetch_request **requests, struct logger *logger);

void add_crl_fetch_request(asn1_t issuer_dn, shunk_t url/*could be empty*/,
			   struct crl_fetch_request **requests,
			   struct logger *logger);

typedef bool (fetch_crl_fn)(chunk_t issuer, const char *url, struct logger *logger);
void process_crl_fetch_requests(fetch_crl_fn *fetch_crl, struct logger *logger);

void free_crl_queue(void);
void list_crl_fetch_requests(struct show *s, bool utc);

#endif
