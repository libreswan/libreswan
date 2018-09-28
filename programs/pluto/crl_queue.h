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

#include <secitem.h>

#include "chunk.h"
#include "realtime.h"
#include "lswlog.h"

#include "x509.h"		/* for generalName_t */

struct crl_fetch_request {
	realtime_t request_time;
	SECItem *issuer_dn;
	generalName_t *dps;
	struct crl_fetch_request *next;
};

struct crl_fetch_request *crl_fetch_request(SECItem *issuer, generalName_t *end_dp,
					    struct crl_fetch_request *next);
void free_crl_fetch_requests(struct crl_fetch_request **request);

void add_crl_fetch_requests(struct crl_fetch_request *requests);
struct crl_fetch_request *get_crl_fetch_requests(void);

#endif
