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

#ifndef X509_CRL
#define X509_CRL

#include <stdbool.h>

#include "chunk.h"
#include "shunk.h"
#include "realtime.h"
#include "asn1.h"

struct logger;
struct crl_fetch_request;
struct show;

void submit_crl_fetch_request(asn1_t issuer_dn, struct logger *logger);

void list_crl_fetch_requests(struct show *s, bool utc);
void fetch_x509_crls(struct show *s);

bool init_x509_crl_queue(struct logger *logger);
void shutdown_x509_crl_queue(struct logger *logger);

struct x509_crl_config {
	deltatime_t timeout;
	char *curl_iface;
	bool strict;
	deltatime_t check_interval;
};

extern struct x509_crl_config x509_crl;

#endif
