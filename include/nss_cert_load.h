/*
 * NSS certificate loading routines for libreswan, the ipsec daemon
 *
 * Copyright (C) 2015 Matt Rogers <mrogers@libreswan.org>
 * Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2016 Paul Wouters <pwouters@redhat.com>
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

#ifndef _NSS_CERT_LOAD_H
#define _NSS_CERT_LOAD_H

#include "ckaid.h"
#include "secrets.h"

CERTCertificate *get_cert_by_nickname_from_nss(const char *nickname, const struct logger *logger);
CERTCertificate *get_cert_by_ckaid_from_nss(const ckaid_t *ckaid, const struct logger *logger);

#endif /* _NSS_CERT_LOAD_H */
