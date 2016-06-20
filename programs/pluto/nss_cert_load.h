/*
 * NSS certificate loading routines for libreswan, the ipsec daemon
 *
 * Copyright (C) 2015 Matt Rogers <mrogers@libreswan.org>
 * Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
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

#ifndef _NSS_CERT_LOAD_H
#define _NSS_CERT_LOAD_H

#include <libreswan.h>
extern bool load_coded_file(const char *filename, const char *type, chunk_t *blob);
extern CERTCertificate *get_cert_by_nickname_from_nss(const char *nickname);
extern CERTCertificate *get_cert_by_ckaid_from_nss(const char *ckaid);

#endif /* _NSS_CERT_LOAD_H */
