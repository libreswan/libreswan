/* CAVP algorithm, for libreswan
 *
 * Copyright (C) 2018, Andrew Cagney
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

#include <string.h>

#include "lswlog.h"

#include "acvp.h"

#include "cavp.h"
#include "cavp_entry.h"
#include "cavp_ikev2.h"

#include "ike_alg_sha1.h"
#include "ike_alg_sha2.h"

#include "test_buffer.h"
#include "crypt_symkey.h"

struct acvp_prf {
	const char *name;
	const struct prf_desc *prf;
};

static const struct acvp_prf acvp_prfs[] = {
	{ "2", &ike_alg_prf_sha1, },
	{ "5", &ike_alg_prf_sha2_256, },
	{ "6", &ike_alg_prf_sha2_384, },
	{ "7", &ike_alg_prf_sha2_512, },
	{ .prf = NULL, },
};

static bool table_entry(struct cavp_entry *entries, const char *opt, const char *param)
{
	for (struct cavp_entry *entry = entries; entry->key != NULL; entry++) {
		for (unsigned i = 0; i < elemsof(entry->opt); i++) {
			if (entry->opt[i] != NULL && strcasecmp(entry->opt[i], opt) == 0) {
				entry->op(entry, param);
				return true;
			}
		}
	}
	return false;
}

bool acvp_option(struct cavp *cavp, const char *opt, const char *param)
{
	/* try the config table */
	if (table_entry(cavp->config, opt, param)) {
		return true;
	}
	/* try the data table */
	if (table_entry(cavp->data, opt, param)) {
		return true;
	}
	/* try some PRF magic */
	if (strcasecmp(opt, ACVP_PRF_OPTION) == 0 ||
	    /* compat */ strcasecmp(opt, "hash") == 0 ||
	    /* compat */ strcasecmp(opt, "h") == 0) {
		const struct prf_desc *prf = NULL;
		/* map number to PRF? */
		for (const struct acvp_prf *p = acvp_prfs; p->prf != NULL; p++) {
			if (strcmp(p->name, param) == 0) {
				prf = p->prf;
				break;
			}
		}
		/* by name */
		for (struct cavp_entry *entry = cavp->config; entry->key != NULL; entry++) {
			if (entry->prf != NULL) {
				if (entry->prf == prf ||
				    strcasecmp(entry->key, param)) {
					entry->op(entry, param);
					return true;
				}
			}
		}
		fprintf(stderr, "-prf option invalid in this context\n");
		return false;
	}
	/* try some dmklen magic */
	long dkmlen_in_bits = -1;

	if (strcasecmp(opt, ACVP_DKM_OPTION) == 0) {
		dkmlen_in_bits = strtoul(param, NULL, 10);
	}
	if (/* compat */ strcasecmp(opt, "dkmlen") == 0 ||
	    /* compat */ strcmp(opt, "l") == 0) {
		dkmlen_in_bits = strtoul(param, NULL, 10) * 8;
	}
	if (dkmlen_in_bits >= 0) {
		for (struct cavp_entry *entry = cavp->config; entry->key != NULL; entry++) {
			if (strstr(entry->key, "DKM") != NULL) {
				*entry->signed_long =  dkmlen_in_bits;
				return true;
			}
		}
		fprintf(stderr, "-dkmlen option invalid in this context\n");
		return false;
	}
	/* else unknown */
	return false;
}
