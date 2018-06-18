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

static bool table_entry(const struct cavp_entry *entries, const char *opt, const char *param)
{
	const struct cavp_entry *entry = cavp_entry_by_opt(entries, opt);
	if (entry != NULL) {
		entry->op(entry, param);
		return true;
	} else {
		return false;
	}
}

bool acvp_option(const struct cavp *cavp, const char *opt, const char *param)
{
	/* try the config table */
	if (table_entry(cavp->config, opt, param)) {
		return true;
	}
	/* try the data table */
	if (table_entry(cavp->data, opt, param)) {
		return true;
	}
	/* map PRF option onto config */
	if (strcasecmp(opt, ACVP_PRF_OPTION) == 0) {
		/* boldly assume PARAM matches a config option */
		const struct cavp_entry *entry = cavp_entry_by_key(cavp->config, param);
		if (entry == NULL) {
			return false;
		}
		entry->op(entry, NULL);
		return true;
	}
	/*
	 * STRONGSWAN compat magic.  Delete?
	 */
	if (/* compat */ strcasecmp(opt, "hash") == 0 ||
	    /* compat */ strcasecmp(opt, "h") == 0) {
		static const struct acvp_prf acvp_prfs[] = {
			{ "2", &ike_alg_prf_sha1, },
			{ "5", &ike_alg_prf_sha2_256, },
			{ "6", &ike_alg_prf_sha2_384, },
			{ "7", &ike_alg_prf_sha2_512, },
			{ .prf = NULL, },
		};
		const struct prf_desc *prf = NULL;
		/* map number to PRF? */
		for (const struct acvp_prf *p = acvp_prfs; p->prf != NULL; p++) {
			if (strcmp(p->name, param) == 0) {
				prf = p->prf;
				break;
			}
		}
		if (prf == NULL) {
			return false;
		}
		/* by name */
		for (const struct cavp_entry *entry = cavp->config; entry->key != NULL; entry++) {
			if (entry->prf == prf) {
				entry->op(entry, param);
				return true;
			}
		}
		fprintf(stderr, "-prf option invalid in this context\n");
		return false;
	}
	/* else unknown */
	return false;
}
