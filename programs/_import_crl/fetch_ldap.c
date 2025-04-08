/* Dynamic fetching of X.509 CRLs, for libreswan
 *
 * Copyright (C) 2015 Matt Rogers <mrogers@libreswan.org>
 * Copyright (C) 2002 Stephane Laroche <stephane.laroche@colubris.com>
 * Copyright (C) 2002-2004 Andreas Steffen, Zuercher Hochschule Winterthur
 * Copyright (C) 2003-2008 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2018-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2019 D. Hugh Redelmeier <hugh@mimosa.com>
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
 *
 */

#define LDAP_DEPRECATED 1
#include <ldap.h>		/* dnf openldap-devel */

#include "import_crl.h"

#include "err.h"
#include "lswlog.h"

/*
 * parses the result returned by an ldap query
 */
static err_t parse_ldap_result(LDAP *ldap, LDAPMessage *result, chunk_t *blob,
			       struct verbose verbose)
{
	err_t ugh = NULL;

	LDAPMessage *entry = ldap_first_entry(ldap, result);

	if (entry != NULL) {
		BerElement *ber = NULL;
		char *attr = ldap_first_attribute(ldap, entry, &ber);

		if (attr != NULL) {
			struct berval **values = ldap_get_values_len(ldap,
								     entry,
								     attr);

			if (values != NULL) {
				if (values[0] != NULL) {
					*blob = clone_bytes_as_chunk(
						values[0]->bv_val,
						values[0]->bv_len,
						"ldap blob");
					if (values[1] != NULL)
						vlog("warning: more than one value was fetched from LDAP URL");
				} else {
					ugh = "no values in attribute";
				}
				ldap_value_free_len(values);
			} else {
				ugh = ldap_err2string(
					ldap_result2error(ldap, entry, 0));
			}
			ldap_memfree(attr);
		} else {
			ugh = ldap_err2string(
				ldap_result2error(ldap, entry, 0));
		}
		ber_free(ber, 0);
	} else {
		ugh = ldap_err2string(ldap_result2error(ldap, result, 0));
	}
	return ugh;
}

/*
 * fetches a binary blob from an ldap url
 */
err_t fetch_ldap(const char *url, time_t timeout, chunk_t *blob, struct verbose verbose)
{
	LDAPURLDesc *lurl;
	err_t ugh = NULL;
	int rc;

	vdbg("trying LDAP URL '%s'", url);
	verbose.level++;

	rc = ldap_url_parse(url, &lurl);

	if (rc == LDAP_SUCCESS) {
		LDAP *ldap = ldap_init(lurl->lud_host, lurl->lud_port);

		if (ldap != NULL) {
			struct timeval ldap_timeout = {
				.tv_sec  = timeout,
			};
			const int ldap_version = LDAP_VERSION3;
			ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION,
					&ldap_version);
			ldap_set_option(ldap, LDAP_OPT_NETWORK_TIMEOUT,
					&ldap_timeout);

			int msgid = ldap_simple_bind(ldap, NULL, NULL);

			/* XXX: LDAP_TIMEOUT can't be const!?! */
			LDAPMessage *result;
			rc = ldap_result(ldap, msgid, 1, &ldap_timeout, &result);

			switch (rc) {
			case -1:
				ldap_msgfree(result);
				return "ldap_simple_bind error";

			case 0:
				ldap_msgfree(result);
				return "ldap_simple_bind timeout";

			case LDAP_RES_BIND:
				ldap_msgfree(result);
				ldap_timeout = (struct timeval) {
					.tv_sec = timeout,
				};

				rc = ldap_search_st(ldap, lurl->lud_dn,
						    lurl->lud_scope,
						    lurl->lud_filter,
						    lurl->lud_attrs,
						    0, &ldap_timeout, &result);

				if (rc == LDAP_SUCCESS) {
					ugh = parse_ldap_result(ldap,
								result,
								blob,
								verbose);
					ldap_msgfree(result);
				} else {
					ugh = ldap_err2string(rc);
				}
				break;

			default:
				/* ??? should we ldap_msgfree(result);? */
				ugh = ldap_err2string(rc);
			}
			ldap_unbind_s(ldap);
		} else {
			ugh = "ldap init";
		}
		ldap_free_urldesc(lurl);
	} else {
		ugh = ldap_err2string(rc);
	}
	return ugh;
}
