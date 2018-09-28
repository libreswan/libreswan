/* Libreswan Virtual IP Management
 * Copyright (C) 2002 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2004 Xelerance Corporation
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2011 Wolfgang Nothdurft <wolfgang@linogate.de>
 * Copyright (C) 2012 Bram <bram-bcrafjna-erqzvar@spam.wizbit.be>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 Paul Wouters <pwouters@redhat.com>
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

#include <libreswan.h>

#include <stdlib.h>
#include <string.h>

#include "sysdep.h"
#include "constants.h"
#include "lswlog.h"

#include "defs.h"
#include "log.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"
#include "whack.h"
#include "nat_traversal.h"
#include "virtual.h"	/* needs connections.h */

#define F_VIRTUAL_NO          1
#define F_VIRTUAL_PRIVATE     2
#define F_VIRTUAL_ALL         4
#define F_VIRTUAL_HOST        8

struct virtual_t {
	unsigned short flags;
	unsigned short n_net;
	ip_subnet net[0];
};

/* subnets to include and to exclude as virtual-private */

static ip_subnet *private_net_incl = NULL;	/* [private_net_incl_len] */
static int private_net_incl_len = 0;

static ip_subnet *private_net_excl = NULL;	/* [private_net_excl_len] */
static int private_net_excl_len = 0;

/*
 * Read a subnet (IPv4/IPv6)
 * inclusion form: %v4:x.x.x.x/y or %v6:xxxxxxxxx/yy
 * exclusion form: %v4:!x.x.x.x/y or %v6:!xxxxxxxxx/yy
 *
 * @param src String in format (see above)
 * @param len Length of src string
 * @param dst out: IP Subnet * Destination
 * @param dstexcl out: IP Subnet * for ! form (required if ! is to be accepted)
 * @param isincl out: bool * inclusive form or not
 * @return bool If the format string is valid.
 */
static bool read_subnet(const char *src, size_t len,
			ip_subnet *dst,
			ip_subnet *dstexcl,
			bool *isincl)
{
	bool incl = TRUE;
	int af = AF_UNSPEC;	/* AF_UNSPEC means "guess from form" */
	int pl = 0;
	err_t ugh;

	/*
	 * Note: len might not be sufficient for each of these strncmp calls
	 * but that's OK because the character in src[len] is either ',' or '\0'
	 * so the result will be a non-match, safely and correctly.
	 */
	if (startswith(src, "%v4:")) {
		pl = 4;
		af = AF_INET;
	} else if (startswith(src, "%v6:")) {
		pl = 4;
		af = AF_INET6;
	}

	if (src[pl] == '!') {
		pl++;
		if (dstexcl == NULL)
			return FALSE;
		incl = FALSE;
	}

	src += pl;
	len -= pl;

	ugh = ttosubnet(src, len, af, incl ? dst : dstexcl);
	if (ugh != NULL) {
		loglog(RC_LOG_SERIOUS, "virtual-private entry is not a proper subnet: %s", ugh);
		return FALSE;
	}
	if (isincl != NULL)
		*isincl = incl;
	return TRUE;
}

void free_virtual_ip(void)
{
	/* These might be NULL if empty in ipsec.conf */
	private_net_incl_len = 0;
	pfreeany(private_net_incl);

	private_net_excl_len = 0;
	pfreeany(private_net_excl);
}

/*
 * Initialize Virtual IP Support
 *
 * @param private_list String (contents of virtual-private= from ipsec.conf)
 */
void init_virtual_ip(const char *private_list)
{
	const char *str;
	int ign = 0, i_incl, i_excl;

	free_virtual_ip();

	/** Count **/
	str = private_list;
	while (str != NULL) {
		const char *next = strchr(str, ',');
		bool incl;
		ip_subnet sub;	/* sink: value never used */

		if (next == NULL)
			next = str + strlen(str);
		if (read_subnet(str, next - str, &sub, &sub, &incl)) {
			if (incl)
				private_net_incl_len++;
			else
				private_net_excl_len++;
		} else {
			ign++;
		}
		str = *next != '\0' ? next + 1 : NULL;
	}

	if (ign == 0) {
		/** Allocate **/
		if (private_net_incl_len != 0) {
			private_net_incl = (ip_subnet *)alloc_bytes(
				(private_net_incl_len * sizeof(ip_subnet)),
				"private_net_incl subnets");
		}
		if (private_net_excl_len != 0) {
			private_net_excl = (ip_subnet *)alloc_bytes(
				(private_net_excl_len * sizeof(ip_subnet)),
				"private_net_excl subnets");
		}

		/** Fill **/
		str = private_list;
		i_incl = 0;
		i_excl = 0;
		while (str != NULL) {
			const char *next = strchr(str, ',');
			bool incl;

			if (next == NULL)
				next = str + strlen(str);
			if (read_subnet(str, next - str,
					 &(private_net_incl[i_incl]),
					 &(private_net_excl[i_excl]),
					 &incl)) {
				if (incl)
					i_incl++;
				else
					i_excl++;
			}
			str = *next != '\0' ? next + 1 : NULL;
		}
	} else {
		loglog(RC_LOG_SERIOUS,
		       "%d bad entries in virtual-private - none loaded", ign);
	}
}

/*
 * virtual string must be :
 * {vhost,vnet}:[%method]*
 *
 * vhost = accept only a host (/32)
 * vnet  = accept any network
 *
 * %no   = no virtual IP (accept public IP)
 * %priv = accept system-wide private net list
 * %v4:x = accept ipv4 in list 'x'
 * %v6:x = accept ipv6 in list 'x'
 * %all  = accept all ips                             [only for testing]
 *
 * ex: vhost:%no,%priv,%v4:192.168.1.0/24
 *
 * @param c Connection Struct
 * @param string (virtual_private= from ipsec.conf)
 * @return virtual_t
 */
struct virtual_t *create_virtual(const struct connection *c, const char *string)
{
	unsigned short flags = 0,
		n_net = 0;
	const char *str = string,
		*first_net = NULL;
	struct virtual_t *v;

	if (string == NULL || string[0] == '\0')
		return NULL;

	if (eat(str, "vhost:")) {
		flags |= F_VIRTUAL_HOST;
	} else if (eat(str, "vnet:")) {
		/* ??? do nothing? */
	} else {
		libreswan_log("virtual string \"%s\" is missing prefix - virtual selection is disabled for connection '%s'",
			string, c->name);
		return NULL;
	}

	/*
	 * Parse string: fill flags & count subnets
	 */
	while (*str != '\0') {
		ip_subnet sub;	/* sink -- value never used */
		ptrdiff_t len;
		const char *next = strchr(str, ',');

		if (next == NULL)
			next = str + strlen(str);
		len = next - str;
		if (eat(str, "%no")) {
			flags |= F_VIRTUAL_NO;
		} else if (eat(str, "%priv")) {
			flags |= F_VIRTUAL_PRIVATE;
		} else if (eat(str, "%all")) {
			flags |= F_VIRTUAL_ALL;
		} else if (read_subnet(str, len, &sub, NULL, NULL)) {
			n_net++;
			if (first_net == NULL)
				first_net = str;
			str += len;
		} else {
			/* nothing matched: force failure */
			str = NULL;
		}
		if (str != next) {
			libreswan_log("invalid virtual string \"%s\" - virtual selection is disabled for connection '%s'",
				string, c->name);
			return NULL;
		}
		/* clang 3.5 thinks that next might be NULL; wrong */
		if (*next == '\0')
			break;
		str = next + 1;
	}

	v = (struct virtual_t *)alloc_bytes(
		sizeof(struct virtual_t) + (n_net * sizeof(ip_subnet)),
		"virtual description");

	v->flags = flags;
	v->n_net = n_net;
	if (n_net != 0 && first_net != NULL) {
		/*
		 * Save subnets in newly allocated struct
		 */
		int i = 0;

		for (str = first_net; str != NULL && *str != '\0'; ) {
			const char *next = strchr(str, ',');

			if (next == NULL)
				next = str + strlen(str);
			if (read_subnet(str, next - str, &(v->net[i]), NULL,
					 NULL))
				i++;
			str = *next ? next + 1 : NULL;
		}
	}

	return v;
}

/*
 * is_virtual_end - Do we have a virtual IP on the other end?
 *
 * @param that end structure
 * @return bool True if we do
 */
bool is_virtual_end(const struct end *that)
{
	return that->virt != NULL;
}

/*
 * Does this connection have a virtual IP ?
 *
 * @param c Active Connection struct
 * @return bool True if we do
 */
bool is_virtual_connection(const struct connection *c)
{
	const struct spd_route *sr;

	for (sr = &c->spd; sr != NULL; sr = sr->spd_next)
		if (sr->that.virt != NULL)
			return TRUE;

	return FALSE;
}

/*
 * Does this spd have a virtual IP ?
 *
 * @param c Active Connection struct
 * @return bool True if we do
 */
bool is_virtual_sr(const struct spd_route *sr)
{
	return is_virtual_end(&sr->that);
}

/*
 * is_virtual_vhost - is the virt set to a host or a net?
 *
 * @param that end structure
 * @return bool True if we do
 */
bool is_virtual_vhost(const struct end *that)
{
	return that->virt != NULL && (that->virt->flags & F_VIRTUAL_HOST) != 0;
}

/*
 * net_in_list - Check if a subnet is in a list
 *
 * @param peer_net IP Subnet to check
 * @param list IP Subnet list to search within
 * @param len # of subnets in list
 * @return bool True if peer_net is in list
 */
static bool net_in_list(const ip_subnet *peer_net, const ip_subnet *list,
			int len)
{
	int i;

	for (i = 0; i < len; i++)
		if (subnetinsubnet(peer_net, &(list[i])))
			return TRUE;

	return FALSE;
}

/*
 * check_virtual_net_allowed -
 * Check if the virtual network the client proposes is acceptable to us
 *
 * @param c Connection structure (active)
 * @param peer_net IP Subnet the peer proposes
 * @param his_addr Peers IP Address
 * @return bool True if allowed
 */
err_t check_virtual_net_allowed(const struct connection *c,
			     const ip_subnet *peer_net,
			     const ip_address *his_addr)
{
	const struct virtual_t *virt = c->spd.that.virt;
	err_t why = NULL;

	if (virt == NULL)
		return NULL;

	if (virt->flags & F_VIRTUAL_HOST) {
		if (!subnetishost(peer_net)) {
			return "only virtual host IPs are allowed";
		}
	}

	if (virt->flags & F_VIRTUAL_NO) {
		if (subnetishost(peer_net) && addrinsubnet(his_addr, peer_net))
			return NULL;
	}

	if (virt->flags & F_VIRTUAL_PRIVATE) {
		if (net_in_list(peer_net, private_net_incl,
				private_net_incl_len) &&
		    !net_in_list(peer_net, private_net_excl,
				private_net_excl_len))
			return NULL;

		why = "a private network virtual IP was required, but the proposed IP did not match our list (virtual-private=), or our list excludes their IP (e.g. %v4!...) since it is in use elsewhere";
	}

	if (virt->n_net != 0) {
		/* ??? if why is already set, is this behaviour correct? */
		if (net_in_list(peer_net, virt->net, virt->n_net))
			return NULL;

		why = "a specific network IP was required, but the proposed IP did not match our list (subnet=vhost:list)";
	}

	if (virt->flags & F_VIRTUAL_ALL) {
		/* ??? if why is already set, is this behaviour correct? */
		/* %all must only be used for testing - log it */
		loglog(RC_LOG_SERIOUS, "Warning - v%s:%%all must only be used for testing",
			(virt->flags & F_VIRTUAL_HOST) ? "host" : "net");
		return NULL;
	}

	return why;
}

static void show_virtual_private_kind(const char *kind,
	const ip_subnet *private_net,
	int private_net_len)
{
	if (private_net != NULL) {
		bool trunc = FALSE;
		char all[256] = "";  /* arbitrary limit */
		int i;

		for (i = 0; i < private_net_len; i++) {
			char sn[SUBNETTOT_BUF];
			const char *sep = *all == '\0'? "" : ", ";

			subnettot(&private_net[i], 0, sn, sizeof(sn));
			if (strlen(all) + strlen(sep) +  strlen(sn) <
					sizeof(all)) {
				strcat(all, sep);	/* safe: see allocation above */
				strcat(all, sn);	/* safe: see allocation above */
			} else {
				trunc = TRUE;
				break;
			}
		}
		whack_log(RC_COMMENT, "- %s subnet%s: %s",
			kind, i == 1? "" : "s", all);
		if (trunc)
			whack_log(RC_COMMENT, "showing only %d of %d!",
				i, private_net_len);
	}
}

void show_virtual_private(void)
{
	if (nat_traversal_enabled) {
		whack_log(RC_COMMENT, "virtual-private (%%priv):");
		show_virtual_private_kind("allowed", private_net_incl, private_net_incl_len);
		show_virtual_private_kind("excluded", private_net_excl, private_net_excl_len);
		whack_log(RC_COMMENT, " ");     /* spacer */
	}
}
