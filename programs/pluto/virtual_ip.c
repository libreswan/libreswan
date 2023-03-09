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

#include "defs.h"
#include "log.h"
#include "connections.h"
#include "virtual_ip.h"
#include "nat_traversal.h"		/* for nat_traversal_enabled */
#include "refcnt.h"
#include "ip_info.h"
#include "show.h"

#define F_VIRTUAL_NO		1	/* %no (subnet must be host/32) */
#define F_VIRTUAL_PRIVATE	2	/* %priv (list held in private_net_{incl,excl} */
#define F_VIRTUAL_ALL		4	/* %all [only for testing] */
#define F_VIRTUAL_HOST		8	/* vhost (vnet has no representation) */

struct virtual_ip {
	refcnt_t refcnt;
	unsigned short flags;	/* union of F_VIRTUAL_* */
	unsigned short n_net;
	ip_subnet net[0 /*n_net*/];	/* 0-length array is a GCC extension */
};

/*
 * subnets to include and to exclude as virtual-private
 *
 * From from ipsec.conf's config setup's virtual-private= )
 */

static ip_subnet *private_net_incl = NULL;	/* [private_net_incl_len] */
static int private_net_incl_len = 0;

static ip_subnet *private_net_excl = NULL;	/* [private_net_excl_len] */
static int private_net_excl_len = 0;

/*
 * Read a subnet (IPv4/IPv6)
 * inclusion form: [%v4:]x.x.x.x/y or [%v6]:xxxxxxxxx/yy
 * exclusion form: [%v4:]!x.x.x.x/y or [%v6:]!xxxxxxxxx/yy
 *
 * @param src String in format (see above)
 * @param len Length of src string
 * @param dst out: IP Subnet Destination
 * @param isincl out: bool; inclusive form or not (required if ! is to be accepted)
 * @return err_t NULL if the format string is valid.
 */

static err_t read_subnet(shunk_t src, ip_subnet *dst, bool *isincl)
{
	shunk_t cursor = src;

	/*
	 * Note: len might not be sufficient for each of these strncmp
	 * calls but that's OK because the character in src[len] is
	 * either ',' or '\0' so the result will be a non-match,
	 * safely and correctly.
	 */
	const struct ip_info *afi;
	if (shunk_strcaseeat(&cursor, "%v4:")) {
		afi = &ipv4_info;
	} else if (shunk_strcaseeat(&cursor, "%v6:")) {
		afi = &ipv6_info;
	} else {
		afi = NULL;	/* "guess from src" */
	}

	/*
	 * Only allow exclude when ISINCL!=NULL.
	 */
	bool incl = !shunk_strcaseeat(&cursor, "!");
	if (isincl != NULL) {
		*isincl = incl;
	} else if (!incl) {
		return "! invalid";
	}

	ip_address nonzero_host;
	err_t e = ttosubnet_num(cursor, afi, dst, &nonzero_host);
	if (e != NULL) {
		return e;
	}
	if (nonzero_host.is_set) {
		return "subnet contains non-zero host identifier";
	}
	return NULL;
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
void init_virtual_ip(const char *private_list,
		     struct logger *logger)
{
	free_virtual_ip();

	/** Count **/

	int bad = 0;	/* count of errors */

	for (const char *str = private_list; str != NULL; ) {
		const char *next = strchr(str, ',');

		if (next == NULL)
			next = str + strlen(str);

		bool incl = false;
		ip_subnet sub;	/* sink: value never used */

		if (read_subnet(shunk2(str, next - str), &sub, &incl) == NULL/*no-err*/) {
			if (incl)
				private_net_incl_len++;
			else
				private_net_excl_len++;
		} else {
			bad++;
		}
		str = *next != '\0' ? next + 1 : NULL;
	}

	if (bad == 0) {
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

		int i_incl = 0;
		int i_excl = 0;
		for (const char *str = private_list; str != NULL; ) {
			const char *next = strchr(str, ',');

			if (next == NULL)
				next = str + strlen(str);

			bool incl = false;
			ip_subnet sub;
			if (read_subnet(shunk2(str, next - str),
					&sub, &incl) == NULL/*no-err*/) {
				if (incl) {
					private_net_incl[i_incl++] = sub;
				} else {
					private_net_excl[i_excl++] = sub;
				}
			}
			str = *next != '\0' ? next + 1 : NULL;
		}
	} else {
		llog(RC_LOG_SERIOUS, logger,
			    "%d bad entries in virtual-private - none loaded", bad);
		pfreeany(private_net_incl);
		private_net_incl = NULL;
	}
}

/*
 * virtual string must be:
 *	{vhost,vnet}:[method [, method]* ]
 *
 * vhost = accept only a host (/32)
 * vnet  = accept any network
 *
 * method:
 *	%no  (means no virtual IP (accept IP of host/32))
 *	%priv  (means accept system-wide private net list)
 *	[%v4:]x  (means accept literal IPv4 subnet x)
 *	[%v6:]x  (means accept literal IPv6 subnet x)
 *	%all  (means accept all IPs [only for testing])
 *
 * examples:
 *	vhost:%priv,%no
 *	vnet:%priv,%v4:192.168.1.0/24
 *
 * @param c Connection Struct
 * @param string (virtual_private= from ipsec.conf)
 * @return virtual_ip
 */

diag_t create_virtual(const char *leftright, const char *string, struct virtual_ip **vip)
{
	passert(string != NULL && string[0] != '\0');

	unsigned short flags = 0;
	const char *str = string;

	if (eat(str, "vhost:")) {
		flags |= F_VIRTUAL_HOST;
	} else if (eat(str, "vnet:")) {
		/* represented in flags by the absence of F_VIRTUAL_HOST */
	} else {
		return diag("virtual %ssubnet=%s invalid, missing \"vhost:\" or \"vnet:\"",
			    leftright, string);
	}

	/*
	 * Pass 1 of 2.
	 *
	 * Parse string filling in flags & count subnets.
	 */

	unsigned n_net = 0;
	const char *first_net = NULL;

	while (*str != '\0') {
		/* point NEXT at ',' or '\0' */
		const char *next = strchr(str, ',');
		if (next == NULL)
			next = str + strlen(str);

		ptrdiff_t len = next - str;
		ip_subnet sub;	/* sink -- value never used */

		if (eat(str, "%no")) {
			flags |= F_VIRTUAL_NO;
		} else if (eat(str, "%priv")) {
			flags |= F_VIRTUAL_PRIVATE;
		} else if (eat(str, "%all")) {
			flags |= F_VIRTUAL_ALL;
		} else {
			/* don't allow ! form */
			err_t e = read_subnet(shunk2(str, len), &sub, NULL);
			if (e != NULL) {
				return diag("virtual %ssubnet=%s invalid, %s",
					    leftright, string, e);
			}
			n_net++;
			if (first_net == NULL)
				first_net = str;
			str += len;
		}
		if (str != next) {
			return diag("virtual %ssubnet=%s invalid, contains trailing garbage '%s'",
				    leftright, string, str);
		}
		/* clang 3.5 thinks that next might be NULL; wrong */
		if (*next == '\0')
			break;
		/* skip comma */
		str = next + 1;
	}

	/*
	 * Pass 2 of 2.
	 *
	 * Allocate struct plus space for the .net[] array (using the
	 * array at end of struct hack).
	 */
	struct virtual_ip *v = refcnt_overalloc(struct virtual_ip,
						/*extra*/(n_net * sizeof(ip_subnet)),
						HERE);

	v->flags = flags;
	v->n_net = n_net;
	if (n_net > 0) {
		passert(first_net != NULL);
		/*
		 * Save subnets in newly allocated struct
		 */
		unsigned i = 0;

		for (const char *str = first_net; str != NULL && *str != '\0'; ) {
			/* point NEXT at ',' or '\0' */
			const char *next = strchr(str, ',');
			if (next == NULL)
				next = str + strlen(str);

			/* don't allow ! form; stumble over %entries */
			ip_subnet sub;
			if (read_subnet(shunk2(str, next - str), &sub, NULL) == NULL/*no-err*/) {
				passert(i < n_net);
				v->net[i++] = sub;
			}
			/* clang 3.5 thinks that next might be NULL; wrong */
			if (*next == '\0')
				break;
			/* skip comma */
			str = next + 1;
		}
		passert(i == n_net);
	}

	*vip = v;
	return NULL;
}

/*
 * is_virtual_end - Do we have a virtual IP on the other end?
 *
 * @param that end structure
 * @return bool True if we do
 */
bool is_virtual_spd_end(const struct spd_end *end)
{
	bool virt = (end->virt != NULL);
	dbg("virt: %s() %s spd=%s config=%s",
	    __func__, bool_str(virt),
	    bool_str(end->virt != NULL),
	    bool_str(end->config->child.virt != NULL));
	pexpect((end->config->child.virt != NULL) >= (end->virt != NULL));
	return virt;
}

/*
 * Does this connection's remote have a Virtual IP?
 *
 * @param c Active Connection struct
 * @return bool True if we do
 */
bool is_virtual_remote(const struct connection *c)
{
	bool virt = false;
	FOR_EACH_ITEM(spd, &c->child.spds) {
		if (spd->remote->virt != NULL) {
			virt = true;
			break;
		}
	}
	ldbg(c->logger, "virt: %s() %s local/remote spd %s/%s; config %s/%s",
	     __func__, bool_str(virt),
	     bool_str(c->spd->local->virt != NULL),
	     bool_str(c->spd->remote->virt != NULL),
	     bool_str(c->local->config->child.virt != NULL),
	     bool_str(c->remote->config->child.virt != NULL));
	pexpect((c->remote->config->child.virt != NULL) >= (virt));
	return virt;
}

/*
 * is_virtual_vhost - is the virt set to a host or a net?
 *
 * @param that end structure
 * @return bool True if we do
 */
bool is_virtual_vhost(const struct spd_end *end)
{
	return is_virtual_spd_end(end) && (end->virt->flags & F_VIRTUAL_HOST) != 0;
}

/*
 * net_in_list - Check if a subnet is in a list
 *
 * @param peer_net IP Subnet to check
 * @param list IP Subnet list to search within
 * @param len # of subnets in list
 * @return bool True if peer_net is in list
 */
static bool net_in_list(const ip_subnet peer_net, const ip_subnet *list,
			int len)
{
	for (int i = 0; i < len; i++)
		if (subnet_in_subnet(peer_net, list[i]))
			return true;

	return false;
}

/*
 * check_virtual_net_allowed -
 * Check if the virtual network the client proposes is acceptable to us
 *
 * @param c Connection structure (active)
 * @param peer_net IP Subnet the peer proposes
 * @param peers_addr Peers IP Address
 * @return err_t NULL if allowed, diagnostic otherwise
 */
err_t check_virtual_net_allowed(const struct connection *c,
				const ip_subnet peer_net,
				const ip_address peers_addr)
{
	ldbg(c->logger, "virt: %s() spd %s/%s; config %s/%s",
	     __func__,
	     bool_str(c->spd->local->virt != NULL),
	     bool_str(c->spd->remote->virt != NULL),
	     bool_str(c->local->config->child.virt != NULL),
	     bool_str(c->remote->config->child.virt != NULL));
	const struct virtual_ip *virt = c->spd->remote->virt;
	if (virt == NULL)
		return NULL;

	if (virt->flags & F_VIRTUAL_HOST && subnet_size(peer_net) != 1) {
		return "only virtual host single IPs are allowed";
	}

	if (private_net_incl == NULL)
		return NULL;

	if (virt->flags & F_VIRTUAL_NO) {
		if (subnet_eq_address(peer_net, peers_addr)) {
			return NULL;
		}
		/* ??? why isn't this case an error? */
	}

	/* last failure; ignored on subsequent success; ??? default is success */
	err_t why = NULL;

	if (virt->flags & F_VIRTUAL_PRIVATE) {
		if (!net_in_list(peer_net, private_net_incl,
				private_net_incl_len)) {
			why = "a private network virtual IP was required, but the proposed IP did not match our list (virtual-private=) since it is in use elsewhere";
		} else if (net_in_list(peer_net, private_net_excl,
				private_net_excl_len)) {
			why = "a private network virtual IP was required, but our list (virtual-private=) excludes their IP (e.g. %v4!...) since it is in use elsewhere";
		} else {
			return NULL;	/* success */
		}
	}

	if (virt->n_net != 0) {
		if (net_in_list(peer_net, virt->net, virt->n_net))
			return NULL;	/* success */

		why = "a specific network IP was required, but the proposed IP did not match our list (subnet=vhost:list)";
	}

	if (virt->flags & F_VIRTUAL_ALL) {
		/* %all must only be used for testing - log it */
		llog(RC_LOG_SERIOUS, c->logger,
		     "WARNING: v%s:%%all must only be used for testing",
		     (virt->flags & F_VIRTUAL_HOST) ? "host" : "net");

		return NULL;	/* success */
	}

	/* ??? if why is NULL, this seems to be success-by-default.  Is that intended? */
	return why;
}

static void show_virtual_private_kind(struct show *s,
				      const char *kind,
				      const ip_subnet *private_net,
				      int private_net_len)
{
	if (private_net != NULL) {
		char all[256] = "";  /* arbitrary limit */
		struct jambuf buf = ARRAY_AS_JAMBUF(all);
		int i;
		for (i = 0; i < private_net_len; i++) {
			jampos_t start = jambuf_get_pos(&buf);
			if (i > 0) {
				jam(&buf, ", ");
			}
			jam_subnet(&buf, &private_net[i]);
			if (!jambuf_ok(&buf)) {
				/* oops overflowed, discard last */
				jambuf_set_pos(&buf, &start);
				break;
			}
		}
		show_comment(s, "- %s subnet%s: %s",
			kind, i == 1? "" : "s", all);
		if (i < private_net_len) {
			show_comment(s, "showing only %d of %d!",
				     i, private_net_len);
		}
	}
}

void show_virtual_private(struct show *s)
{
	if (nat_traversal_enabled) {
		show_comment(s, "virtual-private (%%priv):");
		show_virtual_private_kind(s, "allowed",
					  private_net_incl,
					  private_net_incl_len);
		show_virtual_private_kind(s, "excluded",
					  private_net_excl,
					  private_net_excl_len);
	}
}

struct virtual_ip *virtual_ip_addref_where(struct virtual_ip *vip, where_t where)
{
	return addref_where(vip, where);
}

void virtual_ip_delref_where(struct virtual_ip **vipp, where_t where)
{
	const struct logger *logger = &global_logger;
	struct virtual_ip *vip = delref_where(vipp, logger, where);
	if (vip != NULL) {
		pfree(vip);
	}
}
