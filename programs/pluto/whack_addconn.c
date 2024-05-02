/* <<ipsec add ...>> aka addconn, for libreswan
 *
 * Copyright (C) 2023 Andrew Cagney
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

#include "lswlog.h"	/* for RC_FATAL */
#include "whack.h"

#include "whack_addconn.h"
#include "show.h"
#include "connections.h"
#include "whack_delete.h"

PRINTF_LIKE(3)
static void llog_add_connection_failed(const struct whack_message *wm,
				       struct logger *logger,
				       const char *fmt, ...)
{
	LLOG_JAMBUF(RC_FATAL, logger, buf) {
		jam(buf, "\"%s\": failed to add connection: ", wm->name);
		va_list ap;
		va_start(ap, fmt);
		jam_va_list(buf, fmt, ap);
		va_end(ap);
	}
}

/*
 * When false, should also check error.
 */

struct subnets {
	const char *leftright;
	const char *name;
	unsigned start;
	/* results */
	ip_subnets subnets;
};

/*
 * The first combination is the current leftsubnet/rightsubnet value,
 * and then each iteration of rightsubnets, and then each permutation
 * of leftsubnets X rightsubnets.
 *
 * If both subnet= is set and subnets=, then it is as if an extra
 * element of subnets= has been added, so subnets= for only one side
 * will do the right thing, as will some combinations of also=
 */

static bool parse_subnets(struct subnets *sn,
			  const struct whack_message *wm,
			  const struct whack_end *end,
			  struct logger *logger)
{
	*sn = (struct subnets) {
		.name = wm->name,
		.leftright = end->leftright,
	};

	unsigned len = 0;

	ip_subnet subnet = unset_subnet;
	if (end->subnet != NULL) {
		ip_address nonzero_host;
		err_t e = ttosubnet_num(shunk1(end->subnet), /*afi*/NULL,
					&subnet, &nonzero_host);
		if (e != NULL) {
			llog_add_connection_failed(wm, logger, 
						   "%ssubnet=%s invalid, %s",
						   end->leftright, end->subnet, e);
			return false;
		}
		if (nonzero_host.is_set) {
			llog_add_connection_failed(wm, logger,
						   "%ssubnet=%s contains non-zero host identifier",
						   end->leftright, end->subnet);
			return false;
		}
		/* make space */
		len += 1;
	}

	ip_subnets subnets = {0};
	if (end->subnets != NULL) {
		diag_t d = ttosubnets_num(shunk1(end->subnets), /*afi*/NULL, &subnets);
		if (d != NULL) {
			llog_add_connection_failed(wm, logger,
						   "%ssubnets=%s invalid, %s",
						   end->leftright, end->subnets,
						   str_diag(d));
			pfree_diag(&d);
			return false;
		}
		/* make space */
		len += subnets.len;
	}

	/*
	 * Merge lists.
	 */
	sn->start = (subnet.is_set ? 0 :
		     subnets.len == 0 ? 0 :
		     1);
	sn->subnets.len = len;
	sn->subnets.list = alloc_things(ip_subnet, len, "subnets");
	unsigned pos = 0;
	if (subnet.is_set) {
		sn->subnets.list[pos++] = subnet;
	}
	FOR_EACH_ITEM(s, &subnets) {
		sn->subnets.list[pos++] = *s;
	}
	pfreeany(subnets.list);
	return true;
}

/*
 * Determine the next_subnet.
 *
 * When subnet= and subnets= were both NULL, set .subnet to NULL so
 * add_connection() will fill in valid, presumably from host.
 */

static const struct ip_info *next_subnet(struct whack_end *end,
					 const ip_subnets *subnets,
					 unsigned i)
{
	if (subnets->len > 0) {
		ip_subnet subnet = subnets->list[i];
		subnet_buf b;
		str_subnet(&subnet, &b);
		/* freed by free_wam() */
		end->subnet = clone_str(str_subnet(&subnet, &b), "subnet name");
		return subnet_info(subnet);
	}

	/*
	 * There's no subnet, clear things so that add_connection()
	 * will fill it in using the host address.
	 */
	end->subnet = NULL;
	return NULL; /* unknown */
}

static void free_wam(struct whack_message *wam)
{
	pfreeany(wam->name);
	pfreeany(wam->left.subnet);
	pfreeany(wam->right.subnet);
}

/*
 * permutate_conns - generate all combinations of subnets={}
 *
 * @operation - the function to apply to each generated conn
 * @cfg       - the base configuration
 * @conn      - the conn to permute
 *
 * This function goes through the set of N x M combinations of the subnets
 * defined in conn's "subnets=" declarations and synthesizes conns with
 * the proper left/right subnet settings, and then calls operation(),
 * (which is usually add/delete/route/etc.)
 *
 */

static void permutate_connection_subnets(const struct whack_message *wm,
					 const struct subnets *left,
					 const struct subnets *right,
					 struct logger *logger)
{
	/*
	 * The first combination is the current leftsubnet/rightsubnet
	 * value, and then each iteration of rightsubnets, and then
	 * each permutation of leftsubnets X rightsubnets.
	 *
	 * Both loops execute at least once.  When an end has
	 * subnet=NULL and subnets=NULL, the value unset_subnet is
	 * used and .subnet is set to NULL so that add_connection()
	 * will fill it in using the host address.
	 */

	for (unsigned left_i = 0;
	     left_i == 0 || left_i < left->subnets.len;
	     left_i++) {

		for (unsigned right_i = 0;
		     right_i == 0 || right_i < right->subnets.len;
		     right_i++) {

			/*
			 * whack message --- we can borrow all
			 * pointers, since this is a temporary copy.
			 */
			struct whack_message wam = *wm;
			wam.connalias = wm->name;

			/*
			 * Leave .subnets values alone.
			 *
			 * This way, add_connection() can see the
			 * original value that the subnet was taken
			 * from and log accordingly.
			 *
			 * For instance addresspool vs subnets should
			 * complain about subnets and not subnet.
			 */
#if 0
			wam.left.subnets = NULL;
			wam.right.subnets = NULL;
#endif

			/*
			 * Build a new connection name by appending
			 * /<left-nr>x<right-nr>.
			 *
			 * When the connection also contained subnet=,
			 * that has NR==0.
			 *
			 * MUST FREE
			 */
			wam.name = alloc_printf("%s/%ux%u",
						wm->name,
						left->start+left_i,
						right->start+right_i);

			/*
			 * Either .subnet is !.is_set or is valid.
			 * {left,right}_afi can be NULL.
			 */
			const struct ip_info *left_afi = next_subnet(&wam.left, &left->subnets, left_i);
			const struct ip_info *right_afi = next_subnet(&wam.right, &right->subnets, right_i);

			if (left_afi == right_afi ||
			    left_afi == NULL ||
			    right_afi == NULL) {
				diag_t d = add_connection(&wam, logger);
				if (d != NULL) {
					llog_add_connection_failed(&wam, logger, "%s", str_diag(d));
					pfree_diag(&d);
					free_wam(&wam);
					return;
				}
			} else {
				PEXPECT(logger, (wam.left.subnet != NULL &&
						 wam.right.subnet != NULL));
				llog(RC_LOG, logger,
				     "\"%s\": warning: skipping mismatched leftsubnets=%s rightsubnets=%s",
				     wm->name, wam.left.subnet, wam.right.subnet);
			}

			free_wam(&wam);
		}
	}

}

static void add_connections(const struct whack_message *wm, struct logger *logger)
{
	/*
	 * Reject {left,right}subnets=... combined with
	 * {left,right}subnet=a,b
	 */
	bool have_subnets = false;
	FOR_EACH_THING(subnets, &wm->left, &wm->right) {
		if (subnets->subnets == NULL) {
			continue;
		}
		have_subnets = true;
		/* have subnets=... */
		FOR_EACH_THING(subnet, &wm->left, &wm->right) {
			if (subnet->subnet == NULL) {
				continue;
			}
			if (strchr(subnet->subnet, ',') == NULL) {
				continue;
			}
			/* have subnets=.. and subnet=a,b... */
			llog_add_connection_failed(wm, logger,
						   "multi-selector %ssubnet=\"%s\" combined with %ssubnets=\"%s\"",
						   subnet->leftright, subnet->subnet,
						   subnets->leftright, subnets->subnets);
			return;
		}
	}

	/* basic case, nothing special to synthize! */
	if (!have_subnets) {
		diag_t d = add_connection(wm, logger);
		if (d != NULL) {
			llog_add_connection_failed(wm, logger, "%s", str_diag(d));
			pfree_diag(&d);
		}
		return;
	}

	struct subnets left = {0};
	if (!parse_subnets(&left, wm, &wm->left, logger)) {
		pfreeany(left.subnets.list);
		return;
	}

	struct subnets right = {0};
	if (!parse_subnets(&right, wm, &wm->right, logger)) {
		pfreeany(left.subnets.list);
		pfreeany(right.subnets.list);
		return;
	}

	permutate_connection_subnets(wm, &left, &right, logger);
	pfreeany(left.subnets.list);
	pfreeany(right.subnets.list);
}

void whack_addconn(const struct whack_message *wm, struct show *s)
{
	if (wm->name == NULL) {
		whack_log(RC_FATAL, s,
			  "received command to delete a connection, but did not receive the connection name - ignored");
		return;
	}

	/*
	 * "ipsec add" semantics.
	 *
	 * Any existing connection matching .name is purged before
	 * this connection is added.
	 *
	 * In the case of subnets=, .name is NAME/NxM, and not NAME,
	 * which means this call deletes a specific alias instance and
	 * not all instances.  An earlier delete .name=NAME message
	 * will have purged everything (see <<ipsec>>).
	 */
	whack_delete(wm, s, /*log_unknown_name*/false);

	/*
	 * Confirm above did its job.
	 */
	if (connection_with_name_exists(wm->name)) {
		llog_pexpect(show_logger(s), HERE,
			     "attempt to redefine connection \"%s\"", wm->name);
		return;
	}

	add_connections(wm, show_logger(s));
}
