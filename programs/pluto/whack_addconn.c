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

/*
 * When false, should also check error.
 */

struct subnets {
	const char *leftright;
	const char *name;
	/* keep track */
	const char *subnets;
	int count;
	/* results */
	ip_subnet subnet;
	err_t error;
	char *must_free;
};

static bool next_subnet(struct subnets *sn, struct logger *logger);

/*
 * The first combination is the current leftsubnet/rightsubnet value,
 * and then each iteration of rightsubnets, and then each permutation
 * of leftsubnets X rightsubnets.
 *
 * If both subnet= is set and subnets=, then it is as if an extra
 * element of subnets= has been added, so subnets= for only one side
 * will do the right thing, as will some combinations of also=
 */

static bool first_subnet(struct subnets *sn,
			 const struct whack_message *wm,
			 const struct whack_end *end,
			 struct logger *logger)
{
	char *subnets;
	int count;
	*sn = (struct subnets) {
		.name = wm->name,
		.leftright = end->leftright,
	};
	if (end->subnets != NULL &&
	    end->subnet != NULL) {
		subnets = alloc_printf("%s,%s",
				       end->subnet,
				       end->subnets);
		count = -1; /* becomes 0 below */
	} else if (end->subnets != NULL) {
		subnets = clone_str(end->subnets, "subnets");
		count = 0; /* becomes 1 below */
	} else if (end->subnet != NULL) {
		subnets = clone_str(end->subnet, "subnets");
		count = -1; /* becomes 0 below */
	} else {
		/* neither subnet= subnets= presumably peer has values */
		pexpect(sn->count == 0);
		pexpect(sn->subnets == NULL);
		return true;
	}
	sn->must_free = subnets;
	sn->subnets = subnets;
	sn->count = count;
	/* advances .count to 0(subnet) or 1(subnets) */
	return next_subnet(sn, logger);
}

static bool next_subnet(struct subnets *sn, struct logger *logger)
{
	sn->subnet = unset_subnet; /* always */

	const char *subnets = sn->subnets;
	if (subnets == NULL) {
		/* happens when both subnet= and subnets= */
		return false;
	}

	/* find first non-space item */
	while (*subnets != '\0' && (char_isspace(*subnets) || *subnets == ',')) {
		subnets++;
	}

	/* did we find something? */
	if (*subnets == '\0') {
		return false;	/* no more input */
	}

	/* save start */
	const char *start = subnets;

	/* find end of this item */
	while (*subnets != '\0' && !(char_isspace(*subnets) || *subnets == ',')) {
		subnets++;
	}

	shunk_t subnet = shunk2(start, subnets - start);
	ip_address nonzero_host;
	sn->error = ttosubnet_num(subnet, NULL/*any-AFI*/,
				  &sn->subnet, &nonzero_host);
	if (sn->error != NULL) {
		llog(RC_LOG, logger,
		     "\"%s\": warning: '"PRI_SHUNK"' is not a subnet declaration (%s%s): %s",
		     sn->name,
		     pri_shunk(subnet), sn->leftright,
		     (sn->count == 0 ? "subnet" : "subnets"),
		     sn->error);
		return false;
	}
	if (nonzero_host.is_set) {
		address_buf hb;
		llog(RC_LOG, logger,
		     "\"%s\": warning: zeroing non-zero host identifier %s in '"PRI_SHUNK"' (%s%s)",
		     sn->name, str_address(&nonzero_host, &hb),
		     pri_shunk(subnet),
		     sn->leftright, (sn->count == 0 ? "subnet" : "subnets"));
	}

	/* update pointer ready for next call */
	sn->subnets = subnets;
	sn->count++;
	return true;
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
					 const struct subnets *first_left,
					 const struct subnets *first_right,
					 struct logger *logger)
{
	/*
	 * The first combination is the current leftsubnet/rightsubnet
	 * value, and then each iteration of rightsubnets, and then
	 * each permutation of leftsubnets X rightsubnets.
	 *
	 * If both subnet= is set and subnets=, then it is as if an
	 * extra element of subnets= has been added, so subnets= for
	 * only one side will do the right thing, as will some
	 * combinations of also=
	 */

	struct subnets left = *first_left;
	pexpect(left.count >= 0);
	struct subnets right = *first_right;
	pexpect(right.count >= 0);

	do {
		do {

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
			 */
			char tmpconnname[256];
			snprintf(tmpconnname, sizeof(tmpconnname), "%s/%ux%u",
				 wm->name, left.count, right.count);
			ldbg(logger, "tmpconnname=%s", tmpconnname);
			wam.name = tmpconnname;

			/*
			 * Fix up leftsubnet/rightsubnet
			 * properly, make sure that has_client
			 * is set.
			 *
			 * Danger: LB and RB must be the same scope as
			 * WAM.
			 */
			subnet_buf lb, rb;
			str_subnet(&left.subnet, &lb);
			str_subnet(&right.subnet, &rb);
			wam.left.subnet = (left.subnet.is_set ? lb.buf : NULL);
			wam.right.subnet = (right.subnet.is_set ? rb.buf : NULL);

			/*
			 * Either .subnet is !.is_set or is valid.
			 * {left,right}_afi can be NULL.
			 */
			const struct ip_info *left_afi = subnet_info(left.subnet);
			const struct ip_info *right_afi = subnet_info(right.subnet);
			if (left_afi == right_afi ||
			    left_afi == NULL ||
			    right_afi == NULL) {
				if (!add_connection(&wam, logger)) {
					return;
				}
			} else {
				PASSERT(logger, (wam.left.subnet != NULL &&
						 wam.right.subnet != NULL));
				llog(RC_LOG, logger,
				     "\"%s\": warning: skipping mismatched leftsubnets=%s rightsubnets=%s",
				     wm->name, wam.left.subnet, wam.right.subnet);
			}

			/*
			 * Try to advance right.
			 */
		} while (next_subnet(&right, logger));

		if (right.error != NULL) {
			/* really bad */
			return;
		}

		/*
		 * Right is out so rewind it and advance left.
		 */
		right = *first_right;

	} while (next_subnet(&left, logger));

	if (left.error != NULL) {
		/* really bad */
		return;
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
			llog(RC_FATAL, logger,
			     CONNECTION_ADD_FAILED(wm, "multi-selector %ssubnet=\"%s\" combined with %ssubnets=\"%s\""),
			     subnet->leftright, subnet->subnet,
			     subnets->leftright, subnets->subnets);
			return;
		}
	}

	/* basic case, nothing special to synthize! */
	if (!have_subnets) {
		add_connection(wm, logger);
		return;
	}

	struct subnets first_left = {0};
	if (!first_subnet(&first_left, wm, &wm->left, logger)) {
		/* syntax error; already logged */
		return;
	}

	struct subnets first_right = {0};
	if (!first_subnet(&first_right, wm, &wm->right, logger)) {
		/* syntax error; already logged */
		pfreeany(first_left.must_free);
		return;
	}

	permutate_connection_subnets(wm, &first_left, &first_right, logger);
	pfreeany(first_left.must_free);
	pfreeany(first_right.must_free);
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
