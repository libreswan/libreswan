/* Implement policy groups-style control files (aka "foodgroups")
 * Copyright (C) 2002  D. Hugh Redelmeier.
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <limits.h> /* PATH_MAX */
#include <errno.h>

#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"        /* needs id.h */
#include "foodgroups.h"
#include "kernel.h"             /* needs connections.h */
#include "lswconf.h"
#include "lex.h"
#include "log.h"
#include "whack.h"
#include "ip_info.h"
#include "ip_selector.h"
#include "orient.h"

/* Groups is a list of connections that are policy groups.
 * The list is updated as group connections are added and deleted.
 */

struct fg_groups {
	struct fg_groups *next;
	struct connection *connection;
};

static struct fg_groups *groups = NULL;

/* Targets is a list of pairs: subnet and its policy group.
 * This list is bulk-updated on whack --listen and
 * incrementally updated when group connections are deleted.
 *
 * It is ordered by source subnet, and if those are equal, then target subnet.
 * A subnet is compared by comparing the network, and if those are equal,
 * comparing the mask.
 */

struct fg_targets {
	struct fg_targets *next;
	struct fg_groups *group;
	ip_selector subnet;
	uint8_t proto;
	uint16_t sport;
	uint16_t dport;
	char *name; /* name of instance of group conn */
};

static struct fg_targets *targets = NULL;

/* subnetcmp compares the two ip_subnet values a and b.
 * It returns -1, 0, or +1 if a is, respectively,
 * less than, equal to, or greater than b.
 */
static int subnetcmp(const ip_selector a, const ip_selector b)
{
	int r;

	ip_address neta = selector_prefix(a);
	ip_address maska = selector_prefix_mask(a);
	ip_address netb = selector_prefix(b);
	ip_address maskb = selector_prefix_mask(b);
	r = addrcmp(&neta, &netb);
	if (r == 0)
		r = addrcmp(&maska, &maskb);
	return r;
}

static void read_foodgroup(struct file_lex_position *oflp, struct fg_groups *g,
			   struct fg_targets **new_targets)
{
	const char *fgn = g->connection->name;
	const ip_selector *lsn = &g->connection->spd.this.client;
	const struct lsw_conf_options *oco = lsw_init_options();
	char *fg_path = alloc_printf("%s/%s", oco->policies_dir, fgn); /* must free */

	struct file_lex_position *flp;
	if (!lexopen(&flp, fg_path, true, oflp)) {
		char cwd[PATH_MAX];
		dbg("no group file \"%s\" (pwd:%s)", fg_path, getcwd(cwd, sizeof(cwd)));
		pfreeany(fg_path);
		return;
	}
	pfreeany(fg_path);

	llog(RC_LOG, flp->logger, "loading group \"%s\"", flp->filename);
	while (flp->bdry == B_record) {

		/* force advance to first token */
		flp->bdry = B_none;     /* eat the Record Boundary */
		/* get real first token */
		if (!shift(flp)) {
			/* blank line or comment */
			continue;
		}

		/* address or address/mask */
		ip_selector sn;
		if (strchr(flp->tok, '/') == NULL) {
			/* no /, so treat as /32 or V6 equivalent */
			ip_address t;
			err_t err = ttoaddress_num(shunk1(flp->tok), NULL, &t);
			if (err != NULL) {
				llog(RC_LOG_SERIOUS, flp->logger,
					    "ignored, '%s' is not an address: %s",
					    flp->tok, err);
				flushline(flp, NULL/*shh*/);
				continue;
			}
			sn = selector_from_address(t);
		} else {
			const struct ip_info *afi = strchr(flp->tok, ':') == NULL ? &ipv4_info : &ipv6_info;
			ip_subnet snn;
			err_t err = ttosubnet(shunk1(flp->tok), afi, 'x', &snn, flp->logger);
			if (err != NULL) {
				llog(RC_LOG_SERIOUS, flp->logger,
					    "ignored, '%s' is not a subnet: %s",
					    flp->tok, err);
				flushline(flp, NULL/*shh*/);
				continue;
			}
			sn = selector_from_subnet(snn);
		}

		const struct ip_info *type = selector_type(&sn);
		if (type == NULL) {
			llog(RC_LOG_SERIOUS, flp->logger,
				    "ignored, unsupported Address Family \"%s\"",
				    flp->tok);
			flushline(flp, NULL/*shh*/);
			continue;
		}

		unsigned proto = 0;
		unsigned sport = 0;
		unsigned dport = 0;

		/* check for: [protocol sport dport] */
		if (shift(flp)) {
			err_t err;
			/* protocol */
			err = ttoipproto(flp->tok, &proto);
			if (err != NULL) {
				llog(RC_LOG_SERIOUS, flp->logger,
					    "protocol '%s' invalid: %s",
					    flp->tok, err);
				break;
			}
			if (proto == 0 || proto == IPPROTO_ESP || proto == IPPROTO_AH) {
				llog(RC_LOG_SERIOUS, flp->logger,
					    "invalid protocol '%s' - mistakenly defined to be 0 or %u(esp) or %u(ah)",
					    flp->tok, IPPROTO_ESP, IPPROTO_AH);
				break;
			}
			/* source port */
			if (!shift(flp)) {
				llog(RC_LOG_SERIOUS, flp->logger,
					    "missing source_port: either only specify CIDR, or specify CIDR protocol source_port dest_port");
				break;
			}
			err = ttoport(flp->tok, &sport);
			if (err != NULL) {
				llog(RC_LOG_SERIOUS, flp->logger,
					    "source port '%s' invalid: %s",
					    flp->tok, err);
				break;
			}
			/* dest port */
			if (!shift(flp)) {
				llog(RC_LOG_SERIOUS, flp->logger,
					    "missing dest_port: either only specify CIDR, or specify CIDR protocol source_port dest_port");
				break;
			}
			err = ttoport(flp->tok, &dport);
			if (err != NULL) {
				llog(RC_LOG_SERIOUS, flp->logger,
					    "destination port '%s' invalid: %s",
					    flp->tok, err);
				break;
			}
			/* more stuff? */
			if (shift(flp)) {
				llog(RC_LOG_SERIOUS, flp->logger,
					    "garbage '%s' at end of line: either only specify CIDR, or specify CIDR protocol source_port dest_port",
					    flp->tok);
				break;
			}
		}

		pexpect(flp->bdry == B_record || flp->bdry == B_file);

		/* Find where new entry ought to go in new_targets. */
		struct fg_targets **pp;
		int r;

		for (pp = new_targets;;
		     pp = &(*pp)->next) {
			if (*pp == NULL) {
				r = -1; /* end of list is infinite */
				break;
			}
			r = subnetcmp(*lsn, (*pp)->group->connection->spd.this.client);
			if (r == 0) {
				r = subnetcmp(sn, (*pp)->subnet);
			}
			if (r != 0)
				break;

			if (proto == (*pp)->proto &&
			    sport == (*pp)->sport &&
			    dport == (*pp)->dport) {
				break;
			}
		}

		if (r == 0) {
			subnet_buf source;
			subnet_buf dest;
			llog(RC_LOG_SERIOUS, flp->logger,
				    "subnet \"%s\", proto %d, sport %d dport %d, source %s, already \"%s\"",
				    str_selector_subnet(&sn, &dest),
				    proto, sport, dport,
				    str_selector_subnet(lsn, &source),
				    (*pp)->group->connection->name);
		} else {
			struct fg_targets *f = alloc_thing(struct fg_targets,
							   "fg_target");
			f->next = *pp;
			f->group = g;
			f->subnet = sn;
			f->proto = proto;
			f->sport = sport;
			f->dport = dport;
			f->name = NULL; /* filled in below */
			*pp = f;
		}
	}
	if (flp->bdry != B_file) {
		llog(RC_LOG_SERIOUS, flp->logger, "rest of file ignored");
	}
	lexclose(&flp);
}

static void pfree_target(struct fg_targets **target)
{
	pfreeany((*target)->name);
	pfree((*target));
	*target = NULL;
}

void load_groups(struct logger *logger)
{
	struct fg_targets *new_targets = NULL;

	/* for each group, add config file targets into new_targets */
	for (struct fg_groups *g = groups; g != NULL; g = g->next) {
		if (oriented(*g->connection)) {
			struct file_lex_position flp = {
				.logger = logger,
			};
			read_foodgroup(&flp, g, &new_targets);
		}
	}

	if (DBGP(DBG_BASE)) {
		/* dump old food groups */
		DBG_log("old food groups:");
		for (struct fg_targets *t = targets; t != NULL; t = t->next) {
			selector_buf asource;
			selector_buf atarget;
			DBG_log("  %s->%s %d sport %d dport %d %s",
				str_selector(&t->group->connection->spd.this.client, &asource),
				str_selector(&t->subnet, &atarget),
				t->proto, t->sport, t->dport,
				t->group->connection->name);
		}
		/* dump new food groups */
		DBG_log("new food groups:");
		for (struct fg_targets *t = new_targets; t != NULL; t = t->next) {
			selector_buf asource;
			selector_buf atarget;
			DBG_log("  %s->%s %d sport %d dport %d %s",
				str_selector(&t->group->connection->spd.this.client, &asource),
				str_selector(&t->subnet, &atarget),
				t->proto, t->sport, t->dport,
				t->group->connection->name);
		}
	}

	/*
	 * determine and deal with differences between targets and
	 * new_targets.  Structured like a merge of old into new.
	 */
	{
		struct fg_targets **opp = &targets;
		struct fg_targets **npp = &new_targets;

		while ((*opp) != NULL || (*npp) != NULL) {
			struct fg_targets *op = *opp;
			struct fg_targets *np = *npp;

			/* select next: -1:old; 0:merge; +1:new? */
			int r = 0;
			if (op == NULL) {
				r = 1; /* no more old; next is new */
			}
			if (np == NULL) {
				r = -1; /* no more new; next is old */
			}
			if (r == 0)
				r = subnetcmp(op->group->connection->spd.this.client,
					      np->group->connection->spd.this.client);
			if (r == 0)
				r = subnetcmp(op->subnet, np->subnet);
			if (r == 0)
				r = op->proto - np->proto;
			if (r == 0)
				r = op->sport - np->sport;
			if (r == 0)
				r = op->dport - np->dport;

			if (r == 0 && op->group == np->group) {
				/* unchanged -- steal name & skip over */
				passert(np->name == NULL);
				np->name = op->name;
				op->name = NULL;
				/* free old; advance new */
				*opp = op->next;
				pfree_target(&op);
				npp = &np->next;
			} else {
				/* note: r>=0 || r<= 0: following cases overlap! */
				if (r <= 0) {
					remove_group_instance(op->group->connection,
							      op->name);
					/* free old */
					*opp = op->next;
					pfree_target(&op);
				}
				if (r >= 0) {
					struct connection *g = np->group->connection;
					/* XXX: something better? */
					close_any(&g->logger->global_whackfd);
					g->logger->global_whackfd = dup_any(logger->global_whackfd);
					struct connection *ng = add_group_instance(g, &np->subnet, np->proto,
										   np->sport, np->dport);
					/* XXX: something better? */
					close_any(&g->logger->global_whackfd);
					if (ng != NULL) {
						passert(np->name == NULL);
						np->name = clone_str(ng->name, "group instance name");
						/* advance new */
						npp = &np->next;
					} else {
						/* XXX: is this really a pexpect()? */
						dbg("add group instance failed");
						/* free new; advance new */
						*npp = np->next;
						pfree_target(&np);
					}
				}
			}
		}

		/* update: new_targets replaces targets */
		passert(targets == NULL);
		targets = new_targets;
	}
}

void add_group(struct connection *c)
{
	struct fg_groups *g = alloc_thing(struct fg_groups, "policy group");

	g->next = groups;
	groups = g;

	g->connection = c;
}

static struct fg_groups *find_group(const struct connection *c)
{
	struct fg_groups *g;

	for (g = groups; g != NULL && g->connection != c; g = g->next)
		;
	return g;
}

void route_group(struct connection *c)
{
	/* it makes no sense to route a connection that is ISAKMP-only */
	if (!NEVER_NEGOTIATE(c->policy) && !HAS_IPSEC_POLICY(c->policy)) {
		llog(RC_ROUTE, c->logger,
		     "cannot route an ISAKMP-only group connection");
	} else {
		struct fg_groups *g = find_group(c);
		struct fg_targets *t;

		passert(g != NULL);
		g->connection->policy |= POLICY_GROUTED;
		for (t = targets; t != NULL; t = t->next) {
			if (t->group == g) {
				struct connection *ci = conn_by_name(t->name, false/*!strict*/);

				if (ci != NULL) {
					/*
					 * XXX: why whack only?
					 * Shouldn't this leave a
					 * breadcrumb in the log file?
					 */
					if (!trap_connection(ci))
						llog(WHACK_STREAM|RC_ROUTE, c->logger,
						     "could not route");
				}
			}
		}
	}
}

void unroute_group(struct connection *c)
{
	struct fg_groups *g = find_group(c);
	struct fg_targets *t;

	passert(g != NULL);
	g->connection->policy &= ~POLICY_GROUTED;
	for (t = targets; t != NULL; t = t->next) {
		if (t->group == g) {
			struct connection *ci = conn_by_name(t->name, false/*!strict*/);

			if (ci != NULL) {
				unroute_connection(ci);
			}
		}
	}
}

void delete_group(const struct connection *c)
{
	/*
	 * find and remove from groups
	 */
	struct fg_groups *g = NULL;
	for (struct fg_groups **pp = &groups; *pp != NULL; pp = &(*pp)->next) {
		if ((*pp)->connection == c) {
			g = *pp;
			*pp = g->next;
			break;
		}
	}

	/*
	 * find and remove from targets
	 */
	if (pexpect(g != NULL)) {
		struct fg_targets **pp = &targets;
		while (*pp != NULL) {
			struct fg_targets *t = *pp;
			if (t->group == g) {
				/* remove *PP but advance first */
				*pp = t->next;
				remove_group_instance(t->group->connection,
						      t->name);
				pfree_target(&t);
				/* pp is ready for next iteration */
			} else {
				/* advance PP */
				pp = &t->next;
			}
		}
		pfree(g);
	}
}
