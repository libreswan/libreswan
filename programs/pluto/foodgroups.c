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

#include <errno.h>

/* Food group config files are found in directory fg_path */

static char *fg_path = NULL;
static size_t fg_path_space = 0;

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
	ip_subnet subnet;
	uint8_t proto;
	uint16_t sport;
	uint16_t dport;
	char *name; /* name of instance of group conn */
};

static struct fg_targets *targets = NULL;

static struct fg_targets *new_targets;


/* subnetcmp compares the two ip_subnet values a and b.
 * It returns -1, 0, or +1 if a is, respectively,
 * less than, equal to, or greater than b.
 */
static int subnetcmp(const ip_subnet *a, const ip_subnet *b)
{
	int r;

	ip_address neta = subnet_prefix(a);
	ip_address maska = subnet_mask(a);
	ip_address netb = subnet_prefix(b);
	ip_address maskb = subnet_mask(b);
	r = addrcmp(&neta, &netb);
	if (r == 0)
		r = addrcmp(&maska, &maskb);
	return r;
}

static void read_foodgroup(struct fg_groups *g, struct fd *whackfd)
{
	const char *fgn = g->connection->name;
	const ip_subnet *lsn = &g->connection->spd.this.client;
	const struct lsw_conf_options *oco = lsw_init_options();
	size_t plen = strlen(oco->policies_dir) + 2 + strlen(fgn) + 1;
	struct file_lex_position flp_space;

	if (plen > fg_path_space) {
		pfreeany(fg_path);
		fg_path_space = plen + 10;
		fg_path = alloc_bytes(fg_path_space, "policy group path");
	}

	/* danger, global buffer */
	snprintf(fg_path, fg_path_space, "%s/%s", oco->policies_dir, fgn);
	if (!lexopen(&flp_space, fg_path, TRUE)) {
		char cwd[PATH_MAX];
		dbg("no group file \"%s\" (pwd:%s)", fg_path, getcwd(cwd, sizeof(cwd)));
		return;
	}

	log_global(RC_LOG, whackfd, "loading group \"%s\"", fg_path);
	while (flp->bdry == B_record) {

		/* force advance to first token */
		flp->bdry = B_none;     /* eat the Record Boundary */
		(void)shift();          /* get real first token */
		if (flp->bdry != B_none) {
			continue;
		}

		/* address or address/mask */
		ip_subnet sn;
		if (strchr(flp->tok, '/') == NULL) {
			/* no /, so treat as /32 or V6 equivalent */
			ip_address t;
			err_t err = numeric_to_address(shunk1(flp->tok), NULL, &t);
			if (err != NULL) {
				log_global(RC_LOG_SERIOUS, whackfd,
					   "\"%s\" line %d ignored, '%s' is not an address: %s",
					   flp->filename, flp->lino, flp->tok, err);
				flushline(NULL/*shh*/);
				continue;
			}
			sn = subnet_from_address(&t);
		} else {
			const struct ip_info *afi = strchr(flp->tok, ':') == NULL ? &ipv4_info : &ipv6_info;
			err_t err = ttosubnet(flp->tok, 0, afi->af, 'x', &sn);
			if (err != NULL) {
				log_global(RC_LOG_SERIOUS, whackfd,
					   "\"%s\" line %d ignored, '%s' is not a subnet: %s",
					   flp->filename, flp->lino, flp->tok, err);
				flushline(NULL/*shh*/);
				continue;
			}
		}

		const struct ip_info *type = subnet_type(&sn);
		if (type == NULL) {
			log_global(RC_LOG_SERIOUS, whackfd,
				   "\"%s\" line %d ignored, unsupported Address Family \"%s\"",
				   flp->filename, flp->lino, flp->tok);
			flushline(NULL);
			continue;
		}

		unsigned proto = 0;
		unsigned sport = 0;
		unsigned dport = 0;
		int line = flp->lino;

		/* check for: [protocol sport dport] */
		(void)shift();
		if (flp->bdry == B_none) {
			err_t err;
			/* protocol */
			err = ttoipproto(flp->tok, &proto);
			if (err != NULL) {
				log_global(RC_LOG_SERIOUS, whackfd,
					   "\"%s\" line %d: protocol '%s' invalid: %s",
					   flp->filename, line, flp->tok, err);
				break;
			}
			if (proto == 0 || proto == IPPROTO_ESP || proto == IPPROTO_AH) {
				log_global(RC_LOG_SERIOUS, whackfd,
					   "\"%s\" line %d: invalid protocol '%s' - mistakenly defined to be 0 or %u(esp) or %u(ah)",
					   flp->filename, line, flp->tok, IPPROTO_ESP, IPPROTO_AH);
				break;
			}
			(void)shift();
			/* source port */
			if (flp->bdry != B_none) {
				log_global(RC_LOG_SERIOUS, whackfd,
					   "\"%s\" line %d: missing source_port: either only specify CIDR, or specify CIDR protocol source_port dest_port",
					   flp->filename, line);
				break;
			}
			err = ttoport(flp->tok, &sport);
			if (err != NULL) {
				log_global(RC_LOG_SERIOUS, whackfd,
					   "\"%s\" line %d: source port '%s' invalid: %s",
					   flp->filename, line, flp->tok, err);
				break;
			}
			(void)shift();
			/* dest port */
			if (flp->bdry != B_none) {
				log_global(RC_LOG_SERIOUS, whackfd,
					   "\"%s\" line %d: missing dest_port: either only specify CIDR, or specify CIDR protocol source_port dest_port",
					   flp->filename, line);
				break;
			}
			err = ttoport(flp->tok, &dport);
			if (err != NULL) {
				log_global(RC_LOG_SERIOUS, whackfd,
					   "\"%s\" line %d: destination port '%s' invalid: %s",
					   flp->filename, line, flp->tok, err);
				break;
			}
			shift();
			/* more stuff? */
			if (flp->bdry == B_none) {
				log_global(RC_LOG_SERIOUS, whackfd,
					   "\"%s\" line %d: garbage '%s' at end of line: either only specify CIDR, or specify CIDR protocol source_port dest_port",
					   flp->filename, line, flp->tok);
				break;
			}
		}

		pexpect(flp->bdry == B_record || flp->bdry == B_file);

		/* Find where new entry ought to go in new_targets. */
		struct fg_targets **pp;
		int r;

		for (pp = &new_targets;;
		     pp = &(*pp)->next) {
			if (*pp == NULL) {
				r = -1; /* end of list is infinite */
				break;
			}
			r = subnetcmp(lsn,
				      &(*pp)->group->connection->spd.this.client);
			if (r == 0) {
				r = subnetcmp(&sn, &(*pp)->subnet);
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
			log_global(RC_LOG_SERIOUS, whackfd,
				   "\"%s\" line %d: subnet \"%s\", proto %d, sport %d dport %d, source %s, already \"%s\"",
				   flp->filename,
				   flp->lino,
				   str_subnet(&sn, &dest),
				   proto, sport, dport,
				   str_subnet(lsn, &source),
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
			f->name = NULL;
			*pp = f;
		}
	}
	if (flp->bdry != B_file) {
		log_global(RC_LOG_SERIOUS, whackfd,
			   "\"%s\" line %d: rest of file ignored",
			   flp->filename, flp->lino);
	}
	lexclose();
}

static void free_targets(void)
{
	while (targets != NULL) {
		struct fg_targets *t = targets;

		targets = t->next;
		pfreeany(t->name);
		pfree(t);
	}
}

void load_groups(struct fd *whackfd)
{
	passert(new_targets == NULL);

	/* for each group, add config file targets into new_targets */
	{
		struct fg_groups *g;

		for (g = groups; g != NULL; g = g->next)
			if (oriented(*g->connection))
				read_foodgroup(g, whackfd);
	}

	/* dump new_targets */
	if (DBG_BASE) {
		for (struct fg_targets *t = new_targets; t != NULL; t = t->next) {
			selector_buf asource;
			selector_buf atarget;
			DBG_log("%s->%s %d sport %d dport %d %s",
				str_selector(&t->group->connection->spd.this.client, &asource),
				str_selector(&t->subnet, &atarget),
				t->proto, t->sport, t->dport,
				t->group->connection->name);
		}
	    }

	/* determine and deal with differences between targets and new_targets.
	 * structured like a merge.
	 */
	{
		struct fg_targets *op = targets,
		*np = new_targets;

		while (op != NULL && np != NULL) {
			int r = subnetcmp(
				&op->group->connection->spd.this.client,
				&np->group->connection->spd.this.client);

			if (r == 0)
				r = subnetcmp(&op->subnet, &np->subnet);
			if (r == 0)
				r = op->proto - np->proto;
			if (r == 0)
				r = op->sport - np->sport;
			if (r == 0)
				r = op->dport - np->dport;

			if (r == 0 && op->group == np->group) {
				/* unchanged -- steal name & skip over */
				np->name = op->name;
				op->name = NULL;
				op = op->next;
				np = np->next;
			} else {
				/* note: following cases overlap! */
				if (r <= 0) {
					remove_group_instance(
						op->group->connection,
						op->name);
					op = op->next;
				}
				if (r >= 0) {
					np->name = add_group_instance(
						whackfd,
						np->group->connection,
						&np->subnet, np->proto,
						np->sport, np->dport);
					np = np->next;
				}
			}
		}
		for (; op != NULL; op = op->next)
			remove_group_instance(op->group->connection, op->name);

		for (; np != NULL; np = np->next) {
			np->name = add_group_instance(whackfd,
						      np->group->connection,
						      &np->subnet, np->proto,
						      np->sport, np->dport);
		}

		/* update: new_targets replaces targets */
		free_targets();
		targets = new_targets;
		new_targets = NULL;
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

void route_group(struct fd *whackfd, struct connection *c)
{
	/* it makes no sense to route a connection that is ISAKMP-only */
	if (!NEVER_NEGOTIATE(c->policy) && !HAS_IPSEC_POLICY(c->policy)) {
		log_connection(RC_ROUTE, whackfd, c,
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
					struct connection *old = push_cur_connection(ci); /* for trap_connection() */
					if (!trap_connection(ci, whackfd))
						log_connection(WHACK_STREAM|RC_ROUTE, whackfd, c,
							       "could not route");
					pop_cur_connection(old);
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
				set_cur_connection(ci);
				unroute_connection(ci);
				set_cur_connection(c);
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
				pfree(t);
				/* pp is ready for next iteration */
			} else {
				/* advance PP */
				pp = &t->next;
			}
		}
		pfree(g);
	}
}
