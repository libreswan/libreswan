/* autoall mark/sweep, for libreswan
 *
 * Copyright (C) 2026 James Raphael Tiovalen <jamestiotio@meta.com>
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
 */

#include "whack_autoall.h"

#include "show.h"
#include "log.h"
#include "connections.h"
#include "terminate.h"
#include "visit_connection.h"
#include "whack.h"
#include "extract.h"
#include "hash_table.h"
#include "resolve_helper.h"

static struct config_digest compute_config_digest(const struct whack_message *wm)
{
	return (struct config_digest) {
		.valid = true,
		.hash = hash_bytes(wm->string, wm->str_size, zero_hash),
	};
}

static bool config_digest_equal(const struct config_digest *a,
				const struct config_digest *b)
{
	return (a->valid && b->valid &&
		a->hash.hash == b->hash.hash);
}

static bool route_addr_resolved_on_add(const struct route_addr *addr)
{
	switch (addr->type) {

	case KH_IPHOSTNAME:
	case KH_DEFAULTROUTE:
	case KH_IFACE:
		return true;

	case KH_IPADDR:
	case KH_ANY:
	case KH_OPPO:
	case KH_OPPOGROUP:
	case KH_GROUP:
	case KH_DIRECT:
	case KH_NOTSET:
		return false;
	}

	bad_case(addr->type);
}

static bool host_end_resolved_on_add(const struct host_end_config *end)
{
	return (route_addr_resolved_on_add(&end->host) ||
		route_addr_resolved_on_add(&end->nexthop));
}

static bool connection_host_resolved_on_add(const struct connection *c)
{
	return (host_end_resolved_on_add(&c->local->config->host) ||
		host_end_resolved_on_add(&c->remote->config->host));
}

static bool route_addr_unchanged(const struct route_addr *config,
				 const ip_address resolved,
				 const ip_address current)
{
	if (!route_addr_resolved_on_add(config)) {
		return true;
	}
	return (address_is_specified(resolved) &&
		address_eq_address(resolved, current));
}

static bool connection_addrs_unchanged(const struct connection *c,
				       const struct host_addrs *resolved)
{
	FOR_EACH_THING(lr, LEFT_END, RIGHT_END) {
		const struct host_end_config *config = &c->config->end[lr].host;
		const struct host_end *host = &c->end[lr].host;
		if (!route_addr_unchanged(&config->host,
					  resolved->end[lr].host.addr,
					  host->addr) ||
		    !route_addr_unchanged(&config->nexthop,
					  resolved->end[lr].nexthop.addr,
					  host->nexthop)) {
			return false;
		}
	}
	return true;
}

static void autoall_probed(struct connection *c,
			   const struct host_addrs *resolved,
			   bool background UNUSED,
			   struct verbose verbose)
{
	if (!connection_addrs_unchanged(c, resolved)) {
		ldbg(verbose.logger, "autoall: %s address changed", c->name);
		c->autoall_address_changed = true;
	}
	whack_detach(c, verbose.logger);
}

struct autoall_match_context {
	struct config_digest new_digest;
	unsigned nr_roots;
	unsigned nr_expected;
	bool changed;
};

static unsigned autoall_match(const struct whack_message *m UNUSED,
			      struct show *s UNUSED,
			      struct connection *c,
			      struct connection_visitor_context *context)
{
	struct autoall_match_context *ctx =
		(struct autoall_match_context *)context;
	if (c->clonedfrom != NULL) {
		return 0;
	}
	ctx->nr_roots++;
	if (c->autoall_address_changed ||
	    !config_digest_equal(&c->config_digest, &ctx->new_digest)) {
		ctx->changed = true;
		return 1;
	}
	if (ctx->nr_expected == 0) {
		ctx->nr_expected = c->config_digest.nr_roots;
	} else if (ctx->nr_expected != c->config_digest.nr_roots) {
		ctx->changed = true;
	}
	return 1;
}

static unsigned autoall_keep(const struct whack_message *m UNUSED,
			     struct show *s,
			     struct connection *c,
			     struct connection_visitor_context *context UNUSED)
{
	if (c->clonedfrom != NULL) {
		return 0;
	}
	c->autoall_stale = false;
	struct logger *logger = show_logger(s);
	whack_attach(c, logger);
	llog(RC_LOG, c->logger, "unchanged");
	whack_detach(c, logger);
	return 1;
}

bool whack_autoall_unchanged(const struct whack_message *wm, struct show *s)
{
	struct autoall_match_context ctx = {
		.new_digest = compute_config_digest(wm),
	};
	whack_connection_roots(wm, s, OLD2NEW, autoall_match,
			       (struct connection_visitor_context *)&ctx,
			       (struct each) {
				       .log_unknown_name = false,
			       });
	if (ctx.nr_roots == 0 || ctx.changed) {
		return false;
	}
	if (ctx.nr_roots != ctx.nr_expected) {
		ldbg(show_logger(s), "autoall: %s has %u of %u connections",
		     wm->name, ctx.nr_roots, ctx.nr_expected);
		return false;
	}
	whack_connection_roots(wm, s, OLD2NEW, autoall_keep, NULL,
			       (struct each) {
				       .log_unknown_name = false,
			       });
	return true;
}

struct autoall_save_context {
	struct config_digest new_digest;
};

static unsigned autoall_count(const struct whack_message *m UNUSED,
			      struct show *s UNUSED,
			      struct connection *c,
			      struct connection_visitor_context *context)
{
	struct autoall_save_context *ctx =
		(struct autoall_save_context *)context;
	if (c->clonedfrom != NULL) {
		return 0;
	}
	ctx->new_digest.nr_roots++;
	return 1;
}

static unsigned autoall_save(const struct whack_message *m UNUSED,
			     struct show *s UNUSED,
			     struct connection *c,
			     struct connection_visitor_context *context)
{
	struct autoall_save_context *ctx =
		(struct autoall_save_context *)context;
	if (c->clonedfrom != NULL) {
		return 0;
	}
	c->config_digest = ctx->new_digest;
	return 1;
}

void whack_autoall_save(const struct whack_message *wm, struct show *s)
{
	struct autoall_save_context ctx = {
		.new_digest = compute_config_digest(wm),
	};
	whack_connection_roots(wm, s, OLD2NEW, autoall_count,
			       (struct connection_visitor_context *)&ctx,
			       (struct each) {
				       .log_unknown_name = false,
			       });
	if (ctx.new_digest.nr_roots == 0) {
		return;
	}
	whack_connection_roots(wm, s, OLD2NEW, autoall_save,
			       (struct connection_visitor_context *)&ctx,
			       (struct each) {
				       .log_unknown_name = false,
			       });
}

void whack_autoall_start(const struct whack_message *wm UNUSED, struct show *s)
{
	struct logger *logger = show_logger(s);

	ldbg(logger, "marking root connections as stale for autoall sweep");

	struct connection_filter cq = {
		.search = {
			.order = OLD2NEW,
			.verbose.logger = logger,
			.where = HERE,
		},
	};
	while (next_connection(&cq)) {
		if (cq.c->clonedfrom != NULL) {
			continue;
		}
		cq.c->autoall_stale = true;
		cq.c->autoall_address_changed = false;
		if (!connection_host_resolved_on_add(cq.c)) {
			continue;
		}
		whack_attach(cq.c, logger);
		request_resolve_probe(cq.c, autoall_probed, logger);
	}
}

void whack_autoall_stop(const struct whack_message *wm UNUSED, struct show *s)
{
	struct logger *logger = show_logger(s);

	ldbg(logger, "sweeping stale connections after autoall");

	struct connection_filter cq = {
		.search = {
			.order = OLD2NEW,
			.verbose.logger = logger,
			.where = HERE,
		},
	};
	while (all_connections(&cq)) {
		if (cq.c->clonedfrom != NULL) {
			continue;
		}
		if (!cq.c->autoall_stale) {
			continue;
		}
		whack_attach(cq.c, logger);
		llog(RC_LOG, cq.c->logger, "swept");
		connection_addref(cq.c, logger);
		terminate_and_delete_connections(cq.c, logger, HERE);
		connection_delref(&cq.c, logger);
	}
}
