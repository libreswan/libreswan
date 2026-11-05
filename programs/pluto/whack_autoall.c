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
#include "hunk.h"

static shunk_t packed_strings(const struct whack_message *wm)
{
	return shunk2(wm->string, wm->str_size);
}

static bool subnets_root_name(const char *name, const char *base)
{
	if (!startswith(name, base)) {
		return false;
	}
	const char *s = name + strlen(base);
	if (*s++ != '/') {
		return false;
	}
	size_t n = strspn(s, "0123456789");
	if (n == 0 || s[n] != 'x') {
		return false;
	}
	s += n + 1;
	size_t m = strspn(s, "0123456789");
	return (m > 0 && s[m] == '\0');
}

static bool autoall_root(const struct whack_message *wm,
			 const struct connection *c)
{
	if (c->clonedfrom != NULL) {
		return false;
	}
	if (streq(c->base_name, wm->name)) {
		return true;
	}
	return (c->config->connalias != NULL &&
		streq(c->config->connalias, wm->name) &&
		subnets_root_name(c->base_name, wm->name));
}

struct autoall_match_context {
	shunk_t strings;
	unsigned nr_roots;
	unsigned nr_expected;
	bool changed;
};

static unsigned autoall_match(const struct whack_message *m,
			      struct show *s UNUSED,
			      struct connection *c,
			      struct connection_visitor_context *context)
{
	struct autoall_match_context *ctx =
		(struct autoall_match_context *)context;
	if (!autoall_root(m, c)) {
		return 0;
	}
	ctx->nr_roots++;
	if (c->autoall_config == NULL ||
	    !hunk_eq(*c->autoall_config, ctx->strings)) {
		ctx->changed = true;
		return 1;
	}
	if (ctx->nr_expected == 0) {
		ctx->nr_expected = c->autoall_nr_roots;
	} else if (ctx->nr_expected != c->autoall_nr_roots) {
		ctx->changed = true;
	}
	return 1;
}

static unsigned autoall_keep(const struct whack_message *m,
			     struct show *s,
			     struct connection *c,
			     struct connection_visitor_context *context UNUSED)
{
	if (!autoall_root(m, c)) {
		return 0;
	}
	c->autoall_stale = false;
	struct logger *logger = show_logger(s);
	whack_attach(c, logger);
	llog(RC_LOG, c->logger, "unchanged");
	whack_detach(c, logger);
	return 1;
}

bool whack_autoall_keep_if_unchanged(const struct whack_message *wm, struct show *s)
{
	struct autoall_match_context ctx = {
		.strings = packed_strings(wm),
	};
	whack_connection_roots(wm, s, /*alias_order*/OLD2NEW, autoall_match,
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
	whack_connection_roots(wm, s, /*alias_order*/OLD2NEW, autoall_keep, NULL,
			       (struct each) {
				       .log_unknown_name = false,
			       });
	return true;
}

struct autoall_save_context {
	struct ro_hunk *copy;
	unsigned nr_roots;
};

static unsigned autoall_count(const struct whack_message *m,
			      struct show *s UNUSED,
			      struct connection *c,
			      struct connection_visitor_context *context)
{
	struct autoall_save_context *ctx =
		(struct autoall_save_context *)context;
	if (!autoall_root(m, c)) {
		return 0;
	}
	ctx->nr_roots++;
	return 1;
}

static unsigned autoall_save(const struct whack_message *m,
			     struct show *s UNUSED,
			     struct connection *c,
			     struct connection_visitor_context *context)
{
	struct autoall_save_context *ctx =
		(struct autoall_save_context *)context;
	if (!autoall_root(m, c)) {
		return 0;
	}
	replace_ro_hunk(&c->autoall_config, ctx->copy, c->logger, HERE);
	c->autoall_nr_roots = ctx->nr_roots;
	return 1;
}

void whack_autoall_save(const struct whack_message *wm, struct show *s)
{
	struct logger *logger = show_logger(s);
	struct autoall_save_context ctx = {0};
	whack_connection_roots(wm, s, /*alias_order*/OLD2NEW, autoall_count,
			       (struct connection_visitor_context *)&ctx,
			       (struct each) {
				       .log_unknown_name = false,
			       });
	if (ctx.nr_roots == 0) {
		return;
	}
	/* One copy shared by every root that this message produced. */
	shunk_t strings = packed_strings(wm);
	ctx.copy = clone_hunk_as_ro_hunk(&strings, logger, HERE);
	whack_connection_roots(wm, s, /*alias_order*/OLD2NEW, autoall_save,
			       (struct connection_visitor_context *)&ctx,
			       (struct each) {
				       .log_unknown_name = false,
			       });
	ro_hunk_delref(&ctx.copy, logger);
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
