/* ipsec add --autoall reconciliation, for libreswan
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

struct autoall_run {
	uint64_t run;		/* 0 when none */
	bool overtaken;		/* a real run sent messages since START */
	unsigned unchanged, replaced, added;
};

static struct {
	struct autoall_run real, dry;
} runs;

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

/* is C one of the roots that adding WM produces? */
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

void autoall_roots_append(struct autoall_roots *roots, struct connection *c,
			  const struct logger *logger)
{
	realloc_things(roots->list, roots->len, roots->len + 1, "autoall roots");
	roots->list[roots->len++] = connection_addref(c, logger);
}

void autoall_roots_release(struct autoall_roots *roots,
			   const struct logger *logger)
{
	for (unsigned i = 0; i < roots->len; i++) {
		connection_delref(&roots->list[i], logger);
	}
	pfreeany(roots->list);
	roots->len = 0;
}

/* .dry_run is off the wire, don't index with it */
static struct autoall_run *run_slot(const struct whack_message *wm, struct show *s)
{
	if (wm->whack_autoall.run == 0) {
		show_rc(RC_FATAL, s, "received ipsec add --autoall message without a run - ignored");
		return NULL;
	}
	return (wm->whack_autoall.dry_run ? &runs.dry : &runs.real);
}

static struct autoall_run *current_run(const struct whack_message *wm, struct show *s)
{
	struct autoall_run *r = run_slot(wm, s);
	if (r == NULL) {
		return NULL;
	}
	if (wm->whack_autoall.run != r->run) {
		show_rc(RC_AUTOALL_CONFLICT, s,
			"ipsec add --autoall was superseded by a later run");
		return NULL;
	}
	if (r == &runs.real) {
		runs.dry.overtaken = true;
	}
	return r;
}

/*
 * Find what adding WM would purge.  It is unchanged when every root
 * it produced last time is there, with identical strings.
 */

struct connection_visitor_context {
	shunk_t strings;
	bool dry_run;
	struct autoall_roots roots;
	unsigned nr_own;	/* roots that WM produced */
	unsigned nr_expected;
	bool changed;
};

static unsigned lookup_root(const struct whack_message *wm,
			    struct show *s,
			    struct connection *c,
			    struct connection_visitor_context *l)
{
	autoall_roots_append(&l->roots, c, show_logger(s));
	if (!autoall_root(wm, c)) {
		return 0;
	}
	l->nr_own++;
	/* .autoall_dry_purged: a dry run's earlier purge would delete it */
	if (c->autoall_config == NULL ||
	    (l->dry_run && c->autoall_dry_purged) ||
	    !hunk_eq(*c->autoall_config, l->strings)) {
		l->changed = true;
	} else if (l->nr_expected == 0) {
		l->nr_expected = c->autoall_nr_roots;
	} else if (l->nr_expected != c->autoall_nr_roots) {
		l->changed = true;
	}
	return 1;
}

static enum autoall_action lookup(const struct whack_message *wm,
				  struct show *s,
				  bool dry_run,
				  struct connection_visitor_context *l)
{
	*l = (struct connection_visitor_context) {
		.strings = packed_strings(wm),
		.dry_run = dry_run,
	};
	whack_connection_roots(wm, s, /*alias_order*/OLD2NEW,
			       lookup_root, l,
			       (struct each) {
				       .log_unknown_name = false,
			       });
	if (l->roots.len == 0) {
		return AUTOALL_ADD;
	}
	if (l->changed || l->nr_own == 0) {
		return AUTOALL_REPLACE;
	}
	if (l->nr_own != l->nr_expected) {
		ldbg(show_logger(s), "autoall: %s has %u of %u connections",
		     wm->name, l->nr_own, l->nr_expected);
		return AUTOALL_REPLACE;
	}
	return AUTOALL_KEEP;
}

static void preview(const struct whack_message *wm, struct show *s,
		    struct autoall_run *r, enum autoall_action action,
		    const struct autoall_roots *roots)
{
	switch (action) {
	case AUTOALL_ADD:
		show(s, "\"%s\": would be added", wm->name);
		r->added++;
		break;
	case AUTOALL_REPLACE:
		show(s, "\"%s\": would be replaced", wm->name);
		r->replaced++;
		break;
	case AUTOALL_KEEP:
		r->unchanged++;
		break;
	}

	/*
	 * Mark the roots the way the real run would leave them.  The
	 * purge also deletes any alias: like a root that was not
	 * loaded, it is swept unless a later connection re-adds it.
	 */
	for (unsigned i = 0; i < roots->len; i++) {
		struct connection *c = roots->list[i];
		bool own = autoall_root(wm, c);
		if (action == AUTOALL_REPLACE) {
			c->autoall_dry_purged = true;
			c->autoall_dry_stale = !own;
		} else if (own) {
			c->autoall_dry_stale = false;
		}
	}
}

enum autoall_action whack_autoall_add(const struct whack_message *wm, struct show *s)
{
	if (wm->whack_autoall.run == 0) {
		return AUTOALL_REPLACE;	/* plain add */
	}
	struct autoall_run *r = current_run(wm, s);
	if (r == NULL) {
		return AUTOALL_KEEP;	/* superseded */
	}

	struct logger *logger = show_logger(s);
	bool dry_run = (r == &runs.dry);
	struct connection_visitor_context l;
	enum autoall_action action = lookup(wm, s, dry_run, &l);
	if (dry_run) {
		preview(wm, s, r, action, &l.roots);
		action = AUTOALL_KEEP;
	} else if (action == AUTOALL_KEEP) {
		for (unsigned i = 0; i < l.roots.len; i++) {
			struct connection *c = l.roots.list[i];
			if (autoall_root(wm, c)) {
				c->autoall_stale = false;
				whack_attach(c, logger);
				llog(RC_LOG, c->logger, "unchanged");
				whack_detach(c, logger);
			}
		}
	} else {
		/*
		 * The purge deletes these.  One that something else
		 * still holds must not be deleted again by the sweep.
		 */
		for (unsigned i = 0; i < l.roots.len; i++) {
			l.roots.list[i]->autoall_stale = false;
		}
	}
	autoall_roots_release(&l.roots, logger);
	return action;
}

void whack_autoall_save(const struct whack_message *wm,
			const struct autoall_roots *roots,
			const struct logger *logger)
{
	if (wm->whack_autoall.run == 0 || roots->len == 0) {
		return;
	}
	/* one copy shared by every root that WM produced */
	shunk_t strings = packed_strings(wm);
	struct ro_hunk *copy = clone_hunk_as_ro_hunk(&strings, logger, HERE);
	for (unsigned i = 0; i < roots->len; i++) {
		struct connection *c = roots->list[i];
		replace_ro_hunk(&c->autoall_config, copy, c->logger, HERE);
		c->autoall_nr_roots = roots->len;
	}
	ro_hunk_delref(&copy, logger);
}

void whack_autoall_start(const struct whack_message *wm, struct show *s)
{
	struct autoall_run *r = run_slot(wm, s);
	if (r == NULL) {
		return;
	}
	struct logger *logger = show_logger(s);
	bool dry_run = (r == &runs.dry);

	if (r->run != 0) {
		llog(RC_LOG, logger, "superseding an unfinished ipsec add --autoall");
	}

	*r = (struct autoall_run) {
		.run = wm->whack_autoall.run,
	};

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
		if (dry_run) {
			cq.c->autoall_dry_stale = true;
			cq.c->autoall_dry_purged = false;
		} else {
			cq.c->autoall_stale = true;
		}
	}
}

void whack_autoall_stop(const struct whack_message *wm, struct show *s)
{
	struct autoall_run *r = current_run(wm, s);
	if (r == NULL) {
		return;
	}
	r->run = 0;

	struct logger *logger = show_logger(s);
	bool dry_run = (r == &runs.dry);

	if (wm->whack_autoall.unsent > 0) {
		llog(ERROR_STREAM, logger,
		     "not sweeping, %u connections could not be sent to pluto",
		     wm->whack_autoall.unsent);
		return;
	}

	if (dry_run && r->overtaken) {
		show_rc(RC_AUTOALL_CONFLICT, s,
			"dry run may be out of date, another ipsec add --autoall ran during it");
		return;
	}

	ldbg(logger, "sweeping stale connections after autoall");

	/*
	 * Collect, then delete.  Only roots are held, so a template's
	 * instances can go away when it is deleted.
	 */
	unsigned swept = 0;
	struct autoall_roots stale = {0};
	struct connection_filter cq = {
		.search = {
			.order = OLD2NEW,
			.verbose.logger = logger,
			.where = HERE,
		},
	};
	while (next_connection(&cq)) {
		if (cq.c->clonedfrom != NULL ||
		    !(dry_run ? cq.c->autoall_dry_stale : cq.c->autoall_stale)) {
			continue;
		}
		swept++;
		if (dry_run) {
			show(s, "%s: would be swept", cq.c->name);
		} else {
			autoall_roots_append(&stale, cq.c, logger);
		}
	}

	for (unsigned i = 0; i < stale.len; i++) {
		struct connection **cp = &stale.list[i];
		if (refcnt_peek(*cp, logger) == 1) {
			continue;	/* already deleted */
		}
		whack_attach(*cp, logger);
		llog(RC_LOG, (*cp)->logger, "swept");
		terminate_and_delete_connections(*cp, logger, HERE);
		connection_delref(cp, logger);
	}
	autoall_roots_release(&stale, logger);

	if (dry_run) {
		show(s, "dry run: %u unchanged, %u to replace, %u to add, %u to sweep",
		     r->unchanged, r->replaced, r->added, swept);
	}
}
