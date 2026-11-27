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

#ifndef WHACK_AUTOALL_H
#define WHACK_AUTOALL_H

struct whack_message;
struct show;
struct connection;
struct logger;

/* refcounted root connections */
struct autoall_roots {
	struct connection **list;
	unsigned len;
};

void autoall_roots_append(struct autoall_roots *roots, struct connection *c,
			  const struct logger *logger);
void autoall_roots_release(struct autoall_roots *roots,
			   const struct logger *logger);

enum autoall_action {
	AUTOALL_ADD,		/* nothing by that name or alias */
	AUTOALL_REPLACE,	/* purge what is there, then add */
	AUTOALL_KEEP,		/* change nothing */
};

void whack_autoall_start(const struct whack_message *wm, struct show *s);
void whack_autoall_stop(const struct whack_message *wm, struct show *s);

enum autoall_action whack_autoall_add(const struct whack_message *wm, struct show *s);
void whack_autoall_save(const struct whack_message *wm,
			const struct autoall_roots *roots,
			const struct logger *logger);

#endif
