/* show functions, for libreswan
 *
 * Copyright (C) 2020 Andrew Cagney
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

#ifndef SHOW_H
#define SHOW_H

/*
 * Try to deal with the separator (aka blank line or spacer) problem
 * in show output.
 */

struct show;
enum rc_type;

struct show *alloc_show(struct logger *logger);
void free_show(struct show **s);
/* underlying global logger formed by alloc_show() */
struct logger *show_logger(struct show *s);

/*
 * output primitives: access the internal jambuf; show the contents of
 * a jambuf.
 */

struct jambuf *show_jambuf(struct show *s);
void jambuf_to_show(struct jambuf *jambuf, struct show *s, enum rc_type rc);
#define SHOW_JAMBUF(RC, S, BUF)				\
	for (struct jambuf *BUF = show_jambuf(s);	\
	     BUF != NULL;				\
	     jambuf_to_show(BUF, S, RC), BUF = NULL)

/*
 * Flag that the next line needs to be preceded by a separator (aka
 * blank line).  For instance:
 *
 *    struct show *s = new_show(whackfd);
 *    show_separator(s);
 *    show_comment(s, "heading 1");
 *    show_separator(s);
 *    show_separator(s);
 *    show_comment(s, "heading 2");
 *    show_separator(s);
 *    free_show(&s);
 *
 * will output:
 *
 *    line 1
 *    <blank>
 *    line 2
 *    <blank>
 *
 */
void show_separator(struct show *s);

/*
 * If necessary show the separator (aka blank line), and then show the
 * message.  Suppress further separation.
 *
 * "comment" comes from RC_COMMENT, better name?
 */

void show_comment(struct show *s, const char *message, ...) PRINTF_LIKE(2);

/*
 * A raw line (no prefix).
 */
void show_raw(struct show *s, const char *message, ...) PRINTF_LIKE(2);

#endif
