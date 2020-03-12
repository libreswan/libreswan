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
 * Try to deal with the blank line (spacer) problem in show output:
 *
 * Set spacer to true to indicate that the next output should be
 * preceeded by a blank line.
 *
 * For instance:
 *
 * show_p(s)
 *    show_comment(s, "Showing p");
 *    s->spacer = true;
 *    for (p in list) {
 *        show_comment(s, "  p: %d", p->i);
 *    }
 *    s->spacer = true;
 *
 * will output:
 *
 *    Showing p:
 *
 *      p: 1
 */

struct show {
	/*
	 * where to send the output
	 */
	const struct fd *whackfd;
	/*
	 * Should the next output be preceeded by a blank line?
	 */
	bool spacer;
};

/*
 * If necessary show a spacer, then suppress further spacers:
 *
 * For instance:
 *
 *    show_spacer(s);
 *    WHACK_LOG(RC_COMMENT, s->whackfd, buf) {
 *       jam(buf, "some stuff");
 *    }
 */
void show_spacer(struct show *s);

/*
 * If necessary show a spacer (suppressing further spacers), and then
 * show the message.  Its a wrapper for the above example.
 */
void show_comment(struct show *s, const char *message, ...) PRINTF_LIKE(2);

#endif
