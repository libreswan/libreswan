/* <<ipsec listen ...>> aka addconn, for libreswan
 *
 * Copyright (C) 2025 Andrew Cagney
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

#ifndef WHACK_LISTEN_H
#define WHACK_LISTEN_H

struct whack_message;
struct show;
struct whack_listen;
struct logger;

void whack_listen_1(const struct whack_listen *wl, struct logger *logger);
void whack_listen(const struct whack_message *wm, struct show *s);

#endif
