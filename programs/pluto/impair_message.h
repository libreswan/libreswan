/* impair messages recv/sent, for libreswan
 *
 * Copyright (C) 2020  Andrew Cagney
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

#ifndef IMPAIR_MESSAGE_H
#define IMPAIR_MESSAGE_H

#include <stdbool.h>

#include "shunk.h"

struct logger;
struct msg_digest;
enum impair_action;

void add_message_impairment(unsigned nr, enum impair_action action, struct logger *logger);
bool impair_incoming_message(struct msg_digest *md);
bool impair_outgoing_message(shunk_t message, struct logger *logger);

void free_impair_message(struct logger *logger);

#endif /* _DEMUX_H */
