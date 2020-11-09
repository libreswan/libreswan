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

/*
 * Impair a message identified using the message's direction's
 * sequence number:
 *
 * - incoming and outgoing message streams are numbered separately
 *
 * - only unique messages (for each stream) are assigned a new number
 *
 *   i.e., a duplicate message will have the same number as the
 *   original
 *
 * - once an impair has been matched and actioned it is discarded
 *
 *   i.e., drop-inomming:2 will only match and drop the first incoming
 *   message #2
 *
 * For instance, here's an exchange with the INITIATOR impaired to
 * drop the second incoming message:
 *
 *     initiator                             responder
 *       out#1     IKE_SA_INIT req ->           in#1
 *       in#1   <- IKE_SA_INIT resp             out#1
 *       out#2     IKE_AUTH req ->              in#2
 *      *in#2*  <- IKE_AUTH resp                out#2  DROPPED
 *       out#2     IKE_AUTH req ->              in#2   RETRANSMIT
 *       in#2   <- IKE_AUTH resp                out#2  RETRANSMIT
 *
 * See enum impair_action for what actions are supported)
 */

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
