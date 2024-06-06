/* impair messages recv/sent, for libreswan
 *
 * Copyright (C) 2020,2023  Andrew Cagney
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
 * - inbound and outbound message streams are numbered separately
 *
 * - only unique messages (for each stream) are assigned a new number
 *
 *   i.e., a duplicate message will have the same number as the
 *   original
 *
 * - once an impair has been matched and actioned it is discarded
 *
 *   i.e., drop-inomming:2 will only match and drop the first inbound
 *   message #2
 *
 * For instance, here's an exchange with the INITIATOR impaired to
 * drop the second inbound message:
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
#include "ip_endpoint.h"

struct logger;
struct msg_digest;
enum impair_action;
struct iface_device;

void add_message_impairment(enum impair_action impair_action,
			    enum impair_message_direction impair_direction,
			    bool whack_enable, unsigned whack_value,
			    struct logger *logger);

bool impair_outbound(const struct iface_endpoint *interface, shunk_t message,
		     const ip_endpoint *endpoint, struct logger *logger);

bool impair_inbound(struct msg_digest *md);

void shutdown_impair_message(struct logger *logger);

#endif /* _DEMUX_H */
