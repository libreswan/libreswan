/* demultiplex incoming IKEv1 packets
 *
 * Copyright (C) 2026 Andrew Cagney
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

#ifndef IKEv1_DEMUX_H
#define IKEv1_DEMUX_H

struct msg_digest;
struct logger;

void process_ikev1_md(struct msg_digest *md,
		      unsigned vmajor,
		      unsigned vminor);

void init_ikev1_demux(struct logger *logger);

#endif
