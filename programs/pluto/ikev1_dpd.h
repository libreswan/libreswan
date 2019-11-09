/* IPsec IKE Dead Peer Detection code.
 *
 * Copyright (C) 2003 Ken Bantoft        <ken@xelerance.com>
 * Copyright (C) 2003-2006 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010 FURUSO Shinichi <Shinichi.Furuso@jp.sony.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
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
extern stf_status dpd_init(struct state *st);
extern void dpd_event(struct state *st);

extern stf_status dpd_inI_outR(struct state *st,
			       struct isakmp_notification *const n,
			       pb_stream *pbs);
extern stf_status dpd_inR(struct state *st,
			  struct isakmp_notification *const n,
			  pb_stream *pbs);
extern void dpd_timeout(struct state *st);

#define DPD_RETRANS_MAX 3
