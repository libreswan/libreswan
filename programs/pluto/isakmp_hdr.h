/* format of ISAKMP message header
 * Copyright (C) 2014 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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

/*
 * This used to be part of packet.h.
 * It is the only part used outside of Pluto (by ikeping).
 * Breaking this out allows packet.h to be private to Pluto.
 */

#include "ike_spi.h"

/* ISAKMP Header: for all messages
 * layout from RFC 2408 "ISAKMP" section 3.1
 *
 * NOTE: the IKEv2 header format is identical EXCEPT that the cookies are now
 * called (IKE SA) SPIs.  See RFC 5996 Figure 4.
 *
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                          Initiator                            !
 * !                            Cookie                             !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                          Responder                            !
 * !                            Cookie                             !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !  Next Payload ! MjVer ! MnVer ! Exchange Type !     Flags     !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                          Message ID                           !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                            Length                             !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#define NSIZEOF_isakmp_hdr	28	/* on-the-wire sizeof struct isakmpg_hdr */
#define NSIZEOF_isakmp_generic	4	/* on-the-wire sizeof isakmp_generic) */

struct isakmp_hdr {
#define isa_ike_initiator_spi isa_ike_spis.initiator
#define isa_ike_responder_spi isa_ike_spis.responder
	ike_spis_t isa_ike_spis;
	uint8_t isa_np;	/* Next payload */
	uint8_t isa_version;	/* high-order 4 bits: Major; low order 4: Minor */
	uint8_t isa_xchg;	/* Exchange type */
	uint8_t isa_flags;
	uint32_t isa_msgid;	/* Message ID */
	uint32_t isa_length;	/* Length of message */
};
