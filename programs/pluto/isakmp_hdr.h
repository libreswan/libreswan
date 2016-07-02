/* format of ISAKMP message header
 * Copyright (C) 2014 D. Hugh Redelmeier <hugh@mimosa.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
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
#define NOFFSETOF_isa_np	16	/* on-the-wire offset of isa_np (one octet) */
#define NOFFSETOF_isag_length	2	/* on-the-wire offset of isag_length (two octets, network order */
#define NOFFSETOF_isag_np	0	/* on-the-wire offset of isag_np (one octet) */
#define NSIZEOF_isakmp_generic	4	/* on-the-wire sizeof isakmp_generic) */

struct isakmp_hdr {
	u_int8_t isa_icookie[COOKIE_SIZE];
	u_int8_t isa_rcookie[COOKIE_SIZE];
	u_int8_t isa_np;	/* Next payload */
	u_int8_t isa_version;	/* high-order 4 bits: Major; low order 4: Minor */
	u_int8_t isa_xchg;	/* Exchange type */
	u_int8_t isa_flags;
	u_int32_t isa_msgid;	/* Message ID (RAW) */
	u_int32_t isa_length;	/* Length of message */
};
