/*
 * continuations for using the asynchronous crypto routines.
 *
 * Copyright (C) 2007 Michael C. Richardson <mcr@xelerance.com>
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
 *
 */

#ifndef _IKE_CONTINUATIONS_
#define _IKE_CONTINUATIONS_

struct ke_continuation {
	struct pluto_crypto_req_cont ke_pcrc;
	struct msg_digest           *md;
};

struct dh_continuation {
	struct pluto_crypto_req_cont dh_pcrc;
	struct msg_digest           *md;
	so_serial_t serialno;                   /* used for inter state
	                                         * calculations on responder */
};

#endif /* _IKE_CONTINUATIONS_ */
