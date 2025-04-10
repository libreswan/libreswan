/* unpack generic parts of a message, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002,2010-2017 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2006  Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010-2011 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2018 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2014-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017-2018 Antony Antony <antony@phenome.org>
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
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

#include "ike_alg.h"
#include "id.h"
#include "ip_info.h"

#include "defs.h"		/* for so_serial_t */
#include "demux.h"
#include "unpack.h"
#include "log.h"
#include "packet.h"

/* accept_KE
 *
 * Check and accept DH public value (Gi or Gr) from peer's message.
 * According to RFC2409 "The Internet key exchange (IKE)" 5:
 *  The Diffie-Hellman public value passed in a KE payload, in either
 *  a phase 1 or phase 2 exchange, MUST be the length of the negotiated
 *  Diffie-Hellman group enforced, if necessary, by prepending the
 *  value with zeros.
 */

bool unpack_KE(chunk_t *dest, const char *val_name,
	       const struct dh_desc *gr,
	       struct payload_digest *ke_pd,
	       struct logger *logger)
{
	if (ke_pd == NULL) {
		llog(RC_LOG, logger, "KE missing");
		return false;
	}
	struct pbs_in *pbs = &ke_pd->pbs;
	if (pbs_left(pbs) != gr->bytes) {
		llog(RC_LOG, logger,
			    "KE has %u byte DH public value; %u required",
			    (unsigned) pbs_left(pbs), (unsigned) gr->bytes);
		return false;
	}
	replace_chunk(dest, pbs_in_left(pbs), val_name);
	if (LDBGP(DBG_CRYPT, logger)) {
		LDBG_log(logger, "DH public value received:");
		LDBG_hunk(logger, *dest);
	}
	return true;
}

void unpack_nonce(chunk_t *n, chunk_t *nonce)
{
	/* steal away */
	free_chunk_content(n);
	*n = *nonce;
	*nonce = empty_chunk;
}
