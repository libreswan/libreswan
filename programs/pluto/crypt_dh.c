/*
 * Cryptographic helper function - calculate DH
 *
 * Copyright (C) 2007-2008 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2009-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Wes Hardaker <opensource@hardakers.net>
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2015 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2015,2017 Andrew Cagney <cagney@gnu.org>
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
 * This code was developed with the support of IXIA communications.
 *
 */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <signal.h>

#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "packet.h"
#include "demux.h"
#include "crypto.h"
#include "rnd.h"
#include "state.h"
#include "pluto_crypt.h"
#include "lswlog.h"
#include "log.h"
#include "timer.h"
#include "ike_alg.h"
#include "id.h"
#include "keys.h"
#include "crypt_dh.h"
#include "crypt_symkey.h"
#include <nss.h>
#include <pk11pub.h>
#include <keyhi.h>
#include "lswnss.h"

/** Compute DH shared secret from our local secret and the peer's public value.
 * We make the leap that the length should be that of the group
 * (see quoted passage at start of ACCEPT_KE).
 * If there is something that upsets NSS (what?) we will return NULL.
 */
/* MUST BE THREAD-SAFE */
PK11SymKey *calc_dh_shared(const chunk_t g,	/* converted to SECItem */
			   /*const*/ SECKEYPrivateKey *privk,	/* NSS doesn't do const */
			   const struct oakley_group_desc *group,
			   const SECKEYPublicKey *local_pubk)
{
	PK11SymKey *dhshared = group->dhmke_ops->calc_g_ir(group, privk,
							   local_pubk,
							   g.ptr, g.len);
	/*
	 * The IKEv2 documentation, even for ECP, refers to "g^ir".
	 */
	DBG(DBG_CRYPT, DBG_symkey("dh-shared ", "g^ir", dhshared));
	return dhshared;
}

/* NOTE: if NSS refuses to calculate DH, skr->shared == NULL */
/* MUST BE THREAD-SAFE */
void calc_dh(struct pluto_crypto_req *r)
{
	/* copy the request, since the reply will re-use the memory of the r->pcr_d.dhq */
	struct pcr_skeyid_q dhq;
	memcpy(&dhq, &r->pcr_d.dhq, sizeof(r->pcr_d.dhq));

	/* clear out the reply */
	struct pcr_skeyid_r *skr = &r->pcr_d.dhr;
	zero(skr);	/* ??? pointer fields might not be NULLed */
	INIT_WIRE_ARENA(*skr);

	const struct oakley_group_desc *group = dhq.oakley_group;
	passert(group != NULL);

	SECKEYPrivateKey *ltsecret = dhq.secret;
	SECKEYPublicKey *pubk = dhq.pubk;

	/* now calculate the (g^x)(g^y) */

	chunk_t g;

	setchunk_from_wire(g, &dhq, dhq.role == ORIGINAL_RESPONDER ? &dhq.gi : &dhq.gr);

	DBG(DBG_CRYPT, DBG_dump_chunk("peer's g: ", g));

	skr->shared = calc_dh_shared(g, ltsecret, group, pubk);
}
