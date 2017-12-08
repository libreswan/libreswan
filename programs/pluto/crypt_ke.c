/*
 * Cryptographic helper function - calculate KE and nonce
 * Copyright (C) 2004 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 - 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2017 Andrew Cagney <cagney@gnu.org>
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

#include <nss.h>
#include <nspr.h>
#include <prerror.h>
#include <pk11pub.h>
#include <keyhi.h>
#include "lswnss.h"
#include "test_buffer.h"
#include "ike_alg.h"

/* MUST BE THREAD-SAFE */
void calc_ke(struct pcr_kenonce *kn)
{
	const struct oakley_group_desc *group = kn->group;

	kn->gi = alloc_chunk(group->bytes, "gi");
	group->dhmke_ops->calc_ke(group, &kn->secret, &kn->pubk,
				  kn->gi.ptr, kn->gi.len);

	DBG(DBG_CRYPT,
	    DBG_log("NSS: Local DH %s public value (pointer): %p",
		    group->common.name, kn->pubk);
	    DBG_log("NSS: Local DH %s secret (pointer): %p",
		    group->common.name, kn->secret);
	    DBG_dump_chunk("NSS: Public DH wire value:",
			   kn->gi));
}

/* MUST BE THREAD-SAFE */
void calc_nonce(struct pcr_kenonce *kn)
{
	kn->n = alloc_chunk(DEFAULT_NONCE_SIZE, "n");
	get_rnd_bytes(kn->n.ptr, kn->n.len);

	DBG(DBG_CRYPT,
	    DBG_dump_chunk("Generated nonce:", kn->n));
}

void cancelled_ke_and_nonce(struct pcr_kenonce *kn)
{
	if (kn->secret != NULL) {
		SECKEY_DestroyPrivateKey(kn->secret);
	}
	if (kn->pubk != NULL) {
		SECKEY_DestroyPublicKey(kn->pubk);
	}
	freeanychunk(kn->n);
	freeanychunk(kn->gi);
}

/* Note: not all cn's are the same subtype */
stf_status build_ke_and_nonce(struct state *st,
			      struct pluto_crypto_req_cont *cn,
			      const struct oakley_group_desc *group,
			      enum crypto_importance importance)
{
	passert(st->st_serialno == cn->pcrc_serialno);
	passert(!st->st_sec_in_use);
	pcr_kenonce_init(cn, pcr_build_ke_and_nonce,
			 importance, group);
	return send_crypto_helper_request(st, cn);
}

stf_status build_nonce(struct state *st,
		       struct pluto_crypto_req_cont *cn,
		       enum crypto_importance importance)
{
	pcr_kenonce_init(cn, pcr_build_nonce,
			 importance, NULL);

	return send_crypto_helper_request(st, cn);
}
