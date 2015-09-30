/*
 * unit test for IKEv2 RSA signature/verification
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
 * This code was developed with the support of IXIA communications.
 */

#define LEAK_DETECTIVE
#define DEBUG 1
#define PRINT_SA_DEBUG 1
#define USE_KEYRR 1

#include <stdio.h>
#include <stdlib.h>
#include "sysqueue.h"
#include "lswlog.h"
#include "lswconf.h"
#include "packet.h"
#include "defs.h"
#include "connections.h"
#include "state.h"
#include "keys.h"
#include "crypto.h"
#include "readwhackmsg.h"
#include "ike_alg.h"
#include "ikev2.h"

#include "../../../programs/pluto/hmac.c"
#include "seam_pending.c"
#include "whackmsgtestlib.c"
#include "seam_whack.c"
#include "seam_log.c"
#include "seam_east.c"
#include "seam_rnd.c"
#include "seam_timer.c"
#include "seam_initiate.c"
#include "seam_terminate.c"
#include "seam_kernel.c"
#include "seam_xauth.c"
#include "seam_natt.c"
#include "seam_state.c"
#include "seam_kernelops.c"

void gw_addref(struct gw_info *gw)
{
}
void gw_delref(struct gw_info **gwp)
{
}
bool in_pending_use(const struct connection *c)
{
	return FALSE;
}

char *progname;

const char *check_expiry(time_t expiration_date, int warning_interval,
			bool strict)
{
	return "ok (never)";
}

void exit_log(const char *message, ...)
{
	va_list args;
	char m[LOG_WIDTH];      /* longer messages will be truncated */

	va_start(args, message);
	vsnprintf(m, sizeof(m), message, args);
	va_end(args);

	fprintf(stderr, "FATAL ERROR: %s\n", m);
	exit(0);
}

void exit_tool(int code)
{
	exit(code);
}

void exit_pluto(int code)
{
	exit(code);
}

unsigned char idhash[SHA1_DIGEST_SIZE] = {
	0x01, 0x02, 0x03, 0x04,
	0x11, 0x12, 0x13, 0x14,
	0x21, 0x22, 0x23, 0x24,
	0x31, 0x32, 0x33, 0x34,
	0x41, 0x42, 0x43, 0x44,
};

#include "packetsI1psk.c"

extern struct encrypt_desc algo_aes;
struct encrypt_desc *tc3_encrypter = &algo_aes;
#include "../../lib/libpluto/seam_gi_sha1.c"

int main(int argc, char *argv[])
{
	unsigned char outbuf[1024];
	struct state st1;
	pb_stream outs;
	struct connection *c1;

	progname = argv[0];
	cur_debugging = DBG_CRYPT;

	memset(&st1, 0, sizeof(st1));
	pluto_shared_secrets_file = "../../pluto/ikev2-psk-01/west.secrets";

	lsw_init_ipsecdir("../../baseconfigs/east/etc/ipsec.d");
	lsw_init_rootdir("../../baseconfigs/east");

	/* initialize list of moduli */
	init_crypto();

	readwhackmsg("../../lib/libpluto/lib-parentI1psk/ikev2.record");
	c1 = con_by_name("westnet--eastnet-ikev2", TRUE);

	passert(c1 != NULL);
	show_one_connection(c1);

	init_out_pbs(&outs, outbuf, sizeof(outbuf), "psk signature");

	load_preshared_secrets();

	clonetochunk(st1.st_firstpacket_me, packet1 + 32, packet1_len - 32,
		     "I1");

	/* write nonce to both sides, because we switch roles */
	clonetochunk(st1.st_ni, tc3_ni, tc3_ni_len, "Ni");
	clonetochunk(st1.st_nr, tc3_ni, tc3_ni_len, "Nr");

	st1.st_connection = c1;
	st1.st_oakley.prf_hash = IKEv2_PRF_HMAC_SHA1;
	st1.st_oakley.prf_hasher =
		(struct hash_desc *)ikev2_alg_find(IKE_ALG_HASH,
						       st1.st_oakley.prf_hash);

	ikev2_calculate_psk_auth(&st1,
				 INITIATOR,
				 idhash,
				 &outs);

	DBG_dump_pbs(&outs);

	{
		size_t sig_len = pbs_offset(&outs);

		/* rewind outs pbs */
		init_pbs(&outs, outbuf, sig_len, "psk signature");
	}

	/* swap c1->this and c1->that, because to verify, we have to swap
	 * identities.
	 */
	{
		struct end tmp = c1->spd.this;
		c1->spd.this = c1->spd.that;
		c1->spd.that = tmp;
	}
	clonetochunk(st1.st_firstpacket_him, packet1 + 32, packet1_len - 32,
		     "R1");

	show_one_connection(c1);
	{
		stf_status stat = ikev2_verify_psk_auth(&st1,
							RESPONDER,
							idhash,
							&outs);
		printf("stf status: %s\n", enum_name(&stfstatus_name, stat));
	}

	exit(0);
}

