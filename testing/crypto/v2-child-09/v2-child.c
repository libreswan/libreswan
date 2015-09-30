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

/* for child sa calculation */
#include "alg_info.h"

#include "seam_pending.c"
#include "whackmsgtestlib.c"
#include "seam_whack.c"
#include "seam_log.c"
#include "seam_east.c"
#include "seam_rnd.c"
#include "seam_timer.c"
#include "seam_initiate.c"
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

extern struct encrypt_desc algo_aes;
struct encrypt_desc *tc3_encrypter = &algo_aes;
#include "../../lib/libpluto/seam_gi_sha1.c"
#include "../../lib/libpluto/seam_kernelalgs.c"

int main(int argc, char *argv[])
{
	struct state st1;

	progname = argv[0];
	cur_debugging = DBG_CRYPT | DBG_KERNEL | DBG_PARSING;

	memset(&st1, 0, sizeof(st1));
	pluto_shared_secrets_file = "../../baseconfigs/east/etc/ipsec.secrets";

	lsw_init_ipsecdir("../../baseconfigs/east/etc/ipsec.d");
	lsw_init_rootdir("../../baseconfigs/east");

	/* initialize list of moduli */
	init_crypto();

	init_seam_kernelalgs();

	/* now derive the keys for the CHILD_SA */
	{
		struct ipsec_proto_info *ipi;

		setchunk(st1.st_skey_d, tc3_results_skey_d,
			 sizeof(tc3_results_skey_d));

		ipi = &st1.st_esp;
		ipi->attrs.transattrs.encrypt   = IKEv2_ENCR_AES_CBC;
		ipi->attrs.transattrs.enckeylen = 128;
		ipi->attrs.transattrs.integ_hash = alg_info_esp_v2tov1aa(
			IKEv2_AUTH_HMAC_SHA1_96);

		ikev2_derive_child_keys(&st1);

		DBG_dump("our  keymat: ",
			 ipi->our_keymat,
			 ipi->keymat_len);

		DBG_dump("peer keymat: ",
			 ipi->peer_keymat,
			 ipi->keymat_len);
	}

	exit(0);
}

