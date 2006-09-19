/*
 * stubs for certain functions which are sometimes not present
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
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
 * RCSID $Id: stubs.c,v 1.3 2005/08/31 03:36:27 mcr Exp $
 */

#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>	/* missing from <resolv.h> on old systems */

#include <openswan.h>
#include <openswan/ipsec_policy.h>
#include "openswan/pfkeyv2.h"

#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "id.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#include "ac.h"
#include "smartcard.h"
#ifdef XAUTH_USEPAM
#include <security/pam_appl.h>
#endif
#include "connections.h"	/* needs id.h */
#include "pending.h"
#include "foodgroups.h"
#include "packet.h"
#include "demux.h"	/* needs packet.h */
#include "state.h"
#include "timer.h"
#include "ipsec_doi.h"	/* needs demux.h and state.h */
#include "server.h"
#include "kernel.h"	/* needs connections.h */
#include "log.h"
#include "keys.h"
#include "secrets.h"
#include "adns.h"	/* needs <resolv.h> */
#include "dnskey.h"	/* needs keys.h and adns.h */
#include "whack.h"
#include "alg_info.h"
#include "spdb.h"
#include "ike_alg.h"
#include "kernel_alg.h"
#include "plutoalg.h"
#include "xauth.h"
#ifdef NAT_TRAVERSAL
#include "nat_traversal.h"
#endif

#ifdef VIRTUAL_IP
#include "virtual.h"
#endif

#include "pluto_crypt.h"
#include "crypto.h"
#include "ikev1.h"

stf_status aggr_not_present(int whack_sock UNUSED
			    , struct connection *c UNUSED
			    , struct state *predecessor UNUSED
			    , lset_t policy UNUSED
			    , unsigned long try UNUSED
			    , enum crypto_importance importance UNUSED)
{
    openswan_log("An attempt to use aggressive mode was made.");
    openswan_log("This pluto does not have aggressive mode (congradulations on your wisdom)");

    return STF_FATAL;
}



/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
