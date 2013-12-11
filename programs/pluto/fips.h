/*
 * FIPS header
 *
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
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

#ifdef FIPS_CHECK
# include <fipscheck.h>
#endif

const char *fips_package_files[] = { IPSEC_EXECDIR "/pluto",
				IPSEC_EXECDIR "/setup",
				IPSEC_EXECDIR "/addconn",
				IPSEC_EXECDIR "/auto",
				IPSEC_EXECDIR "/barf",
				IPSEC_EXECDIR "/eroute",
				IPSEC_EXECDIR "/ikeping",
				IPSEC_EXECDIR "/readwriteconf",
				IPSEC_EXECDIR "/_keycensor",
				IPSEC_EXECDIR "/klipsdebug",
				IPSEC_EXECDIR "/look",
				IPSEC_EXECDIR "/newhostkey",
				IPSEC_EXECDIR "/pf_key",
				IPSEC_EXECDIR "/_pluto_adns",
				IPSEC_EXECDIR "/_plutorun",
				IPSEC_EXECDIR "/rsasigkey",
				IPSEC_EXECDIR "/_secretcensor",
				IPSEC_EXECDIR "/secrets",
				IPSEC_EXECDIR "/showhostkey",
				IPSEC_EXECDIR "/spi",
				IPSEC_EXECDIR "/spigrp",
				IPSEC_EXECDIR "/_stackmanager",
				IPSEC_EXECDIR "/tncfg",
				IPSEC_EXECDIR "/_updown",
				IPSEC_EXECDIR "/_updown.klips",
				IPSEC_EXECDIR "/_updown.mast",
				IPSEC_EXECDIR "/_updown.netkey",
				IPSEC_EXECDIR "/verify",
				IPSEC_EXECDIR "/whack",
				IPSEC_SBINDIR "/ipsec",
				NULL };
