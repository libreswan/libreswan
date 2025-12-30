/*
 * Use libunbound to use DNSSEC supported resolving.
 *
 * Copyright (C) 2025  Andrew Cagney
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

#include "dnssec.h"

#include "ipsecconf/setup.h"

static struct dnssec_config config;
static const struct dnssec_config *dnssec;

const struct dnssec_config *dnssec_config_singleton(struct logger *logger UNUSED)
{
	if (dnssec != NULL) {
		return dnssec;
	}

	bool enable = config_setup_yn(KYN_DNSSEC_ENABLE);
#ifdef USE_UNBOUND
	config.enable = enable;
#else
	if (enable) {
		llog(WARNING_STREAM, logger, "dnssec= ignored");
	}
#endif
	config.rootkey_file = config_setup_string(KSF_DNSSEC_ROOTKEY_FILE);
	config.anchors = config_setup_string(KSF_DNSSEC_ANCHORS);
	dnssec = &config;
	return dnssec;
}
