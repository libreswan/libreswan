/* ipsec.conf's config setup for Libreswan
 *
 * Copyright (C) 2025 Andrew Cagney
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

#include <stdbool.h>

#include "config_setup.h"

#include "ipsecconf/confread.h"
#include "passert.h"
#include "lswalloc.h"
#include "lset.h"
#include "lmod.h"
#include "lswlog.h"
#include "lswversion.h"

/**
 * Set up hardcoded defaults, from data in programs/pluto/constants.h
 *
 * @param cfg starter_config struct
 * @return void
 */

static bool config_setup_is_set;
static struct config_setup config_setup;

void config_setup_string(enum keywords kw, const char *string)
{
	config_setup_singleton();
	passert(kw < elemsof(config_setup.values));
	struct keyword_value *kv = &config_setup.values[kw];
	pfreeany(kv->string);
	kv->string = clone_str(string, "kv");
}

void config_setup_option(enum keywords kw, uintmax_t option)
{
	config_setup_singleton();
	passert(kw < elemsof(config_setup.values));
	struct keyword_value *kv = &config_setup.values[kw];
	kv->option = option;
}

struct config_setup *config_setup_singleton(void)
{
	if (!config_setup_is_set) {
		config_setup_is_set = true;

		config_setup_option(KBF_IKEBUF, IKE_BUF_AUTO);
		config_setup_option(KBF_NHELPERS, -1);
		config_setup_option(KBF_DDOS_IKE_THRESHOLD, DEFAULT_IKE_SA_DDOS_THRESHOLD);
		config_setup_option(KBF_MAX_HALFOPEN_IKE, DEFAULT_MAXIMUM_HALFOPEN_IKE_SA);
		config_setup_option(KBF_GLOBAL_IKEv1, GLOBAL_IKEv1_DROP);
		config_setup_option(KBF_DDOS_MODE, DDOS_AUTO);
		config_setup_option(KBF_OCSP_CACHE_SIZE, OCSP_DEFAULT_CACHE_SIZE);
		config_setup_option(KBF_SECCOMP, SECCOMP_DISABLED);

		config_setup_string(KSF_NSSDIR, IPSEC_NSSDIR);
		config_setup_string(KSF_SECRETSFILE, IPSEC_SECRETS);
		config_setup_string(KSF_DUMPDIR, IPSEC_RUNDIR);
		config_setup_string(KSF_IPSECDIR, IPSEC_CONFDDIR);
		config_setup_string(KSF_MYVENDORID, ipsec_version_vendorid());
	}
	return &config_setup;
}

void free_config_setup(void)
{
	for (unsigned i = 0; i < elemsof(config_setup.values); i++) {
		pfreeany(config_setup.values[i].string);
	}
	config_setup_is_set = false;
}

const char *config_setup_ipsecdir(void)
{
	config_setup_singleton();
	return config_setup.values[KSF_IPSECDIR].string;
}

const char *config_setup_secretsfile(void)
{
	config_setup_singleton();
	return config_setup.values[KSF_SECRETSFILE].string;
}

const char *config_setup_nssdir(void)
{
	config_setup_singleton();
	return config_setup.values[KSF_NSSDIR].string;
}

const char *config_setup_dumpdir(void)
{
	config_setup_singleton();
	return config_setup.values[KSF_DUMPDIR].string;
}

const char *config_setup_vendorid(void)
{
	config_setup_singleton();
	return config_setup.values[KSF_MYVENDORID].string;
}

lset_t config_setup_debugging(struct logger *logger)
{
	config_setup_singleton();
	/*
	 * Use ttolmod() since it both knows how to parse a comma
	 * separated list and can handle no-XXX (ex: all,no-xauth).
	 * The final set of enabled bits is returned in .set.
	 */
	lmod_t result = {0};
	const char *plutodebug = config_setup.values[KSF_PLUTODEBUG].string;
	if (!ttolmod(shunk1(plutodebug), &result, &debug_lmod_info, true/*enable*/)) {
		/*
		 * If the lookup failed, complain.
		 *
		 * XXX: the error diagnostic is a little vague -
		 * should lmod_arg() instead return the error?
		 */
		llog(RC_LOG, logger, "plutodebug='%s' invalid, keyword ignored",
			plutodebug);
		return LEMPTY;
	}

	return result.set;
}
