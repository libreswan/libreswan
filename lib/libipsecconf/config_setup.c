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
#include "ocsp_method.h"
#include "global_redirect.h"
#ifdef USE_SECCOMP
#include "seccomp_mode.h"
#endif
#include "ddos_mode.h"

/**
 * Set up hardcoded defaults, from data in programs/pluto/constants.h
 *
 * @param cfg starter_config struct
 * @return void
 */

static bool config_setup_is_set;
static struct config_setup config_setup;

void update_setup_string(enum config_setup_keyword kw, const char *string)
{
	config_setup_singleton();
	passert(kw < elemsof(config_setup.values));
	struct keyword_value *kv = &config_setup.values[kw];
	pfreeany(kv->string);
	kv->string = clone_str(string, "kv");
}

void update_setup_yn(enum config_setup_keyword kw, enum yn_options yn)
{
	config_setup_singleton();
	passert(kw < elemsof(config_setup.values));
	struct keyword_value *kv = &config_setup.values[kw];
	kv->option = yn;
}

void update_setup_deltatime(enum config_setup_keyword kw, deltatime_t deltatime)
{
	config_setup_singleton();
	passert(kw < elemsof(config_setup.values));
	struct keyword_value *kv = &config_setup.values[kw];
	kv->deltatime = deltatime;
}

void update_setup_option(enum config_setup_keyword kw, uintmax_t option)
{
	config_setup_singleton();
	passert(kw < elemsof(config_setup.values));
	struct keyword_value *kv = &config_setup.values[kw];
	kv->option = option;
	kv->set = true;
}

struct config_setup *config_setup_singleton(void)
{
	if (!config_setup_is_set) {
		config_setup_is_set = true;

		update_setup_option(KBF_NHELPERS, -1);

		update_setup_option(KBF_DDOS_MODE, DDOS_AUTO);
		update_setup_option(KBF_DDOS_IKE_THRESHOLD, DEFAULT_IKE_SA_DDOS_THRESHOLD);
		update_setup_option(KBF_MAX_HALFOPEN_IKE, DEFAULT_MAXIMUM_HALFOPEN_IKE_SA);

		update_setup_option(KBF_IKEv1_POLICY, GLOBAL_IKEv1_DROP);
		update_setup_option(KBF_OCSP_CACHE_SIZE, OCSP_DEFAULT_CACHE_SIZE);
#ifdef USE_SECCOMP
		update_setup_option(KBF_SECCOMP, SECCOMP_DISABLED);
#endif

		update_setup_string(KSF_NSSDIR, IPSEC_NSSDIR);
		update_setup_string(KSF_SECRETSFILE, IPSEC_SECRETS);
		update_setup_string(KSF_DUMPDIR, IPSEC_RUNDIR);
		update_setup_string(KSF_IPSECDIR, IPSEC_CONFDDIR);
		update_setup_string(KSF_MYVENDORID, ipsec_version_vendorid());

		update_setup_string(KSF_DNSSEC_ROOTKEY_FILE, DEFAULT_DNSSEC_ROOTKEY_FILE);
		update_setup_yn(KYN_DNSSEC_ENABLE, YN_YES);

		update_setup_yn(KYN_LOGTIME, YN_YES);
		update_setup_yn(KYN_LOGAPPEND, YN_YES);

		update_setup_string(KSF_RUNDIR, IPSEC_RUNDIR);

		update_setup_deltatime(KBF_CRL_TIMEOUT_SECONDS, deltatime(5/*seconds*/));

		/* x509_ocsp */
		update_setup_deltatime(KBF_OCSP_TIMEOUT_SECONDS, deltatime(OCSP_DEFAULT_TIMEOUT));
		update_setup_deltatime(KBF_OCSP_CACHE_MIN_AGE_SECONDS, deltatime(OCSP_DEFAULT_CACHE_MIN_AGE));
		update_setup_deltatime(KBF_OCSP_CACHE_MAX_AGE_SECONDS, deltatime(OCSP_DEFAULT_CACHE_MAX_AGE));
		update_setup_option(KBF_OCSP_METHOD, OCSP_METHOD_GET);
		update_setup_option(KBF_OCSP_CACHE_SIZE, OCSP_DEFAULT_CACHE_SIZE);

		update_setup_yn(KYN_LOGIP, YN_YES);
		update_setup_yn(KYN_AUDIT_LOG, YN_YES);
		update_setup_yn(KYN_UNIQUEIDS, YN_YES);

		update_setup_deltatime(KSF_EXPIRE_SHUNT_INTERVAL, deltatime(DEFAULT_EXPIRE_SHUNT_INTERVAL_SECONDS));
		update_setup_deltatime(KBF_SHUNTLIFETIME, deltatime(DEFAULT_SHUNT_LIFETIME_SECONDS));

		update_setup_option(KBF_GLOBAL_REDIRECT, GLOBAL_REDIRECT_NO);

		update_setup_yn(KYN_IKE_SOCKET_ERRQUEUE, YN_YES);
		update_setup_option(KBF_IKE_SOCKET_BUFSIZE, 0); /*redundant*/

		update_setup_yn(KYN_LISTEN_UDP, YN_YES);
		update_setup_yn(KYN_LISTEN_TCP, YN_NO);
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

const char *config_setup_string(const struct config_setup *setup,
				enum config_setup_keyword field)
{
	passert(field < elemsof(setup->values));
	return setup->values[field].string;
}

const char *config_setup_string_or_unset(const struct config_setup *setup,
					 enum config_setup_keyword field,
					 const char *unset)
{
	const char *string = config_setup_string(setup, field);
	if (string == NULL) {
		return unset;
	}
	return string;
}

bool config_setup_yn(const struct config_setup *setup,
		     enum config_setup_keyword field)
{
	passert(field < elemsof(setup->values));
	enum yn_options yn = setup->values[field].option;
	switch (yn) {
	case 0: return false;
	case YN_NO: return false;
	case YN_YES: return true;
	}
	bad_case(yn);
}

deltatime_t config_setup_deltatime(const struct config_setup *setup,
				   enum config_setup_keyword field)
{
	passert(field < elemsof(setup->values));
	return setup->values[field].deltatime;
}

uintmax_t config_setup_option(const struct config_setup *setup,
			      enum config_setup_keyword field)
{
	passert(field < elemsof(setup->values));
	/* being .set doesn't matter, as default is zero */
	return setup->values[field].option;
}

const char *config_setup_ipsecdir(void)
{
	return config_setup_string(config_setup_singleton(), KSF_IPSECDIR);
}

const char *config_setup_secretsfile(void)
{
	return config_setup_string(config_setup_singleton(), KSF_SECRETSFILE);
}

const char *config_setup_nssdir(void)
{
	return config_setup_string(config_setup_singleton(), KSF_NSSDIR);
}

const char *config_setup_dumpdir(void)
{
	return config_setup_string(config_setup_singleton(), KSF_DUMPDIR);
}

const char *config_setup_vendorid(void)
{
	return config_setup_string(config_setup_singleton(), KSF_MYVENDORID);
}

lset_t config_setup_debugging(struct logger *logger)
{
	/*
	 * Use ttolmod() since it both knows how to parse a comma
	 * separated list and can handle no-XXX (ex: all,no-xauth).
	 * The final set of enabled bits is returned in .set.
	 */
	lmod_t result = {0};
	const char *plutodebug = config_setup_string(config_setup_singleton(), KSF_PLUTODEBUG);
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

bool load_config_setup(const char *file,
		       struct logger *logger,
		       unsigned verbosity)
{
	struct starter_config *cfg =
		confread_load(file, /*config-setup-only*/true,
			      logger, verbosity);
	bool ok = (cfg != NULL);
	confread_free(cfg);
	return ok;
}
