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

#include "ipsecconf/config_setup.h"
#include "ipsecconf/keywords.h"
#include "ipsecconf/confread.h"
#include "ipsecconf/parser.h"
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
#include "timescale.h"

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
	kv->set = k_set;
}

void update_setup_yn(enum config_setup_keyword kw, enum yn_options yn)
{
	config_setup_singleton();
	passert(kw < elemsof(config_setup.values));
	struct keyword_value *kv = &config_setup.values[kw];
	kv->option = yn;
	kv->set = k_set;
}

void update_setup_deltatime(enum config_setup_keyword kw, deltatime_t deltatime)
{
	config_setup_singleton();
	passert(kw < elemsof(config_setup.values));
	struct keyword_value *kv = &config_setup.values[kw];
	kv->deltatime = deltatime;
	kv->set = k_set;
}

void update_setup_option(enum config_setup_keyword kw, uintmax_t option)
{
	config_setup_singleton();
	passert(kw < elemsof(config_setup.values));
	struct keyword_value *kv = &config_setup.values[kw];
	kv->option = option;
	kv->set = k_set;
}

const struct config_setup *config_setup_singleton(void)
{
	if (!config_setup_is_set) {
		config_setup_is_set = true;

		/*
		 * Note: these calls .set=k_set.  The damage is undone
		 * at the end.
		 */

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

		update_setup_yn(KYN_LOGIP, YN_YES);
		update_setup_yn(KYN_LOGTIME, YN_YES);
		update_setup_yn(KYN_LOGAPPEND, YN_YES);
#ifdef USE_LOGFILE
		update_setup_string(KSF_LOGFILE, LOGFILE);
#endif

		update_setup_string(KSF_RUNDIR, IPSEC_RUNDIR);

		update_setup_deltatime(KBF_CRL_TIMEOUT_SECONDS, deltatime(5/*seconds*/));

		/* x509_ocsp */
		update_setup_deltatime(KBF_OCSP_TIMEOUT_SECONDS, deltatime(OCSP_DEFAULT_TIMEOUT));
		update_setup_deltatime(KBF_OCSP_CACHE_MIN_AGE_SECONDS, deltatime(OCSP_DEFAULT_CACHE_MIN_AGE));
		update_setup_deltatime(KBF_OCSP_CACHE_MAX_AGE_SECONDS, deltatime(OCSP_DEFAULT_CACHE_MAX_AGE));
		update_setup_option(KBF_OCSP_METHOD, OCSP_METHOD_GET);
		update_setup_option(KBF_OCSP_CACHE_SIZE, OCSP_DEFAULT_CACHE_SIZE);

		update_setup_yn(KYN_AUDIT_LOG, YN_YES);
		update_setup_yn(KYN_UNIQUEIDS, YN_YES);

		update_setup_deltatime(KSF_EXPIRE_SHUNT_INTERVAL, deltatime(DEFAULT_EXPIRE_SHUNT_INTERVAL_SECONDS));
		update_setup_deltatime(KBF_SHUNTLIFETIME, deltatime(DEFAULT_SHUNT_LIFETIME_SECONDS));

		update_setup_option(KBF_GLOBAL_REDIRECT, GLOBAL_REDIRECT_NO);

		update_setup_yn(KYN_IKE_SOCKET_ERRQUEUE, YN_YES);
		update_setup_option(KBF_IKE_SOCKET_BUFSIZE, 0); /*redundant*/

		update_setup_yn(KYN_LISTEN_UDP, YN_YES);
		update_setup_yn(KYN_LISTEN_TCP, YN_NO);

		update_setup_string(KSF_PROTOSTACK,
#ifdef KERNEL_XFRM
				    "xfrm"
#endif
#ifdef KERNEL_PFKEYV2
				    "pfkeyv2"
#endif
			);

		update_setup_string(KSF_DNS_RESOLVER, "file");

		/*
		 * Clear .set, which is set by update_setup*().  Don't
		 * use k_default as that is intended for 'conn
		 * %default' section and seems to make for general
		 * confusion.
		 */
		FOR_EACH_ELEMENT(kv, config_setup.values) {
			kv->set = k_unset;
		}

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

/**
 * Load a parsed config
 *
 * @param cfg starter_config structure
 * @param cfgp config_parsed (ie: valid) struct
 * @param perr pointer to store errors in
 */

static void llog_bad(struct logger *logger, const struct ipsec_conf_keyval *kv, diag_t d)
{
	llog(ERROR_STREAM, logger,
	     PRI_KEYVAL_SAL": error: %s",
	     pri_keyval_sal(kv), str_diag(d));
}

bool parse_ipsec_conf_config_setup(const struct ipsec_conf *cfgp,
				   struct logger *logger)
{
	config_setup_singleton();

	const struct keyval_entry *kw;

	TAILQ_FOREACH(kw, &cfgp->config_setup, next) {
		/**
		 * the parser already made sure that only config keywords were used,
		 * but we double check!
		 */
		const struct ipsec_conf_keyval *kv = &kw->keyval;
		enum config_setup_keyword f = kv->key->field;
		shunk_t value = shunk1(kv->val);
		diag_t d = NULL;

		PASSERT(logger, f < elemsof(config_setup.values));
		if (config_setup.values[f].set) {
			llog(WARNING_STREAM, logger,
			     PRI_KEYVAL_SAL": overriding earlier 'config setup' keyword with new value: %s=%s",
			     pri_keyval_sal(kv),
			     kv->key->keyname, kv->val);
		}

		switch (kv->key->type) {
		case kt_string:
		{
			/* all treated as strings for now */
			update_setup_string(f, kv->val);
			continue;
		}

		case kt_sparse_name:
		{
			uintmax_t number;
			d = parse_kt_sparse_name(kv, value, &number,
						 ERROR_STREAM, logger);
			if (d != NULL) {
				llog_bad(logger, kv, d);
				pfree_diag(&d);
				return false;
			}

			update_setup_option(f, number);
			continue;
		}

		case kt_unsigned:
		{
			uintmax_t number;
			d = parse_kt_unsigned(kv, value, &number);
			if (d != NULL) {
				llog_bad(logger, kv, d);
				pfree_diag(&d);
				return false;
			}

			update_setup_option(f, number);
			continue;
		}

		case kt_seconds:
		{
			deltatime_t deltatime;
			d = parse_kt_deltatime(kv, value, TIMESCALE_SECONDS, &deltatime);
			if (d != NULL) {
				llog_bad(logger, kv, d);
				pfree_diag(&d);
				return false;
			}

			update_setup_deltatime(f, deltatime);
			continue;
		}

		case kt_obsolete:
		{
			llog(WARNING_STREAM, logger,
			     PRI_KEYVAL_SAL": obsolete keyword ignored: %s=%s",
			     pri_keyval_sal(kv), kv->key->keyname, kv->val);
			continue;
		}

		case kt_also:
		case kt_appendstring:
		case kt_appendlist:
		case kt_nosup:
			break;

		}

		bad_case(kv->key->type);
	}

	return true;
}

bool load_config_setup(const char *file,
		       struct logger *logger,
		       unsigned verbosity)
{

	/*
	 * Load file
	 */
	struct ipsec_conf *ipsec_conf = alloc_ipsec_conf();
	if (!ipsec_conf_add_file(ipsec_conf, file, logger, verbosity)) {
		return false;
	}

	/**
	 * Load setup
	 */
	if (!parse_ipsec_conf_config_setup(ipsec_conf, logger)) {
		pfree_ipsec_conf(&ipsec_conf);
		return false;
	}

	pfree_ipsec_conf(&ipsec_conf);
	return true;
}

static const struct keyword_def config_setup_keyword[] = {
#define K(KEYNAME, TYPE, FIELD, ...) [FIELD] = { .keyname = KEYNAME, .field = FIELD, .type = TYPE, ##__VA_ARGS__ }
#define U(KEYNAME, TYPE, FIELD, ...) [FIELD] = { .keyname = KEYNAME, .field = FIELD, .type = kt_nosup, }

  K("ikev1-policy",  kt_sparse_name,  KBF_IKEv1_POLICY, .sparse_names = &global_ikev1_policy_names),
  K("curl-iface",  kt_string,  KSF_CURLIFACE),

  K("myvendorid",  kt_string,  KSF_MYVENDORID),

  K("plutodebug", kt_string, KSF_PLUTODEBUG),

  K("logfile",  kt_string,  KSF_LOGFILE),
  K("logtime",  kt_sparse_name,  KYN_LOGTIME, .sparse_names = &yn_option_names),
  K("logappend",  kt_sparse_name,  KYN_LOGAPPEND, .sparse_names = &yn_option_names),
  K("logip",  kt_sparse_name,  KYN_LOGIP, .sparse_names = &yn_option_names),
  K("audit-log",  kt_sparse_name,  KYN_AUDIT_LOG, .sparse_names = &yn_option_names),

#ifdef USE_DNSSEC
# define S K
#else
# define S U
#endif
  S("dnssec-enable",  kt_sparse_name,  KYN_DNSSEC_ENABLE, .sparse_names = &yn_option_names),
  S("dnssec-rootkey-file",  kt_string, KSF_DNSSEC_ROOTKEY_FILE),
  S("dnssec-anchors",  kt_string, KSF_DNSSEC_ANCHORS),
#undef S

  K("dumpdir",  kt_string,  KSF_DUMPDIR),
  K("ipsecdir",  kt_string,  KSF_IPSECDIR),
  K("nssdir", kt_string, KSF_NSSDIR),

  /* these are only allowed on the command line */
  K("rundir", kt_string, KSF_RUNDIR, .validity = kv_optarg_only),
  K("logstderr", kt_string, KYN_LOGSTDERR, .validity = kv_optarg_only),

  K("secretsfile",  kt_string,  KSF_SECRETSFILE),
  K("statsbin",  kt_string,  KSF_STATSBIN),
  K("uniqueids",  kt_sparse_name,  KYN_UNIQUEIDS, .sparse_names = &yn_option_names),
  K("shuntlifetime",  kt_seconds,  KBF_SHUNTLIFETIME),

  K("global-redirect", kt_sparse_name, KBF_GLOBAL_REDIRECT, .sparse_names = &global_redirect_names),
  K("global-redirect-to", kt_string, KSF_GLOBAL_REDIRECT_TO),

  K("crl-strict",  kt_sparse_name,  KYN_CRL_STRICT, .sparse_names = &yn_option_names),
  K("crlcheckinterval",  kt_seconds,  KBF_CRL_CHECKINTERVAL),
  K("crl-timeout",  kt_seconds,  KBF_CRL_TIMEOUT_SECONDS),

  K("ocsp-strict",  kt_sparse_name,  KYN_OCSP_STRICT, .sparse_names = &yn_option_names),
  K("ocsp-enable",  kt_sparse_name,  KYN_OCSP_ENABLE, .sparse_names = &yn_option_names),
  K("ocsp-uri",  kt_string,  KSF_OCSP_URI),
  K("ocsp-timeout",  kt_seconds,  KBF_OCSP_TIMEOUT_SECONDS),
  K("ocsp-trustname",  kt_string,  KSF_OCSP_TRUSTNAME),
  K("ocsp-cache-size",  kt_unsigned,  KBF_OCSP_CACHE_SIZE),
  K("ocsp-cache-min-age",  kt_seconds,  KBF_OCSP_CACHE_MIN_AGE_SECONDS),
  K("ocsp-cache-max-age",  kt_seconds,  KBF_OCSP_CACHE_MAX_AGE_SECONDS),
  K("ocsp-method",  kt_sparse_name,  KBF_OCSP_METHOD, .sparse_names = &ocsp_method_names),

#ifdef USE_SECCOMP
# define S K
#else
# define S U
#endif
  S("seccomp",  kt_sparse_name,  KBF_SECCOMP, .sparse_names = &seccomp_mode_names),
#undef S

  K("ddos-mode",  kt_sparse_name,  KBF_DDOS_MODE, .sparse_names = &ddos_mode_names),
  K("ddos-ike-threshold",  kt_unsigned,  KBF_DDOS_IKE_THRESHOLD),
  K("max-halfopen-ike",  kt_unsigned,  KBF_MAX_HALFOPEN_IKE),

  K("ike-socket-bufsize",  kt_unsigned,  KBF_IKE_SOCKET_BUFSIZE),
  K("ike-socket-errqueue",  kt_sparse_name,  KYN_IKE_SOCKET_ERRQUEUE, .sparse_names = &yn_option_names),

#ifdef XFRM_LIFETIME_DEFAULT
# define S K
#else
# define S U
#endif
  S("expire-lifetime",  kt_seconds,  KBF_EXPIRE_LIFETIME),
#undef S

  K("virtual-private",  kt_string,  KSF_VIRTUAL_PRIVATE),
  K("seedbits",  kt_unsigned,  KBF_SEEDBITS),
  K("keep-alive",  kt_seconds,  KBF_KEEP_ALIVE),

  K("listen-tcp", kt_sparse_name, KYN_LISTEN_TCP, .sparse_names = &yn_option_names),
  K("listen-udp", kt_sparse_name, KYN_LISTEN_UDP, .sparse_names = &yn_option_names),

  K("listen",  kt_string,  KSF_LISTEN),
  K("protostack",  kt_string,  KSF_PROTOSTACK),
  K("nhelpers",  kt_unsigned,  KBF_NHELPERS),
  K("drop-oppo-null",  kt_sparse_name,  KYN_DROP_OPPO_NULL, .sparse_names = &yn_option_names),
  K("expire-shunt-interval", kt_seconds, KSF_EXPIRE_SHUNT_INTERVAL),

  K("dns-resolver", kt_string, KSF_DNS_RESOLVER),

  K("ipsec-interface-managed", kt_sparse_name, KYN_IPSEC_INTERFACE_MANAGED, .sparse_names = &yn_option_names),

#ifdef USE_NFLOG
# define S K
#else
# define S U
#endif
  S("nflog-all",  kt_unsigned,  KBF_NFLOG_ALL),
#undef S

  /*
   * Force first alias/obsolete keyword into slot following all
   * defined keywords.  Else compiler tries to store it into above
   * keyword's slot + 1, which is likely occupied by another keyword.
   * The result is a nonsensical error.
   */
  [CONFIG_SETUP_KEYWORD_ROOF] =

  /* alias for compatibility - undocumented on purpose */

#define A(KEYNAME, TYPE, FIELD, ...) { .keyname = KEYNAME, .validity = kv_alias, .type = TYPE, .field = FIELD, ##__VA_ARGS__ }

  A("curl-timeout", kt_seconds, KBF_CRL_TIMEOUT_SECONDS), /* legacy */
#ifdef XFRM_LIFETIME_DEFAULT
  A("xfrmlifetime", kt_seconds, KBF_EXPIRE_LIFETIME), /* legacy */
#endif

  /* obsolete config setup options */

#define O(KEYNAME, ...) { .keyname = KEYNAME, .type = kt_obsolete, }

  O("syslog"), /* never went anywhere! */
  O("plutostderrlog"), /* obsolete name, but very common :/ */
  O("virtual_private"), /* obsolete variant, very common */
  O("interfaces"), /* obsoleted but often present keyword */
  O("ikev1-secctx-attr-type"),  /* obsolete: not a value, a type */
  O("secctx-attr-type"),

#undef U
#undef O
#undef A
#undef K
};

const struct keywords_def config_setup_keywords = {
	.len = elemsof(config_setup_keyword),
	.item = config_setup_keyword,
};
