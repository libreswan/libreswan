/* ipsec.conf's config setup for Libreswan
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

#ifndef CONFIG_SETUP_H
#define CONFIG_SETUP_H

#include <stdint.h>

#include "lset.h"
#include "deltatime.h"

enum yn_options;
struct logger;
struct ipsec_conf;

enum config_setup_keyword {
	/* zero is reserved */

#define CONFIG_SETUP_KEYWORD_FLOOR KSF_CURLIFACE

	/*
	 * By convention, these are global configuration strings and
	 * only appear in the "config setup" section (KSF == Keyword
	 * String Flag?).
	 */
	KSF_CURLIFACE = 1,
	KSF_VIRTUAL_PRIVATE,
	KSF_SYSLOG,
	KSF_DUMPDIR,
	KSF_STATSBIN,
	KSF_IPSECDIR,
	KSF_NSSDIR,
	KSF_SECRETSFILE,
	KSF_MYVENDORID,
	KSF_LOGFILE,
	KSF_RUNDIR,		/* placeholder, no option */
	KSF_DNSSEC_ROOTKEY_FILE,
	KSF_DNSSEC_ANCHORS,
	KYN_DNSSEC_ENABLE,
	KSF_PROTOSTACK,
	KBF_GLOBAL_REDIRECT,
	KSF_GLOBAL_REDIRECT_TO,
	KSF_OCSP_URI,
	KSF_OCSP_TRUSTNAME,
	KSF_EXPIRE_SHUNT_INTERVAL,

	/*
	 * By convention, these are global configuration numeric (and
	 * boolean) values and only appear in the "config setup"
	 * section (KBF == Keyword Boolean Flag?).
	 *
	 * KYN implies yn_options.
	 */
	KYN_UNIQUEIDS,
	KYN_LOGTIME,
	KYN_LOGAPPEND,
	KYN_LOGIP,
	KYN_LOGSTDERR, /*no matching option*/
	KYN_AUDIT_LOG,
	KBF_IKE_SOCKET_BUFSIZE,
	KYN_IKE_SOCKET_ERRQUEUE,
	KBF_EXPIRE_LIFETIME,
	KYN_CRL_STRICT,
	KBF_CRL_CHECKINTERVAL,
	KBF_CRL_TIMEOUT_SECONDS,
	KYN_OCSP_STRICT,
	KYN_OCSP_ENABLE,
	KBF_OCSP_TIMEOUT_SECONDS,
	KBF_OCSP_CACHE_SIZE,
	KBF_OCSP_CACHE_MIN_AGE_SECONDS,
	KBF_OCSP_CACHE_MAX_AGE_SECONDS,
	KBF_OCSP_METHOD,
	KBF_SEEDBITS,
	KYN_DROP_OPPO_NULL,
	KBF_KEEP_ALIVE,
	KBF_NHELPERS,
	KBF_SHUNTLIFETIME,
	KBF_DDOS_IKE_THRESHOLD,
	KBF_MAX_HALFOPEN_IKE,
	KBF_NFLOG_ALL,		/* Enable global nflog device */
	KBF_DDOS_MODE,		/* set DDOS mode */
	KBF_SECCOMP,		/* set SECCOMP mode */

	KSF_LISTEN,		/* address(s) to listen on */
	KYN_LISTEN_TCP,		/* listen on TCP port 4500 - default no */
	KYN_LISTEN_UDP,		/* listen on UDP port 500/4500 - default yes */

	KBF_IKEv1_POLICY,	/* global ikev1 policy - default drop */
	KSF_PLUTODEBUG,
	KYN_IPSEC_INTERFACE_MANAGED,

#define CONFIG_SETUP_KEYWORD_ROOF (KYN_IPSEC_INTERFACE_MANAGED+1)
};

bool load_config_setup(const char *file,
		       struct logger *logger,
		       unsigned verbosity);
bool parse_ipsec_conf_config_setup(const struct ipsec_conf *cfgp,
				   struct logger *logger);

struct config_setup *config_setup_singleton(void);
void free_config_setup(void);

void update_setup_string(enum config_setup_keyword kw, const char *string);
void update_setup_yn(enum config_setup_keyword kw, enum yn_options yn);
void update_setup_deltatime(enum config_setup_keyword kw, deltatime_t deltatime);
void update_setup_option(enum config_setup_keyword kw, uintmax_t option);

const char *config_setup_string(const struct config_setup *setup, enum config_setup_keyword field);
const char *config_setup_string_or_unset(const struct config_setup *setup, enum config_setup_keyword field, const char *unset);
bool config_setup_yn(const struct config_setup *setup, enum config_setup_keyword field);
deltatime_t config_setup_deltatime(const struct config_setup *setup, enum config_setup_keyword field);
uintmax_t config_setup_option(const struct config_setup *setup, enum config_setup_keyword field);

const char *config_setup_ipsecdir(void);
const char *config_setup_secretsfile(void);
const char *config_setup_nssdir(void);
const char *config_setup_dumpdir(void);
const char *config_setup_vendorid(void);
lset_t config_setup_debugging(struct logger *logger);

#endif
