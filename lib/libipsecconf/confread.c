/* Libreswan config file parser (confread.c)
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2004 Xelerance Corporation
 * Copyright (C) 2006-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007 Ken Bantoft <ken@xelerance.com>
 * Copyright (C) 2006-2012 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010 Michael Smith <msmith@cbnco.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Antony Antony <antony@phenome.org>
 * Copyright (C) 2013 Florian Weimer <fweimer@redhat.com>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017-2018 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
 * Copyright (C) 2020 Yulia Kuzovkova <ukuzovkova@gmail.com>
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

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>		/* for AF_UNSPEC */

#include "lswalloc.h"
#include "ip_address.h"
#include "ip_info.h"
#include "hunk.h"		/* for char_is_space() */
#include "ip_cidr.h"
#include "ttodata.h"

#include "ipsecconf/confread.h"
#include "ipsecconf/interfaces.h"

#include "ipsecconf/keywords.h"
#include "ipsecconf/parser.h"	/* includes parser.tab.h generated by bison; requires keywords.h */

#include "whack.h" /* for DEFAULT_CTL_SOCKET */
#include "lswlog.h"

static bool translate_conn(struct starter_conn *conn,
			   const struct config_parsed *cfgp,
			   struct section_list *sl,
			   enum keyword_set assigned_value,
			   struct logger *logger);

/**
 * Set up hardcoded defaults, from data in programs/pluto/constants.h
 *
 * @param cfg starter_config struct
 * @return void
 */
static void ipsecconf_default_values(struct starter_config *cfg)
{
	static const struct starter_config empty_starter_config;	/* zero or null everywhere */
	*cfg = empty_starter_config;

	TAILQ_INIT(&cfg->conns);

	/* ==== config setup ==== */

# define SOPT(kbf, v)  { cfg->values[kbf].option = (v) ; }

	SOPT(KBF_LOGTIME, true);
	SOPT(KBF_LOGAPPEND, true);
	SOPT(KBF_LOGIP, true);
	SOPT(KBF_AUDIT_LOG, true);
	SOPT(KBF_UNIQUEIDS, true);
	SOPT(KBF_LISTEN_UDP, true);
	SOPT(KBF_DO_DNSSEC, true);
	SOPT(KBF_IKEBUF, IKE_BUF_AUTO);
	SOPT(KBF_IKE_ERRQUEUE, true);
#ifdef XFRM_LIFETIME_DEFAULT
	SOPT(KBF_XFRMLIFETIME, XFRM_LIFETIME_DEFAULT); /* not used by pluto itself */
#endif
	SOPT(KBF_NHELPERS, -1); /* see also plutomain.c */

	SOPT(KBF_DDOS_IKE_THRESHOLD, DEFAULT_IKE_SA_DDOS_THRESHOLD);
	SOPT(KBF_MAX_HALFOPEN_IKE, DEFAULT_MAXIMUM_HALFOPEN_IKE_SA);
	/* Don't inflict BSI requirements on everyone */
	SOPT(KBF_GLOBAL_IKEv1, GLOBAL_IKEv1_DROP);

	SOPT(KBF_DDOS_MODE, DDOS_AUTO);

	SOPT(KBF_OCSP_CACHE_SIZE, OCSP_DEFAULT_CACHE_SIZE);

	SOPT(KBF_SECCOMP, SECCOMP_DISABLED); /* will be enabled in the future */

# undef SOPT

	cfg->values[KSF_PLUTO_DNSSEC_ROOTKEY_FILE].string = clone_str(DEFAULT_DNSSEC_ROOTKEY_FILE, "default dnssec rootkey file");
	cfg->values[KSF_NSSDIR].string = clone_str(IPSEC_NSSDIR, "default ipsec nssdir");
	cfg->values[KSF_SECRETSFILE].string = clone_str(IPSEC_SECRETS, "default ipsec.secrets file");
	cfg->values[KSF_DUMPDIR].string = clone_str(IPSEC_RUNDIR, "default dumpdir");
	cfg->values[KSF_IPSECDIR].string = clone_str(IPSEC_CONFDDIR, "default ipsec.d dir");

	/* ==== end of config setup ==== */

	/* ==== conn %default ==== */

	struct starter_conn *d = &cfg->conn_default;

# define DOPT(kbf, v)  { d->values[kbf].option = (v); }

	DOPT(KNCF_NAT_KEEPALIVE, true);    /* per conn */
	DOPT(KNCF_TYPE, KS_TUNNEL);

	DOPT(KNCF_INITIAL_CONTACT, true);

	DOPT(KNCF_XAUTHBY, XAUTHBY_FILE);
	DOPT(KNCF_XAUTHFAIL, XAUTHFAIL_HARD);

	DOPT(KNCF_REPLAY_WINDOW, IPSEC_SA_DEFAULT_REPLAY_WINDOW);

	DOPT(KNCF_IPSEC_MAXBYTES, IPSEC_SA_MAX_OPERATIONS);
	DOPT(KNCF_IPSEC_MAXPACKETS, IPSEC_SA_MAX_OPERATIONS);
	DOPT(KNCF_REKEYFUZZ, SA_REPLACEMENT_FUZZ_DEFAULT);

	DOPT(KNCF_HOSTADDRFAMILY, AF_UNSPEC);
	DOPT(KNCF_CLIENTADDRFAMILY, AF_UNSPEC);

	DOPT(KNCF_AUTO, AUTOSTART_IGNORE);

# undef DOPT

	d->ike_version = IKEv2;
	d->authby = AUTHBY_NONE; /* blank goes to defaults */
	d->never_negotiate_shunt = SHUNT_UNSET;
	d->negotiation_shunt = SHUNT_UNSET;
	d->failure_shunt = SHUNT_UNSET;

	d->sighash_policy = POL_SIGHASH_DEFAULTS;

	d->end[LEFT_END].leftright = "left";
	d->end[LEFT_END].host_family = NULL;
	d->end[LEFT_END].addr = unset_address;
	d->end[LEFT_END].nexttype = KH_NOTSET;
	d->end[LEFT_END].nexthop = unset_address;

	d->end[RIGHT_END].leftright = "right";
	d->end[RIGHT_END].host_family = NULL;
	d->end[RIGHT_END].addr = unset_address;
	d->end[RIGHT_END].nexttype = KH_NOTSET;
	d->end[RIGHT_END].nexthop = unset_address;

	d->xfrm_if_id = UINT32_MAX;

	d->state = STATE_LOADED;
	/* ==== end of conn %default ==== */
}

/**
 * Load a parsed config
 *
 * @param cfg starter_config structure
 * @param cfgp config_parsed (ie: valid) struct
 * @param perr pointer to store errors in
 */
static bool load_setup(struct starter_config *cfg,
		       const struct config_parsed *cfgp)
{
	bool ok = true;
	const struct kw_list *kw;

	for (kw = cfgp->config_setup; kw != NULL; kw = kw->next) {
		/**
		 * the parser already made sure that only config keywords were used,
		 * but we double check!
		 */
		assert(kw->keyword.keydef->validity & kv_config);
		unsigned f = kw->keyword.keydef->field;

		switch (kw->keyword.keydef->type) {
		case kt_string:
		case kt_filename:
		case kt_dirname:
		case kt_host:
			/* all treated as strings for now */
			assert(f < elemsof(cfg->values));
			pfreeany(cfg->values[f].string);
			cfg->values[f].string =
				clone_str(kw->string, "kt_loose_enum kw->string");
			cfg->values[f].set = true;
			break;

		case kt_lset:
		case kt_bool:
		case kt_sparse_name:
		case kt_unsigned:
		case kt_percent:
		case kt_binary:
		case kt_byte:
			/* all treated as a number for now */
			assert(f < elemsof(cfg->values));
			cfg->values[f].option = kw->number;
			cfg->values[f].set = true;
			break;

		case kt_seconds:
		case kt_milliseconds:
			/* all treated as a number for now */
			assert(f < elemsof(cfg->values));
			cfg->values[f].deltatime = kw->deltatime;
			cfg->values[f].set = true;
			break;

		case kt_bitstring:
		case kt_pubkey:
		case kt_ipaddr:
		case kt_subnet:
		case kt_range:
		case kt_idtype:
			ok = false;
			break;

		case kt_also:
		case kt_appendstring:
		case kt_appendlist:
		case kt_obsolete:
			break;

		}
	}

	return ok;
}

/**
 * Validate that yes in fact we are one side of the tunnel
 *
 * The function checks that IP addresses are valid, nexthops are
 * present (if needed) as well as policies, and sets the leftID from
 * the left= if it isn't set.
 *
 * @param conn_st a connection definition
 * @param end a connection end
 * @param leftright const char * "left" or "right"
 * @param perrl pointer to starter_errors_t
 * @return bool TRUE if failed
 */

static bool validate_end(struct starter_conn *conn_st,
			 struct starter_end *end,
			 struct logger *logger)
{
	bool ok = true;
	const char *leftright = end->leftright;

	passert(end->host_family != NULL);
	pexpect(end->host_family == &ipv4_info ||
		end->host_family == &ipv6_info); /* i.e., not NULL */

#  define ERR_FOUND(...) { llog(RC_LOG, logger, __VA_ARGS__); ok = false; }

	if (!end->values[KW_IP].set)
		conn_st->state = STATE_INCOMPLETE;

	/* validate the KSCF_IP/KNCF_IP */
	end->addrtype = end->values[KW_IP].option;
	switch (end->addrtype) {
	case KH_ANY:
		end->addr = unset_address;
		break;

	case KH_IFACE:
		/* generally, this doesn't show up at this stage */
		ldbg(logger, "starter: %s is KH_IFACE", leftright);
		break;

	case KH_IPADDR:
		assert(end->values[KW_IP].string != NULL);

		if (end->values[KW_IP].string[0] == '%') {
			const char *iface = end->values[KW_IP].string + 1;
			if (!starter_iface_find(iface,
						end->host_family,
						&end->addr,
						&end->nexthop))
				conn_st->state = STATE_INVALID;
			/* not numeric, so set the type to the iface type */
			end->addrtype = KH_IFACE;
			break;
		}

		err_t er = ttoaddress_num(shunk1(end->values[KW_IP].string),
					  end->host_family, &end->addr);
		if (er != NULL) {
			/* not an IP address, so set the type to the string */
			end->addrtype = KH_IPHOSTNAME;
		} else {
			pexpect(end->host_family == address_info(end->addr));
		}

		break;

	case KH_OPPO:
	case KH_OPPOGROUP:
	case KH_GROUP:
		/* handled by pluto using .host_type */
		break;

	case KH_IPHOSTNAME:
		/* generally, this doesn't show up at this stage */
		ldbg(logger, "starter: %s is KH_IPHOSTNAME", leftright);
		break;

	case KH_DEFAULTROUTE:
		ldbg(logger, "starter: %s is KH_DEFAULTROUTE", leftright);
		break;

	case KH_NOTSET:
		/* cannot error out here, it might be a partial also= conn */
		break;
	}

	/*
	 * validate the KSCF_NEXTHOP; set nexthop address to
	 * something consistent, by default
	 */
	end->nexthop = end->host_family->address.unspec;
	if (end->values[KW_NEXTHOP].set) {
		char *value = end->values[KW_NEXTHOP].string;
		if (strcaseeq(value, "%defaultroute")) {
			end->nexttype = KH_DEFAULTROUTE;
		} else {
			err_t e = ttoaddress_num(shunk1(value),
						 end->host_family,
						 &end->nexthop);
			if (e != NULL) {
				ERR_FOUND("bad value for %snexthop=%s [%s]",
					  leftright, value, e);
			}
			end->nexttype = KH_IPADDR;
		}
	} else {
		end->nexthop = end->host_family->address.unspec;

		if (end->addrtype == KH_DEFAULTROUTE) {
			end->nexttype = KH_DEFAULTROUTE;
		}
	}

	return ok;
#  undef ERR_FOUND
}

/**
 * Take keywords from ipsec.conf syntax and load into a conn struct
 *
 * @param conn a connection definition
 * @param sl a section_list
 * @param assigned_value is set to either k_set, or k_default.
 *        k_default is used when we are loading a conn that should be
 *        considered to be a "default" value, and that replacing this
 *        value is considered acceptable.
 * @return bool TRUE if unsuccessful
 */

static bool translate_field(struct starter_conn *conn,
			    const struct config_parsed *cfgp,
			    const struct section_list *sl,
			    enum keyword_set assigned_value,
			    const struct kw_list *kw,
			    const char *leftright,
			    keyword_values values,
			    struct logger *logger)
{
	bool ok = true;

	unsigned int field = kw->keyword.keydef->field;

	assert(kw->keyword.keydef != NULL);

	switch (kw->keyword.keydef->type) {
	case kt_also:
	{
		struct section_list *addin;
		const char *seeking = kw->string;
		for (addin = TAILQ_FIRST(&cfgp->sections);
		     addin != NULL && !streq(seeking, addin->name);
		     addin = TAILQ_NEXT(addin, link))
			;
		if (addin == NULL) {
			llog(RC_LOG, logger,
			     "cannot find conn '%s' needed by conn '%s'",
			     seeking, conn->name);
			ok = false;
			break;
		}
		/* translate things, but do not replace earlier settings! */
		ok &= translate_conn(conn, cfgp, addin, k_set, logger);
		break;
	}
	case kt_string:
	case kt_filename:
	case kt_dirname:
	case kt_bitstring:
	case kt_ipaddr:
	case kt_range:
	case kt_subnet:
	case kt_idtype:
		/* all treated as strings for now, even loose enums */
		if (values[field].set == k_set) {
			llog(RC_LOG, logger,
			     "duplicate key '%s%s' in conn %s while processing def %s",
			     leftright, kw->keyword.keydef->keyname,
			     conn->name,
			     sl->name);

			/* only fatal if we try to change values */
			if (kw->keyword.string == NULL ||
			    values[field].string == NULL ||
			    !streq(kw->keyword.string,
				   values[field].string))
			{
				ok = false;
				break;
			}
		}
		pfreeany(values[field].string);

		if (kw->string == NULL) {
			llog(RC_LOG, logger, "invalid %s value",
			     kw->keyword.keydef->keyname);
			ok = false;
			break;
		}

		values[field].string = clone_str(kw->string, "kt_idtype kw->string");
		values[field].set = assigned_value;
		break;

	case kt_appendstring:
	case kt_appendlist:
		/* implicitly, this field can have multiple values */
		if (values[field].string == NULL) {
			values[field].string = clone_str(kw->string, "kt_appendlist kw->string");
		} else {
			char *s = values[field].string;
			size_t old_len = strlen(s);	/* excludes '\0' */
			size_t new_len = strlen(kw->string);
			char *n = alloc_bytes(old_len + 1 + new_len + 1, "kt_appendlist");

			memcpy(n, s, old_len);
			n[old_len] = ' ';
			memcpy(n + old_len + 1, kw->string, new_len + 1);	/* includes '\0' */
			values[field].string = n;
			pfree(s);
		}
		values[field].set = true;
		break;

	case kt_pubkey:
	case kt_host:
		if (values[field].set == k_set) {
			llog(RC_LOG, logger,
			     "duplicate key '%s%s' in conn %s while processing def %s",
			     leftright, kw->keyword.keydef->keyname,
			     conn->name,
			     sl->name);

			/* only fatal if we try to change values */
			if (values[field].option != (int)kw->number ||
			    !(values[field].option ==
			      LOOSE_ENUM_OTHER &&
			      kw->number == LOOSE_ENUM_OTHER &&
			      kw->keyword.string != NULL &&
			      values[field].string != NULL &&
			      streq(kw->keyword.string,
				    values[field].string)))
			{
				ok = false;
				break;
			}
		}

		values[field].option = kw->number;
		if (kw->number == LOOSE_ENUM_OTHER) {
			assert(kw->string != NULL);
			pfreeany(values[field].string);
			values[field].string = clone_str(
				kw->string, "kt_loose_enum kw->keyword.string");
		}
		values[field].set = assigned_value;
		break;

	case kt_lset:
	case kt_bool:
	case kt_sparse_name:
	case kt_unsigned:
	case kt_percent:
	case kt_binary:
	case kt_byte:
		/* all treated as a number for now */
		if (values[field].set == k_set) {
			llog(RC_LOG, logger,
			     "duplicate key '%s%s' in conn %s while processing def %s",
			     leftright, kw->keyword.keydef->keyname,
			     conn->name,
			     sl->name);

			/* only fatal if we try to change values */
			if (values[field].option != (int)kw->number) {
				ok = false;
				break;
			}
		}

		values[field].option = kw->number;
		values[field].set = assigned_value;
		break;

	case kt_seconds:
	case kt_milliseconds:
		/* all treated as a number for now */
		if (values[field].set == k_set) {
			llog(RC_LOG, logger,
			     "duplicate key '%s%s' in conn %s while processing def %s",
			     leftright, kw->keyword.keydef->keyname,
			     conn->name,
			     sl->name);

			/* only fatal if we try to change values */
			if (deltatime_cmp(values[field].deltatime, !=, kw->deltatime)) {
				ok = false;
				break;
			}
		}

		values[field].deltatime = kw->deltatime;
		values[field].set = assigned_value;
		break;

	case kt_obsolete:
		break;
	}

	return ok;
}

static bool translate_leftright(struct starter_conn *conn,
				const struct config_parsed *cfgp,
				const struct section_list *sl,
				enum keyword_set assigned_value,
				const struct kw_list *kw,
				struct starter_end *this,
				struct logger *logger)
{
	return translate_field(conn, cfgp, sl, assigned_value, kw,
			       /*leftright*/this->leftright,
			       this->values,
			       logger);
}

static bool translate_conn(struct starter_conn *conn,
			   const struct config_parsed *cfgp,
			   struct section_list *sl,
			   enum keyword_set assigned_value,
			   struct logger *logger)
{
	if (sl->beenhere) {
		ldbg(logger, "ignore duplicate include");
		return true; /* ok */
	}

	sl->beenhere = true;

	/*
	 * Note: not all errors are considered serious (see above).
	 */
	bool ok = true;

	for (const struct kw_list *kw = sl->kw; kw != NULL; kw = kw->next) {
		if (kw->keyword.keydef->validity & kv_leftright) {
			if (kw->keyword.keyleft) {
				ok &= translate_leftright(conn, cfgp, sl, assigned_value,
							  kw, &conn->end[LEFT_END],
							  logger);
			}
			if (kw->keyword.keyright) {
				ok &= translate_leftright(conn, cfgp, sl, assigned_value,
							  kw, &conn->end[RIGHT_END],
							  logger);
			}
		} else {
			ok &= translate_field(conn, cfgp, sl, assigned_value, kw,
					      /*leftright*/"",
					      conn->values,
					      logger);
		}
	}

	return ok;
}

static bool load_conn(struct starter_conn *conn,
		      const struct config_parsed *cfgp,
		      struct section_list *sl,
		      bool alsoprocessing,
		      bool defaultconn,
		      struct logger *logger)
{
	/* reset all of the "beenhere" flags */
	for (struct section_list *s = TAILQ_FIRST(&cfgp->sections);
	     s != NULL; s = TAILQ_NEXT(s, link)) {
		s->beenhere = false;
	}

	/*
	 * Turn all of the keyword/value pairs into options/strings in
	 * left/right.
	 *
	 * DANGER: returns false on success.
	 */
	if (!translate_conn(conn, cfgp, sl,
			    defaultconn ? k_default : k_set,
			    logger)) {
		return false;
	}

	if (conn->values[KSCF_ALSO].string != NULL &&
	    !alsoprocessing) {
		llog(RC_LOG, logger, "also= is not valid in section '%s'",
		     sl->name);
		return false;	/* error */
	}

	if (conn->values[KNCF_TYPE].set) {
		switch ((enum type_options)conn->values[KNCF_TYPE].option) {
		case KS_UNSET:
			bad_case(KS_UNSET);

		case KS_TUNNEL:
			break;

		case KS_TRANSPORT:
			break;

		case KS_PASSTHROUGH:
			conn->authby = AUTHBY_NONE;
			conn->never_negotiate_shunt = SHUNT_PASS;
			break;

		case KS_DROP:
			conn->authby = AUTHBY_NONE;
			conn->never_negotiate_shunt = SHUNT_DROP;
			break;

		case KS_REJECT:
			llog(RC_LOG, logger, "warning: type=%%reject implemented as type=%%drop");
			conn->authby = AUTHBY_NONE;
			conn->never_negotiate_shunt = SHUNT_DROP;
			break;
		}
	}

	conn->negotiation_shunt = conn->values[KNCF_NEGOTIATIONSHUNT].option;
	conn->failure_shunt = conn->values[KNCF_FAILURESHUNT].option;

	/* i.e., default is to have policy off */
#define KW_POLICY_FLAG(val, fl)						\
	{								\
		if (conn->values[val].set)				\
			conn->policy = (conn->policy & ~(fl)) |		\
				(conn->values[val].option ? (fl) : LEMPTY);	\
	}

	/* i.e., confusion rains */
#define KW_POLICY_NEGATIVE_FLAG(val, fl)				\
	{								\
		if (conn->values[val].set) {				\
			conn->policy = (conn->policy & ~(fl)) |		\
				(!conn->values[val].option ? (fl) : LEMPTY);	\
		}							\
	}

	/*
	 * ??? sometimes (when? why?) the member is already set.
	 *
	 * When a conn sets it and then expands also=.
	 */

	if (conn->values[KNCF_KEYEXCHANGE].set) {
		if (conn->values[KNCF_KEYEXCHANGE].option == IKE_VERSION_ROOF) {
			/*
			 * i.e., keyexchange=ike which was ignored.
			 * Use ikev2= when specified.
			 */
			if (conn->values[KNCF_IKEv2].set) {
				conn->ike_version = (conn->values[KNCF_IKEv2].option == YN_YES ? IKEv2 : IKEv1);
			}
		} else {
			/* IKEv1, IKEv2, ... */
			conn->ike_version = conn->values[KNCF_KEYEXCHANGE].option;
		}
	} else if (conn->values[KNCF_IKEv2].set) {
		conn->ike_version = (conn->values[KNCF_IKEv2].option == YN_YES ? IKEv2 : IKEv1);
	}

	/*
	 * Read in the authby= string and translate to policy bits.
	 *
	 * This is the symmetric (left+right) version.  There is also
	 * leftauth=/rightauth= version stored in 'end'
	 *
	 * authby=secret|rsasig|null|never|rsa-HASH
	 *
	 * using authby=rsasig results in both RSASIG_v1_5 and RSA_PSS
	 *
	 * HASH needs to use full syntax - eg sha2_256 and not sha256,
	 * to avoid confusion with sha3_256
	 */
	if (conn->values[KSCF_AUTHBY].set) {

		conn->sighash_policy = LEMPTY;
		conn->authby = (struct authby) {0};

		shunk_t curseby = shunk1(conn->values[KSCF_AUTHBY].string);
		while (true) {

			shunk_t val = shunk_token(&curseby, NULL/*delim*/, ", ");

			if (val.ptr == NULL) {
				break;
			}
#if 0
			if (val.len == 0) {
				/* ignore empty fields? */
				continue;
			}
#endif

			/* Supported for IKEv1 and IKEv2 */
			if (hunk_streq(val, "secret")) {
				conn->authby.psk = true;;
			} else if (hunk_streq(val, "rsasig") ||
				   hunk_streq(val, "rsa")) {
				conn->authby.rsasig = true;
				conn->authby.rsasig_v1_5 = true;
				conn->sighash_policy |= POL_SIGHASH_SHA2_256;
				conn->sighash_policy |= POL_SIGHASH_SHA2_384;
				conn->sighash_policy |= POL_SIGHASH_SHA2_512;
			} else if (hunk_streq(val, "never")) {
				conn->authby.never = true;
			/* everything else is only supported for IKEv2 */
			} else if (conn->ike_version == IKEv1) {
				llog(RC_LOG, logger,
				     "ikev1 connection must use authby= of rsasig, secret or never");
				return false;
			} else if (hunk_streq(val, "null")) {
				conn->authby.null = true;
			} else if (hunk_streq(val, "rsa-sha1")) {
				conn->authby.rsasig_v1_5 = true;
			} else if (hunk_streq(val, "rsa-sha2")) {
				conn->authby.rsasig = true;
				conn->sighash_policy |= POL_SIGHASH_SHA2_256;
				conn->sighash_policy |= POL_SIGHASH_SHA2_384;
				conn->sighash_policy |= POL_SIGHASH_SHA2_512;
			} else if (hunk_streq(val, "rsa-sha2_256")) {
				conn->authby.rsasig = true;
				conn->sighash_policy |= POL_SIGHASH_SHA2_256;
			} else if (hunk_streq(val, "rsa-sha2_384")) {
				conn->authby.rsasig = true;
				conn->sighash_policy |= POL_SIGHASH_SHA2_384;
			} else if (hunk_streq(val, "rsa-sha2_512")) {
				conn->authby.rsasig = true;
				conn->sighash_policy |= POL_SIGHASH_SHA2_512;
			} else if (hunk_streq(val, "ecdsa") ||
				   hunk_streq(val, "ecdsa-sha2")) {
				conn->authby.ecdsa = true;
				conn->sighash_policy |= POL_SIGHASH_SHA2_256;
				conn->sighash_policy |= POL_SIGHASH_SHA2_384;
				conn->sighash_policy |= POL_SIGHASH_SHA2_512;
			} else if (hunk_streq(val, "ecdsa-sha2_256")) {
				conn->authby.ecdsa = true;
				conn->sighash_policy |= POL_SIGHASH_SHA2_256;
			} else if (hunk_streq(val, "ecdsa-sha2_384")) {
				conn->authby.ecdsa = true;
				conn->sighash_policy |= POL_SIGHASH_SHA2_384;
			} else if (hunk_streq(val, "ecdsa-sha2_512")) {
				conn->authby.ecdsa = true;
				conn->sighash_policy |= POL_SIGHASH_SHA2_512;
			} else if (hunk_streq(val, "ecdsa-sha1")) {
				llog(RC_LOG, logger, "authby=ecdsa cannot use sha1, only sha2");
				return false;
			} else {
				llog(RC_LOG, logger, "connection authby= value is unknown");
				return false;
			}
		}
	}

	/* Let this go through to pluto which will validate it. */
	conn->clientaddrfamily = aftoinfo(conn->values[KNCF_CLIENTADDRFAMILY].option);

	/*
	 * TODO:
	 * The address family default should come in either via
	 * a config setup option, or via gai.conf / RFC3484
	 * For now, %defaultroute and %any means IPv4 only
	 */

	const struct ip_info *afi = aftoinfo(conn->values[KNCF_HOSTADDRFAMILY].option);
	if (afi == NULL) {
		FOR_EACH_THING(end, &conn->end[LEFT_END], &conn->end[RIGHT_END]) {
			FOR_EACH_THING(ips,
				       end->values[KW_IP].string,
				       end->values[KW_NEXTHOP].string) {
				if (ips == NULL) {
					continue;
				}
				/* IPv6 like address */
				if (strchr(ips, ':') != NULL ||
				    streq(ips, "%defaultroute6") ||
				    streq(ips, "%any6")) {
					afi = &ipv6_info;
					break;
				}
			}
			if (afi != NULL) {
				break;
			}
		}
	}
	if (afi == NULL) {
		afi = &ipv4_info;
	}
	conn->end[LEFT_END].host_family = conn->end[RIGHT_END].host_family = afi;

	bool ok = true;
	ok &= validate_end(conn, &conn->end[LEFT_END], logger);
	ok &= validate_end(conn, &conn->end[RIGHT_END], logger);
	return ok;
}

static void copy_conn_default(struct starter_conn *conn,
			      const struct starter_conn *def)
{
	/* structure copy to start */
	*conn = *def;

	/* unlink it */
	conn->link.tqe_next = NULL;
	conn->link.tqe_prev = NULL;

	/* Unshare all strings */

	/*
	 * Note: string fields in struct starter_end and struct starter_conn
	 * should correspond to STR_FIELD calls in copy_conn_default() and confread_free_conn.
	 */

# define STR_FIELD(f)  { conn->f = clone_str(conn->f, #f); }

	STR_FIELD(name);

	for (unsigned i = 0; i < elemsof(conn->values); i++)
		STR_FIELD(values[i].string);

	/* handle starter_end strings */

# define STR_FIELD_END(f) { STR_FIELD(end[LEFT_END].f); STR_FIELD(end[RIGHT_END].f); }

	for (unsigned i = 0; i < elemsof(conn->end[LEFT_END].values); i++)
		STR_FIELD_END(values[i].string);

# undef STR_FIELD_END

# undef STR_FIELD
}

static struct starter_conn *alloc_add_conn(struct starter_config *cfg, const char *name)
{
	struct starter_conn *conn = alloc_thing(struct starter_conn, "add_conn starter_conn");

	copy_conn_default(conn, &cfg->conn_default);
	assert(conn->name == NULL);
	conn->name = clone_str(name, "add conn name");
	conn->state = STATE_FAILED;

	TAILQ_INSERT_TAIL(&cfg->conns, conn, link);
	return conn;
}

static bool init_load_conn(struct starter_config *cfg,
			   const struct config_parsed *cfgp,
			   struct section_list *sconn,
			   bool defaultconn,
			   struct logger *logger)
{
	ldbg(logger, "loading conn %s", sconn->name);

	struct starter_conn *conn = alloc_add_conn(cfg, sconn->name);

	if (!load_conn(conn, cfgp, sconn, /*also*/true, defaultconn, logger)) {
		/* ??? should caller not log perrl? */
		return false;
	}

	conn->state = STATE_LOADED;
	return true;
}

struct starter_config *confread_load(const char *file,
				     bool setuponly,
				     struct logger *logger)
{
	/**
	 * Load file
	 */
	struct config_parsed *cfgp = parser_load_conf(file, logger);

	if (cfgp == NULL)
		return NULL;

	struct starter_config *cfg = alloc_thing(struct starter_config, "starter_config cfg");

	/**
	 * Set default values
	 */
	ipsecconf_default_values(cfg);

	/**
	 * Load setup
	 *
	 * Danger: reverse fail.
	 */
	if (!load_setup(cfg, cfgp)) {
		parser_freeany_config_parsed(&cfgp);
		confread_free(cfg);
		return NULL;
	}

	if (!setuponly) {

		/*
		 * Load %default conn
		 * ??? is it correct to accept multiple %default conns?
		 */
		bool ok = true;
		for (struct section_list *sconn = TAILQ_FIRST(&cfgp->sections);
		     ok && sconn != NULL;
		     sconn = TAILQ_NEXT(sconn, link)) {
			if (streq(sconn->name, "%default")) {
				ldbg(logger, "loading default conn");
				ok &= load_conn(&cfg->conn_default,
						cfgp, sconn,
						/*also=*/false,
						/*default conn*/true,
						logger);
			}
		}

		/*
		 * Load other conns
		 */
		for (struct section_list *sconn = TAILQ_FIRST(&cfgp->sections);
		     sconn != NULL; sconn = TAILQ_NEXT(sconn, link)) {
			if (!streq(sconn->name, "%default"))
				init_load_conn(cfg, cfgp, sconn,
					       /*default conn*/false,
					       logger);
		}
	}

	parser_freeany_config_parsed(&cfgp);
	return cfg;
}

static void confread_free_conn(struct starter_conn *conn)
{
	/* Free all strings */

	/*
	 * Note: string fields in struct starter_end and struct starter_conn
	 * should correspond to STR_FIELD calls in copy_conn_default() and confread_free_conn.
	 */

# define STR_FIELD(f)  { pfreeany(conn->f); }

	STR_FIELD(name);

	for (unsigned i = 0; i < elemsof(conn->values); i++)
		STR_FIELD(values[i].string);

	/* handle starter_end strings */

# define STR_FIELD_END(f) { STR_FIELD(end[LEFT_END].f); STR_FIELD(end[RIGHT_END].f); }

	for (unsigned i = 0; i < elemsof(conn->end[LEFT_END].values); i++)
		STR_FIELD_END(values[i].string);

# undef STR_FIELD_END

# undef STR_FIELD
}

void confread_free(struct starter_config *cfg)
{
	for (unsigned i = 0; i < elemsof(cfg->values); i++)
		pfreeany(cfg->values[i].string);

	confread_free_conn(&cfg->conn_default);

	for (struct starter_conn *conn = TAILQ_FIRST(&cfg->conns);
	     conn != NULL; ) {
		struct starter_conn *c = conn;
		/* step off */
		conn = TAILQ_NEXT(conn, link);
		confread_free_conn(c);
		pfree(c);
	}
	pfree(cfg);
}
