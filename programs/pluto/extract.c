/* information about connections between hosts and clients
 *
 * Copyright (C) 1998-2002,2010,2013,2018 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009-2011 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 Bart Trojanowski <bart@jukie.net>
 * Copyright (C) 2010 Shinichi Furuso <Shinichi.Furuso@jp.sony.com>
 * Copyright (C) 2010,2013 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012-2017 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Philippe Vouters <Philippe.Vouters@laposte.net>
 * Copyright (C) 2012 Bram <bram-bcrafjna-erqzvar@spam.wizbit.be>
 * Copyright (C) 2013 Kim B. Heino <b@bbbs.net>
 * Copyright (C) 2013,2017 Antony Antony <antony@phenome.org>
 * Copyright (C) 2013,2018 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2013 Florian Weimer <fweimer@redhat.com>
 * Copyright (C) 2015-2020 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2016-2020 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
 * Copyright (C) 20212-2022 Paul Wouters <paul.wouters@aiven.io>
 * Copyright (C) 2020 Nupur Agrawal <nupur202000@gmail.com>
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

#include "extract.h"

#include "whack.h"
#include "verbose.h"
#include "ip_info.h"
#include "sparse_names.h"
#include "passert.h"
#include "ipsecconf/interfaces.h"
#include "nss_cert_load.h"
#include "config_setup.h"
#include "scale.h"
#include "deltatime.h"
#include "timescale.h"
#include "kernel_alg.h"

#include "log.h"
#include "connections.h"
#include "connection_db.h"
#include "orient.h"
#include "keys.h"
#include "nss_cert_verify.h"
#include "whack_pubkey.h"
#include "addresspool.h"
#include "virtual_ip.h"
#include "kernel.h"
#include "labeled_ipsec.h"
#include "ikev2_proposals.h"
#include "ipsec_interface.h"
#include "kernel_info.h"
#include "binaryscale-iec-60027-2.h"

static bool is_never_negotiate_wm(const struct whack_message *wm)
{
	/* with no never-negotiate shunt, things must negotiate */
	return (wm->never_negotiate_shunt != SHUNT_UNSET);
}

static void llog_never_negotiate_option(struct verbose verbose,
					const struct whack_message *wm,
					const char *leftright,
					const char *name,
					const char *value)
{
	/* need to reverse engineer type= */
	enum shunt_policy shunt = wm->never_negotiate_shunt;
	vwarning("%s%s=%s ignored for never-negotiate (type=%s) connection",
		 leftright, name, value,
		 (shunt == SHUNT_PASS ? "passthrough" :
		  shunt == SHUNT_DROP ? "drop" :
		  "???"));
}

static bool never_negotiate_string_option(const char *leftright,
					  const char *name,
					  const char *value,
					  const struct whack_message *wm,
					  struct verbose verbose)
{
	if (is_never_negotiate_wm(wm)) {
		if (value != NULL) {
			llog_never_negotiate_option(verbose, wm, leftright, name, value);
		}
		return true;
	}

	return false;
}

static bool never_negotiate_sparse_option(const char *leftright,
					  const char *name,
					  unsigned value,
					  const struct sparse_names *names,
					  const struct whack_message *wm,
					  struct verbose verbose)
{
	if (is_never_negotiate_wm(wm)) {
		if (value != 0) {
			name_buf sb;
			llog_never_negotiate_option(verbose, wm, leftright, name,
						    str_sparse_long(names, value, &sb));
		}
		return true;
	}
	return false;
}

static bool never_negotiate_enum_option(const char *leftright,
					const char *name,
					unsigned value,
					const struct enum_names *names,
					const struct whack_message *wm,
					struct verbose verbose)
{
	if (is_never_negotiate_wm(wm)) {
		if (value != 0) {
			name_buf sb;
			llog_never_negotiate_option(verbose, wm, leftright, name,
						    str_enum_short(names, value, &sb));
		}
		return true;
	}
	return false;
}

static bool is_opportunistic_wm_end(const struct host_addr_config *host_addr)
{
	return (host_addr->type == KH_OPPO ||
		host_addr->type == KH_OPPOGROUP);
}

static bool is_opportunistic_wm(const struct host_addr_config *const host_addrs[END_ROOF])
{
	return (is_opportunistic_wm_end(host_addrs[LEFT_END]) ||
		is_opportunistic_wm_end(host_addrs[RIGHT_END]));
}

static bool is_group_wm_end(const struct host_addr_config *host_addr)
{
	return (host_addr->type == KH_GROUP ||
		host_addr->type == KH_OPPOGROUP);
}

static bool is_group_wm(const struct host_addr_config *const host_addrs[END_ROOF])
{
	return (is_group_wm_end(host_addrs[LEFT_END]) ||
		is_group_wm_end(host_addrs[RIGHT_END]));
}

/*
 * Figure out the host / nexthop / client addresses.
 *
 * Returns diag() when there's a conflict.  leaves *AFI NULL if could
 * not be determined.
 */

struct afi_winner {
	const char *leftright;
	const char *name;
	const char *value;
	const struct ip_info *afi;
};

static diag_t check_afi(struct afi_winner *winner,
			const char *leftright, const char *name, const char *value,
			const struct ip_info *afi,
			struct verbose verbose)
{
	if (afi == NULL) {
		return NULL;
	}

	if (afi == winner->afi) {
		return NULL;
	}

	if (winner->afi == NULL) {
		vdbg("winner: %s%s=%s %s", leftright, name, value, afi->ip_name);
		winner->afi = afi;
		winner->leftright = leftright;
		winner->name = name;
		winner->value = value;
		return NULL;
	}

	return diag("host address family %s from %s%s=%s conflicts with %s%s=%s",
		    winner->afi->ip_name,
		    winner->leftright, winner->name, winner->value,
		    leftright, name, value);
}

static diag_t extract_host_addr(struct afi_winner *winner,
				struct host_addr_config *end,
				const char *leftright,
				const char *name,
				const char *value,
				struct verbose verbose)
{
	diag_t d;
	err_t e;

	vdbg("extracting '%s%s=%s':", leftright, name, (value == NULL ? "" : value));
	verbose.level++;

	/*
	 * {left,right}: when the value '%...' a keywords,
	 * .type is set accordingly; else .type is KH_IPADDR.
	 */
	if (value == NULL) {
		name_buf tb;
		vdbg("-> %s", str_sparse_short(&keyword_host_names, end->type, &tb));
		return NULL;
	}

	end->name = clone_str(value, "host name");

	if (value[0] == '%') {
		/* either keyword, or %interface */
		shunk_t cursor = shunk1(value);

		/* split %any[46] into %any + 46 */
		char delim = '\0'; /*4|6|\0*/
		shunk_t keyword = shunk_token(&cursor, &delim, "46");
		if (cursor.len > 0) {
			return diag("'%s%s=%s' contains the trailing junk '"PRI_SHUNK"'",
				    leftright, name, value, pri_shunk(cursor));
		}

		d = check_afi(winner, leftright, name, value,
			      (delim == '4' ? &ipv4_info : delim == '6' ? &ipv6_info : NULL),
			      verbose);
		if (d != NULL) {
			return d;
		}

		const struct sparse_name *sn =
			sparse_lookup_by_name(&keyword_host_names, keyword);
		/* will fix up KH_IFACE later */
		end->type = (sn != NULL ? sn->value : KH_IFACE);

		name_buf tb;
		vdbg("-> %s", str_sparse_short(&keyword_host_names, end->type, &tb));
		return NULL;
	}

	/* let parser decide address, then reject after */

	e = ttoaddress_num(shunk1(value), NULL, &end->addr);
	if (e == NULL) {
		const struct ip_info *afi = address_info(end->addr);
		d = check_afi(winner, leftright, name, value, afi, verbose);
		if (d != NULL) {
			return d;
		}

		end->type = KH_IPADDR;

		name_buf tb;
		address_buf ab;
		vdbg("-> %s %s", str_sparse_short(&keyword_host_names, end->type, &tb),
		     str_address(&end->addr, &ab));
		return NULL;
	}

	/* not an IP address, assume it's a DNS hostname */
	end->type = KH_IPHOSTNAME;
	name_buf tb;
	vdbg("-> %s", str_sparse_short(&keyword_host_names, end->type, &tb));
	return NULL;

}

static diag_t extract_host_addrs(const struct whack_message *wm,
				 struct config *config,
				 struct verbose verbose)
{
	/* source of AFI */
	diag_t d;
	struct afi_winner winner = {0};

	/*
	 * Start with something easy.
	 */

	if (wm->hostaddrfamily != NULL) {
		/* save the winner */
		const struct ip_info *afi = ttoinfo(wm->hostaddrfamily);
		if (afi == NULL) {
			return diag("hostaddrfamily=%s is not unrecognized", wm->hostaddrfamily);
		}
		/* save source; must be winner! */
		d = check_afi(&winner, "", "hostaddrfamily", wm->hostaddrfamily, afi, verbose);
		if (vbad(d != NULL)) {
			return d;
		}
	}

	FOR_EACH_THING(lr, LEFT_END, RIGHT_END) {
		const struct whack_end *we = &wm->end[lr];
		const char *leftright = we->leftright;
		struct host_addr_config *host = &config->end[lr].host.host;
		struct host_addr_config *nexthop = &config->end[lr].host.nexthop;

		d = extract_host_addr(&winner, host, leftright, "", we->host, verbose);
		if (d != NULL) {
			return d;
		}

		d = extract_host_addr(&winner, nexthop, leftright, "nexthop", we->nexthop, verbose);
		if (d != NULL) {
			return d;
		}
	}

	/*
	 * default!
	 */

	if (winner.afi == NULL) {
		winner.afi = &ipv4_info;
	}

	/*
	 * Verify the extract, update with the unset address when
	 * necessary.
	 *
	 * Deal with the lurking {left,right}=%iface.
	 *
	 * At least one end must specify an IP address (or at least
	 * have that potential to be resolved to an IP address by
	 * being a KP_IPHOSTNAME).
	 *
	 * Without at least one potential address the connection can
	 * never be orient()ed.
	 */

	bool can_orient = false;

	FOR_EACH_THING(lr, LEFT_END, RIGHT_END) {

		struct host_addr_config *host = &config->end[lr].host.host;
		struct host_addr_config *nexthop = &config->end[lr].host.nexthop;
 		const char *leftright = wm->end[lr].leftright;
		const char *name = "";
		const char *value = host->name;
		bool end_can_orient = false;

		switch (host->type) {

		case KH_IPADDR:
			/* handled by pluto using .host_type */
			end_can_orient = true;
			break;

		case KH_DEFAULTROUTE:
			/* handled by pluto using .host_type */
			end_can_orient = true;
			host->addr = winner.afi->address.zero;
			break;

		case KH_OPPO:
		case KH_OPPOGROUP:
		case KH_GROUP:
		case KH_ANY:
			/* handled by pluto using .host_type */
			host->addr = winner.afi->address.zero;
			break;

		case KH_IPHOSTNAME:
			/* handled by pluto using .host_type */
			host->addr = winner.afi->address.zero;
			end_can_orient = true;
			break;

		case KH_IFACE:
		{
			vassert(value != NULL);
			vexpect(value[0] == '%');
			const char *iface = value + 1;
			if (!starter_iface_find(iface, winner.afi,
						&host->addr,
						&nexthop->addr)) {
				return diag("%s%s=%s does not appear to be an interface",
					    leftright, name, value);
			}

			end_can_orient = true;
			break;
		}

		case KH_NOTSET:
			return diag("%s%s= is not set", leftright, name);

		case KH_DIRECT:
			return diag("%s%s=%s invalid", leftright, name, value);

		}

		name_buf nb;
		address_buf hab, nab;
		vdbg("%s%s=%s aka %s set to %s -> %s%s",
		     leftright, name, (value == NULL ? "<null>" : value),
		     str_sparse_short(&keyword_host_names, host->type, &nb),
		     str_address(&host->addr, &hab),
		     str_address(&nexthop->addr, &nab),
		     (end_can_orient ? "; can orient" : ""));

		can_orient |= end_can_orient;
	}

	if (!can_orient) {
		const char *left = config->end[LEFT_END].host.host.name;
		const char *right = config->end[RIGHT_END].host.host.name;
		return diag("neither 'left=%s' nor 'right=%s' specify the local host's IP address",
			    (left == NULL ? "" : left),
			    (right == NULL ? "" : right));
	}

	/*
	 * Validate nexthop.
	 */

	FOR_EACH_THING(lr, LEFT_END, RIGHT_END) {

		struct host_addr_config *nexthop = &config->end[lr].host.nexthop;
 		const char *leftright = wm->end[lr].leftright;
		const char *name = "nexthop";
		const char *value = nexthop->name;
		enum keyword_host type = nexthop->type;

		switch (type) {
		case KH_ANY:
		case KH_IFACE:
		case KH_OPPO:
		case KH_OPPOGROUP:
		case KH_GROUP:
		case KH_IPHOSTNAME:
			return diag("%s%s=%s invalid", leftright, name, value);

		case KH_IPADDR:
			break;

		case KH_DIRECT:
			nexthop->addr = winner.afi->address.zero;
			break;

		case KH_NOTSET:
		{
			struct host_addr_config *host = &config->end[lr].host.host;
			nexthop->addr = winner.afi->address.zero;
			nexthop->type = (host->type == KH_DEFAULTROUTE ? KH_DEFAULTROUTE : KH_NOTSET);
			break;
		}

		case KH_DEFAULTROUTE:
			nexthop->addr = winner.afi->address.zero;
			break;

		}

		name_buf tb, nb;
		address_buf nab;
		vdbg("%s%s=%s aka %s set to %s %s",
		     leftright, name, (value == NULL ? "<null>" : value),
		     str_sparse_short(&keyword_host_names, type, &tb),
		     str_sparse_short(&keyword_host_names, nexthop->type, &nb),
		     str_address(&nexthop->addr, &nab));

	}

	config->host.afi = winner.afi;
	return NULL;
}

/* assume 0 is unset */

static unsigned extract_sparse(const char *leftright, const char *name,
			       unsigned value,
			       unsigned value_when_unset /*i.e., 0*/,
			       unsigned value_when_never_negotiate,
			       const struct sparse_names *names,
			       const struct whack_message *wm,
			       struct verbose verbose)
{
	if (never_negotiate_sparse_option(leftright, name, value,
					  names, wm, verbose)) {
		return value_when_never_negotiate;
	}

	if (value == 0) {
		return value_when_unset;
	}

	return value;
}

static bool extract_yn(const char *leftright, const char *name,
		       enum yn_options value, enum yn_options value_when_unset,
		       const struct whack_message *wm, struct verbose verbose)
{
	enum yn_options yn = extract_sparse(leftright, name, value,
					    value_when_unset, /*never*/YN_NO,
					    &yn_option_names, wm, verbose);

	switch (yn) {
	case YN_NO: return false;
	case YN_YES: return true;
	default:
		bad_sparse(verbose.logger, &yn_option_names, yn);
	}
}

/*
 * YN option that is only used when P is enabled.  When P is disabled a
 * warning is issued but the value is saved regardless:
 *
 * This is to stop:
 *   iptfs=no; iptfs-fragmentation=yes
 * showing as:
 *   iptfs: no; fragmentation: no;
 */

static bool extract_yn_p(const char *leftright, const char *name, enum yn_options yn,
			 enum yn_options value_when_unset,
			 const struct whack_message *wm, struct verbose verbose,
			 const char *p_leftright, const char *p_name, enum yn_options p)
{
	const struct sparse_names *names = &yn_option_names;

	if (yn == 0) {
		/* no argument */
		return value_when_unset;
	}

	bool value;
	switch (yn) {
	case YN_NO: value = false; break;
	case YN_YES: value = true; break;
	default:
		bad_sparse(verbose.logger, &yn_option_names, yn);
	}

	/* complain? */
	if (never_negotiate_sparse_option(leftright, name, yn,
					  &yn_option_names, wm, verbose)) {
		return value;
	}

	if (p == YN_UNSET) {
		name_buf sb;
		vwarning("%s%s=%s ignored without %s%s=yes",
			 leftright, name, str_sparse_long(names, value, &sb),
			 p_leftright, p_name);
	} else if (p == YN_NO) {
		name_buf sb;
		vwarning("%s%s=%s ignored when %s%s=no",
			 leftright, name, str_sparse_long(names, value, &sb),
			 p_leftright, p_name);
	}

	return value;
}

static enum yna_options extract_yna(const char *leftright, const char *name,
				    enum yna_options yna,
				    enum yna_options value_when_unset,
				    enum yna_options value_when_never_negotiate,
				    const struct whack_message *wm,
				    struct verbose verbose)
{
	return extract_sparse(leftright, name, yna,
			      value_when_unset,
			      value_when_never_negotiate,
			      &yna_option_names, wm, verbose);
}

/* terrible name */

static bool can_extract_string(const char *leftright,
			       const char *name,
			       const char *value,
			       const struct whack_message *wm,
			       struct verbose verbose)
{
	if (never_negotiate_string_option(leftright, name, value, wm, verbose)) {
		return false;
	}

	if (value == NULL) {
		return false;
	}

	return true;
}

static char *extract_string(const char *leftright, const char *name,
			    const char *string,
			    const struct whack_message *wm,
			    struct verbose verbose)
{
	if (!can_extract_string(leftright, name, string, wm, verbose)) {
		return NULL;
	}

	return clone_str(string, name);
}

static deltatime_t extract_deltatime(const char *leftright,
				     const char *name,
				     const char *value,
				     enum timescale default_timescale,
				     deltatime_t value_when_unset,
				     const struct whack_message *wm,
				     diag_t *d, struct verbose verbose)
{
	if (!can_extract_string(leftright, name, value, wm, verbose)) {
		return value_when_unset;
	}

	deltatime_t deltatime;
	diag_t diag = ttodeltatime(shunk1(value), &deltatime, default_timescale);
	if (diag != NULL) {
		(*d) = diag_diag(&diag, "%s%s=%s invalid, ",
				 leftright, name, value);
		return value_when_unset;
	}

	return deltatime;
}

static unsigned extract_enum_name(const char *leftright,
				  const char *name,
				  const char *value, unsigned unset,
				  const struct enum_names *names,
				  const struct whack_message *wm,
				  diag_t *d,
				  struct verbose verbose)
{
	(*d) = NULL;

	if (never_negotiate_string_option(leftright, name, value, wm, verbose)) {
		return unset;
	}

	if (value == NULL) {
		return unset;
	}

	int match = enum_match(names, shunk1(value));
	if (match < 0) {
		/* include allowed names? */
		(*d) = diag("%s%s=%s invalid, '%s' unrecognized",
			    leftright, name, value, value);
		return 0;
	}

	return match;
}

static unsigned extract_sparse_name(const char *leftright,
				    const char *name,
				    const char *value,
				    unsigned value_when_unset,
				    const struct sparse_names *names,
				    const struct whack_message *wm,
				    diag_t *d,
				    struct verbose verbose)
{
	(*d) = NULL;

	if (never_negotiate_string_option(leftright, name, value, wm, verbose)) {
		return value_when_unset;
	}

	if (value == NULL) {
		return value_when_unset;
	}

	const struct sparse_name *sparse = sparse_lookup_by_name(names, shunk1(value));
	if (sparse == NULL) {
		/* include allowed names? */
		(*d) = diag("%s%s=%s invalid, '%s' unrecognized",
			    leftright, name, value, value);
		return 0;
	}

	return sparse->value;
}

struct range {
	uintmax_t value_when_unset;
	struct {
		uintmax_t min;
		uintmax_t max;
	} limit;
	struct {
		uintmax_t min;
		uintmax_t max;
	} clamp;
};

static uintmax_t check_range(const char *story,
			     const char *leftright,
			     const char *name,
			     uintmax_t value,
			     struct range range,
			     diag_t *d,
			     struct verbose verbose)
{

	if (range.clamp.min != 0 && value < range.clamp.min) {
		humber_buf hb;
		vlog("%s%s%s%s=%ju clamped to the minimum %s",
		     story, (strlen(story) > 0 ? " " : ""),
		     leftright, name, value,
		     str_humber(range.clamp.min, &hb));
		return range.clamp.min;
	}

	if (range.clamp.max != 0 && value > range.clamp.max) {
		humber_buf hb;
		vlog("%s%s%s%s=%ju clamped to the maximum %s",
		     story, (strlen(story) > 0 ? " " : ""),
		     leftright, name, value,
		     str_humber(range.clamp.min, &hb));
		return range.clamp.max;
	}

	if (range.limit.min != 0 && range.limit.max != 0 &&
	    (value < range.limit.min || value > range.limit.max)) {
		(*d) = diag("%s%s%s%s=%ju invalid, must be in the range %ju-%ju",
			    story, (strlen(story) > 0 ? " " : ""),
			    leftright, name, value,
			    range.limit.min, range.limit.max);
		return range.value_when_unset;
	}

	if (range.limit.min != 0 && value < range.limit.min) {
		(*d) = diag("%s%s%s%s=%ju invalid, minimum is %ju",
			    story, (strlen(story) > 0 ? " " : ""),
			    leftright, name, value,
			    range.limit.min);
		return range.value_when_unset;
	}

	if (range.limit.max != 0 && value > range.limit.max) {
		(*d) = diag("%s%s=%ju invalid, maximum is %ju",
			    leftright, name, value,
			    range.limit.max);
		return range.value_when_unset;
	}

	return value;
}

static uintmax_t extract_uintmax(const char *story,
				 const char *leftright,
				 const char *name,
				 const char *value,
				 struct range range,
				 const struct whack_message *wm,
				 diag_t *d,
				 struct verbose verbose)
{
	(*d) = NULL;
	if (!can_extract_string(leftright, name, value, wm, verbose)) {
		return range.value_when_unset;
	}

	uintmax_t number;
	err_t err = shunk_to_uintmax(shunk1(value), NULL/*all*/, 0, &number);
	if (err != NULL) {
		(*d) = diag("%s%s=%s invalid, %s", leftright, name, value, err);
		return range.value_when_unset;
	}

	return check_range(story, leftright, name, number, range, d, verbose);
}

static uintmax_t extract_scaled_uintmax(const char *story,
					const char *leftright,
					const char *name,
					const char *value,
					const struct scales *scales,
					struct range range,
					const struct whack_message *wm,
					diag_t *d,
					struct verbose verbose)
{
	(*d) = NULL;

	if (!can_extract_string(leftright, name, value, wm, verbose)) {
		return range.value_when_unset;
	}

	uintmax_t number;
	diag_t diag = tto_scaled_uintmax(shunk1(value), &number, scales);
	if ((*d) != NULL) {
		(*d) = diag_diag(&diag, "%s%s=%s invalid, ", leftright, name, value);
		return range.value_when_unset;
	}

	return check_range(story, leftright, name, number, range, d, verbose);
}

static uintmax_t extract_percent(const char *leftright, const char *name, const char *value,
				 uintmax_t value_when_unset,
				 const struct whack_message *wm,
				 diag_t *d,
				 struct verbose verbose)
{
	(*d) = NULL;

	if (!can_extract_string(leftright, name, value, wm, verbose)) {
		return value_when_unset;
	}

	/* NUMBER% */

	uintmax_t percent;
	shunk_t cursor = shunk1(value);
	err_t err = shunk_to_uintmax(cursor, &cursor, /*base*/10, &percent);
	if (err != NULL) {
		(*d) = diag("%s%s=%s invalid, %s", leftright, name, value, err);
		return value_when_unset;
	}

	if (!hunk_streq(cursor, "%")) {
		(*d) = diag("%s%s=%s invalid, expecting %% character", leftright, name, value);
		return value_when_unset;
	}

	if (percent > INT_MAX - 100) {
		vlog("%s%s=%s is way to large, using %ju%%",
		     leftright, name, value, value_when_unset);
		return value_when_unset;
	}

	return percent;
}

static ip_cidr extract_cidr_num(const char *leftright,
				const char *name,
				const char *value,
				const struct whack_message *wm,
				diag_t *d,
				struct verbose verbose)
{
	err_t err;
	(*d) = NULL;

	if (!can_extract_string(leftright, name, value, wm, verbose)) {
		return unset_cidr;
	}

	ip_cidr cidr;
	err = ttocidr_num(shunk1(value), NULL, &cidr);
	if (err != NULL) {
		(*d) = diag("%s%s=%s invalid, %s", leftright, name, value, err);
		return unset_cidr;
	}

	err = cidr_check(cidr);
	if (err != NULL) {
		(*d) = diag("%s%s=%s invalid, %s", leftright, name, value, err);
	}

	return cidr;
}

static diag_t extract_host_ckaid(struct host_end_config *host_config,
				 const struct whack_end *src,
				 bool *same_ca,
				 struct verbose verbose/*connection "..."*/)
{
	const char *leftright = src->leftright;
	ckaid_t ckaid;
	err_t err = string_to_ckaid(src->ckaid, &ckaid);
	if (err != NULL) {
		return diag("%s-ckaid='%s' invalid: %s",
			    leftright, src->ckaid, err);
	}

	/*
	 * Always save the CKAID so that a delayed load of the private
	 * key can work.
	 */
	host_config->ckaid = clone_thing(ckaid, "end ckaid");

	/*
	 * See if there's a certificate matching the CKAID, if not
	 * assume things will later find the private key (or cert on a
	 * later attempt).
	 */
	CERTCertificate *cert = get_cert_by_ckaid_from_nss(&ckaid, verbose.logger);
	if (cert != NULL) {
		diag_t diag = add_end_cert_and_preload_private_key(cert, host_config,
								   *same_ca/*preserve_ca*/,
								   verbose.logger);
		if (diag != NULL) {
			CERT_DestroyCertificate(cert);
			return diag;
		}
		return NULL;
	}

	vdbg("%s-ckaid=%s did not match a certificate in the NSS database",
	     leftright, src->ckaid);

	/* try to pre-load the private key */
	bool load_needed;
	err = preload_private_key_by_ckaid(&ckaid, &load_needed, verbose.logger);
	if (err != NULL) {
		ckaid_buf ckb;
		vdbg("no private key matching %s-ckaid=%s: %s",
		     leftright, str_ckaid(host_config->ckaid, &ckb), err);
		return NULL;
	}

	ckaid_buf ckb;
	llog(LOG_STREAM/*not-whack-for-now*/, verbose.logger,
	     "loaded private key matching %s-ckaid=%s",
	     leftright,
	     str_ckaid(host_config->ckaid, &ckb));
	return NULL;
}

static diag_t extract_authby(struct authby *authby, lset_t *sighash_policy,
			     enum ike_version ike_version,
			     const struct whack_message *wm)
{
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
	(*authby) = (struct authby) {0};
	(*sighash_policy) = LEMPTY;

	if (is_never_negotiate_wm(wm)) {
		(*authby) = AUTHBY_NEVER;
		return NULL;
	}

	if (wm->authby != NULL) {

		shunk_t curseby = shunk1(wm->authby);
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
				authby->psk = true;;
			} else if (hunk_streq(val, "rsasig") ||
				   hunk_streq(val, "rsa")) {
				authby->rsasig = true;
				authby->rsasig_v1_5 = true;
				(*sighash_policy) |= POL_SIGHASH_SHA2_256;
				(*sighash_policy) |= POL_SIGHASH_SHA2_384;
				(*sighash_policy) |= POL_SIGHASH_SHA2_512;
			} else if (hunk_streq(val, "never")) {
				authby->never = true;
			} else if (ike_version == IKEv1) {
				return diag("authby="PRI_SHUNK" is not valid for IKEv1",
					    pri_shunk(val));
				/* everything else is only supported for IKEv2 */
			} else if (hunk_streq(val, "null")) {
				authby->null = true;
			} else if (hunk_streq(val, "rsa-sha1")) {
				authby->rsasig_v1_5 = true;
			} else if (hunk_streq(val, "rsa-sha2")) {
				authby->rsasig = true;
				(*sighash_policy) |= POL_SIGHASH_SHA2_256;
				(*sighash_policy) |= POL_SIGHASH_SHA2_384;
				(*sighash_policy) |= POL_SIGHASH_SHA2_512;
			} else if (hunk_streq(val, "rsa-sha2_256")) {
				authby->rsasig = true;
				(*sighash_policy) |= POL_SIGHASH_SHA2_256;
			} else if (hunk_streq(val, "rsa-sha2_384")) {
				authby->rsasig = true;
				(*sighash_policy) |= POL_SIGHASH_SHA2_384;
			} else if (hunk_streq(val, "rsa-sha2_512")) {
				authby->rsasig = true;
				(*sighash_policy) |= POL_SIGHASH_SHA2_512;
			} else if (hunk_streq(val, "ecdsa") ||
				   hunk_streq(val, "ecdsa-sha2")) {
				authby->ecdsa = true;
				(*sighash_policy) |= POL_SIGHASH_SHA2_256;
				(*sighash_policy) |= POL_SIGHASH_SHA2_384;
				(*sighash_policy) |= POL_SIGHASH_SHA2_512;
			} else if (hunk_streq(val, "ecdsa-sha2_256")) {
				authby->ecdsa = true;
				(*sighash_policy) |= POL_SIGHASH_SHA2_256;
			} else if (hunk_streq(val, "ecdsa-sha2_384")) {
				authby->ecdsa = true;
				(*sighash_policy) |= POL_SIGHASH_SHA2_384;
			} else if (hunk_streq(val, "ecdsa-sha2_512")) {
				authby->ecdsa = true;
				(*sighash_policy) |= POL_SIGHASH_SHA2_512;
			} else if (hunk_streq(val, "ecdsa-sha1")) {
				return diag("authby=ecdsa cannot use sha1, only sha2");
			} else {
				return diag("authby="PRI_SHUNK" is unknown", pri_shunk(val));
			}
		}
		return NULL;
	}

	(*sighash_policy) = POL_SIGHASH_DEFAULTS;
	(*authby) = (ike_version == IKEv1 ? AUTHBY_IKEv1_DEFAULTS :
		     AUTHBY_IKEv2_DEFAULTS);
	return NULL;
}

static diag_t extract_host_end(struct host_end *host,
			       struct host_end_config *host_config,
			       struct host_end_config *other_host_config,
			       const struct whack_message *wm,
			       const struct whack_end *src,
			       const struct whack_end *other_src,
			       const struct host_addr_config *host_addr,
			       const struct host_addr_config *const host_addrs[END_ROOF],
			       enum ike_version ike_version,
			       struct authby whack_authby,
			       bool *same_ca,
			       struct verbose verbose/*connection "..."*/)
{
	err_t err;
	diag_t d = NULL;
	const char *leftright = host_config->leftright;

	bool groundhog = extract_yn(leftright, "groundhog", src->groundhog,
				    /*value_when_unset*/YN_NO, wm, verbose);
	if (groundhog) {
		if (is_fips_mode()) {
			return diag("%sgroundhog=yes is invalid in FIPS mode",
				    leftright);
		}
		host_config->groundhog = groundhog;
		groundhogday |= groundhog;
		vlog("WARNING: %s is a groundhog", leftright);
	} else {
		vdbg("connection is not a groundhog");
	}

	/*
	 * Decode id, if any.
	 *
	 * For %fromcert, the load_end_cert*() call will update it.
	 *
	 * For unset, update_hosts_from_end_host_addr(), will fill it
	 * on from the HOST address (assuming it can be resolved).
	 *
	 * Else it remains unset and acts like a wildcard.
	 */
	struct id id = { .kind = ID_NONE, };
	vexpect(host_config->id.kind == ID_NONE);
	if (can_extract_string(leftright, "id", src->id, wm, verbose)) {
		/*
		 * Treat any atoid() failure as fatal.  One wart is
		 * something like id=foo.  ttoaddress_dns() fails
		 * when, perhaps, the code should instead return FQDN?
		 *
		 * In 4.x the error was ignored and ID=<HOST_IP> was
		 * used.
		 */
		err_t e = atoid(src->id, &id);
		if (e != NULL) {
			return diag("%sid=%s invalid, %s", leftright, src->id, e);
		}

		id_buf idb;
		vdbg("setting %s-id='%s' as wm->%s->id=%s",
		     leftright, str_id(&host_config->id, &idb),
		     leftright, (src->id != NULL ? src->id : "NULL"));

		/* danger, copying pointers */
		host_config->id = id;

	} else if (!is_never_negotiate_wm(wm) &&
		   host_addr->type == KH_IPADDR) {

		address_buf ab;
		err_t e = atoid(str_address(&host_addr->addr, &ab), &id);
		if (e != NULL) {
			return diag("%sid=%s invalid: %s",
				    leftright, host_addr->name, e);
		}

		id_buf idb;
		vdbg("setting %s-id='%s' as resolve.%s.host.kind=KH_IPADDR",
		     leftright, str_id(&host_config->id, &idb),
		     leftright);

		/* danger, copying pointers */
		host_config->id = id;

	}

	/* decode CA distinguished name, if any */
	host_config->ca = empty_chunk;
	if (src->ca != NULL) {
		if (streq(src->ca, "%same")) {
			*same_ca = true;
		} else if (!streq(src->ca, "%any")) {
			err_t ugh;

			/* convert the CA into a DN blob */
			ugh = atodn(src->ca, &host_config->ca);
			if (ugh != NULL) {
				vlog("bad %s CA string '%s': %s (ignored)",
				     leftright, src->ca, ugh);
			} else {
				/* now try converting it back; isn't failing this a bug? */
				ugh = parse_dn(ASN1(host_config->ca));
				if (ugh != NULL) {
					vlog("error parsing %s CA converted to DN: %s",
					     leftright, ugh);
					llog_hunk(RC_LOG, verbose.logger, host_config->ca);
				}
			}

		}
	}

	/*
	 * Handle %dnsondemand and %cert.  Only set PUBKEY when it's a
	 * rawkey.
	 */
	const char *pubkey = NULL;
	if (src->pubkey != NULL) {
		const struct sparse_name *sparse = sparse_lookup_by_name(&keyword_pubkey_names,
									 shunk1(src->pubkey));
		if (sparse == NULL) {
			pubkey = src->pubkey;
		} else if (sparse->value == PUBKEY_DNSONDEMAND) {
			host_config->key_from_DNS_on_demand = true;
		} /* else, ignore %cert! */
	}

	/*
	 * Try to find the cert / private key.
	 *
	 * XXX: Be lazy and simply warn about combinations such as
	 * cert+ckaid.
	 *
	 * Should this instead cross check?
	 */
	if (src->cert != NULL) {

		if (src->ckaid != NULL) {
			vwarning("ignoring %s ckaid '%s' and using %s certificate '%s'",
				 leftright, src->cert,
				 leftright, src->cert);
		}

		if (pubkey != NULL) {
			name_buf pkb;
			vwarning("ignoring %s %s '%s' and using %s certificate '%s'",
				 leftright,
				 str_enum_long(&ipseckey_algorithm_config_names, src->pubkey_alg, &pkb),
				 pubkey,
				 leftright, src->cert);
		}

		CERTCertificate *cert = get_cert_by_nickname_from_nss(src->cert,
								      verbose.logger);
		if (cert == NULL) {
			return diag("%s certificate '%s' not found in the NSS database",
				    leftright, src->cert);
		}
		diag_t diag = add_end_cert_and_preload_private_key(cert, host_config,
								   *same_ca/*preserve_ca*/,
								   verbose.logger);
		if (diag != NULL) {
			CERT_DestroyCertificate(cert);
			return diag;
		}

	} else if (pubkey != NULL) {

		/*
		 * Extract the CKAID from the PUBKEY.  When there's an
		 * ID, also save the pubkey under that name (later,
		 * during oritentation, the the missing ID will be
		 * filled in with HOST or left alone and treated like
		 * "null").
		 *
		 * Not adding the PUBKEY when there's no ID is very
		 * old behaviour.
		 *
		 * Extracting the CKAID from the PUBKEY and using that
		 * to find the private key is a somewhat more recent
		 * behaviour.
		 *
		 * There are OE tests where the missing ID is treated
		 * like "null".  Since the private key isn't needed,
		 * missing key is ignored.
		 *
		 * Are there tests where the ID defaults to HOST?
		 * Presumably the saved CKAID would be used to find
		 * the host key?
		 */

		if (src->ckaid != NULL) {
			name_buf pkb;
			vwarning("ignoring %sckaid=%s and using %s%s",
				 leftright, src->ckaid,
				 leftright, str_enum_long(&ipseckey_algorithm_config_names, src->pubkey_alg, &pkb));
		}

		chunk_t keyspace = NULL_HUNK; /* must free_chunk_content() */
		err = whack_pubkey_to_chunk(src->pubkey_alg, pubkey, &keyspace);
		if (err != NULL) {
			name_buf pkb;
			return diag("%s%s invalid: %s",
				    leftright, str_enum_long(&ipseckey_algorithm_config_names, src->pubkey_alg, &pkb),
				    err);
		}

		/* must-free keyspace */

		if (id.kind == ID_NONE) {

			struct pubkey_content pubkey_content; /* must free_pubkey_content() */
			d = unpack_dns_pubkey_content(src->pubkey_alg, HUNK_AS_SHUNK(keyspace),
						      &pubkey_content, verbose.logger);
			if (d != NULL) {
				free_chunk_content(&keyspace);
				name_buf pkb;
				return diag_diag(&d, "%s%s invalid, ",
						 leftright, str_enum_long(&ipseckey_algorithm_config_names, src->pubkey_alg, &pkb));
			}

			/* must free keyspace pubkey_content */
			vassert(pubkey_content.type != NULL);

			ckaid_buf ckb;
			name_buf pkb;
			vdbg("saving CKAID %s extracted from %s%s",
			     str_ckaid(&pubkey_content.ckaid, &ckb),
			     leftright, str_enum_long(&ipseckey_algorithm_config_names, src->pubkey_alg, &pkb));
			host_config->ckaid = clone_const_thing(pubkey_content.ckaid, "raw pubkey's ckaid");

			free_chunk_content(&keyspace);
			free_pubkey_content(&pubkey_content, verbose.logger);

			/* must-free keyspace */

		} else {

			/* must-free keyspace */

			/* add the public key */
			struct pubkey *pubkey = NULL; /* must pubkey_delref() */
			diag_t d = unpack_dns_pubkey(&id, PUBKEY_LOCAL,
						     src->pubkey_alg,
						     /*install_time*/realnow(),
						     /*until_time*/realtime_epoch,
						     /*ttl*/0,
						     HUNK_AS_SHUNK(keyspace),
						     &pubkey, verbose.logger);
			if (d != NULL) {
				free_chunk_content(&keyspace);
				return d;
			}

			/* must-free keyspace keyid pubkey */

			replace_pubkey(pubkey, &pluto_pubkeys);
			const ckaid_t *ckaid = pubkey_ckaid(pubkey);
			host_config->ckaid = clone_const_thing(*ckaid, "pubkey ckaid");
			pubkey_delref(&pubkey);

			/* must-free keyspace */
		}

		/* saved */
		vexpect(host_config->ckaid != NULL);

		/* must-free keyspace */

		/* try to pre-load the private key */
		bool load_needed;
		err = preload_private_key_by_ckaid(host_config->ckaid, &load_needed,
						   verbose.logger);
		if (err != NULL) {
			ckaid_buf ckb;
			vdbg("no private key matching %s CKAID %s: %s",
			     leftright, str_ckaid(host_config->ckaid, &ckb), err);
		} else if (load_needed) {
			ckaid_buf ckb;
			name_buf pkb;
			llog(LOG_STREAM/*not-whack-for-now*/, verbose.logger,
			     "loaded private key matching %s%s CKAID %s",
			     leftright, str_enum_long(&ipseckey_algorithm_config_names, src->pubkey_alg, &pkb),
			     str_ckaid(host_config->ckaid, &ckb));
		}

		free_chunk_content(&keyspace);

	} else if (src->ckaid != NULL) {
		diag_t d = extract_host_ckaid(host_config, src, same_ca, verbose);
		if (d != NULL) {
			return d;
		}
	}

	if (host_config->id.kind == ID_FROMCERT &&
	    host_config->cert.nss_cert != NULL) {
		host->id = id_from_cert(&host_config->cert);
		id_buf idb;
		vdbg("setting %s-id='%s' as host->config->id=%%fromcert",
		     leftright, str_id(&host->id, &idb));
	} else {
		id_buf idb;
		vdbg("setting %s-id='%s' as host->config->id)",
		     leftright, str_id(&host_config->id, &idb));
		host->id = clone_id(&host_config->id, __func__);
	}

	/* the rest is simple copying of corresponding fields */

	host_config->xauth.server = extract_yn(leftright, "xauthserver", src->xauthserver,
					       YN_NO, wm, verbose);
	host_config->xauth.client = extract_yn(leftright, "xauthclient", src->xauthclient,
					       YN_NO, wm, verbose);
	host_config->xauth.username = extract_string(leftright, "xauthusername",
						     src->xauthusername,
						     wm, verbose);
	enum eap_options autheap = extract_sparse_name(leftright, "autheap", src->autheap,
						       /*value_when_unset*/IKE_EAP_NONE,
						       &eap_option_names,
						       wm, &d, verbose);
	if (d != NULL) {
		return d;
	}

	host_config->eap = autheap;

	enum keyword_auth auth = extract_enum_name(leftright, "auth", src->auth,
						   /*value_when_unset*/AUTH_UNSET,
						   &keyword_auth_names,
						   wm, &d, verbose);
	if (d != NULL) {
		return d;
	}

	if (autheap == IKE_EAP_NONE && auth == AUTH_EAPONLY) {
		return diag("leftauth/rightauth can only be 'eaponly' when using leftautheap/rightautheap is not 'none'");
	}

	/*
	 * Determine the authentication from auth= and authby=.
	 */

	if (is_never_negotiate_wm(wm) && auth != AUTH_UNSET && auth != AUTH_NEVER) {
		/* AUTH_UNSET is updated below */
		name_buf ab;
		return diag("%sauth=%s option is invalid for type=passthrough connection",
			    leftright, str_enum_short(&keyword_auth_names, auth, &ab));
	}

	struct authby authby = whack_authby;

	/*
	 * IKEv1 only allows symetric authentication using authby=
	 * ({left,right}auth= can be asymetric).
	 *
	 * Convert authby= into auth=.
	 */
	if (ike_version == IKEv1) {
		/* override auth= using above authby= from whack */
		if (auth != AUTH_UNSET) {
			return diag("%sauth= is not supported by IKEv1", leftright);
		}
		/*
		 * From AUTHBY, which has multiple authentication bits
		 * set, select the best possible AUTH.  Since
		 * extract_authby(IKEv1) rejects ecdsa et.al. auth
		 * should not end up with ECDSA et.al.
		 */
		auth = auth_from_authby(whack_authby);
		/*
		 * Now use AUTH to generate AUTHBY with a single bit
		 * set (when RSA, both the rsasig and rsasig_v1_5 bits
		 * are set, so scrub the latter as it isn't supported
		 * by IKEv1).
		 */
		authby = authby_from_auth(auth);
		authby.rsasig_v1_5 = false; /* not supported */
		/*
		 * Now compare the rebuilt AUTH with the original
		 * WHACK_AUTH, looking for auth bits that disappeared.
		 */
		struct authby exclude = authby_not(authby);
		struct authby supplied = whack_authby;
		supplied.rsasig_v1_5 = false;
		supplied.ecdsa = false;
		struct authby unexpected = authby_and(supplied, exclude);
		if (authby_is_set(unexpected)) {
			authby_buf wb, ub;
			return diag("additional %s in authby=%s is not supported by IKEv1",
				    str_authby(unexpected, &ub),
				    str_authby(supplied, &wb));
		}
	}

	struct authby authby_mask = {0};
	switch (auth) {
	case AUTH_RSASIG:
		authby_mask = AUTHBY_RSASIG;
		break;
	case AUTH_ECDSA:
		authby_mask = AUTHBY_ECDSA;
		break;
	case AUTH_PSK:
		/* force only bit (not on by default) */
		authby = (struct authby) { .psk = true, };
		break;
	case AUTH_NULL:
		/* force only bit (not on by default) */
		authby = (struct authby) { .null = true, };
		break;
	case AUTH_UNSET:
		auth = auth_from_authby(authby);
		break;
	case AUTH_EAPONLY:
		break;
	case AUTH_NEVER:
		break;
	}

	if (authby_is_set(authby_mask)) {
		authby = authby_and(authby, authby_mask);
		if (!authby_is_set(authby)) {
			name_buf ab;
			authby_buf pb;
			return diag("%sauth=%s expects authby=%s",
				    leftright,
				    str_enum_short(&keyword_auth_names, auth, &ab),
				    str_authby(authby_mask, &pb));
		}
	}

	name_buf eab;
	authby_buf wabb;
	authby_buf eabb;
	vdbg("fake %sauth=%s %sauthby=%s from whack authby %s",
	     src->leftright, str_enum_short(&keyword_auth_names, auth, &eab),
	     src->leftright, str_authby(authby, &eabb),
	     str_authby(whack_authby, &wabb));
	host_config->auth = auth;
	host_config->authby = authby;

	if (src->id != NULL && streq(src->id, "%fromcert")) {
		if (auth == AUTH_PSK || auth == AUTH_NULL) {
			return diag("ID cannot be specified as %%fromcert if PSK or AUTH-NULL is used");
		}
	}

	host_config->sendcert = extract_sparse_name(leftright, "sendcert", src->sendcert,
						    cert_defaultcertpolicy, &sendcert_policy_names,
						    wm, &d, verbose);
	if (d != NULL) {
		return d;
	}

	if (can_extract_string(leftright, "ikeport", src->ikeport, wm, verbose)) {
		err = ttoport(shunk1(src->ikeport), &host_config->ikeport);
		if (err != NULL) {
			return diag("%sikeport=%s invalid, %s", leftright, src->ikeport, err);
		}
		if (!port_is_specified(host_config->ikeport)) {
			return diag("%sikeport=%s invalid, must be in range 1-65535",
				    leftright, src->ikeport);
		}
	}

	/*
	 * Check for consistency between modecfgclient=,
	 * modecfgserver=, cat= and addresspool=.
	 *
	 * Danger:
	 *
	 * Since OE configurations can be both the client and the
	 * server they allow contradictions such as both
	 * leftmodecfgclient=yes leftmodecfgserver=yes.
	 *
	 * Danger:
	 *
	 * It's common practice to specify leftmodecfgclient=yes
	 * rightmodecfgserver=yes even though "right" isn't properly
	 * configured (for instance expecting leftaddresspool).
	 */

	if (src->modecfgserver == YN_YES && src->modecfgclient == YN_YES) {
		diag_t d = diag("both %smodecfgserver=yes and %smodecfgclient=yes defined",
				leftright, leftright);
		if (!is_opportunistic_wm(host_addrs)) {
			return d;
		}
		vlog("opportunistic: %s", str_diag(d));
		pfree_diag(&d);
	}

	if (src->modecfgserver == YN_YES && src->cat == YN_YES) {
		diag_t d = diag("both %smodecfgserver=yes and %scat=yes defined",
				leftright, leftright);
		if (!is_opportunistic_wm(host_addrs)) {
			return d;
		}
		vlog("opportunistic: %s", str_diag(d));
		pfree_diag(&d);
	}

	if (src->modecfgclient == YN_YES && other_src->cat == YN_YES) {
		diag_t d = diag("both %smodecfgclient=yes and %scat=yes defined",
				leftright, other_src->leftright);
		if (!is_opportunistic_wm(host_addrs)) {
			return d;
		}
		vlog("opportunistic: %s", str_diag(d));
		pfree_diag(&d);
	}

	if (src->modecfgserver == YN_YES && src->addresspool != NULL) {
		diag_t d = diag("%smodecfgserver=yes does not expect %saddresspool=",
				leftright, src->leftright);
		if (!is_opportunistic_wm(host_addrs)) {
			return d;
		}
		vlog("opportunistic: %s", str_diag(d));
		pfree_diag(&d);
	}

	/*
	 * XXX: this can't be rejected.  For instance, in
	 * ikev1-psk-dual-behind-nat-01, road has
	 * <east>modecfgserver=yes, but doesn't specify the address
	 * pool.  Arguably modecfgserver= should be ignored?
	 */
#if 0
	if (src->modecfgserver == YN_YES && other_src->addresspool == NULL) {
		diag_t d = diag("%smodecfgserver=yes expects %saddresspool=",
				leftright, other_src->leftright);
		if (!is_opportunistic_wm(wm)) {
			return d;
		}
		vlog("opportunistic: %s", str_diag(d));
		pfree_diag(&d);
	}
#endif

	if (src->modecfgclient == YN_YES && other_src->addresspool != NULL) {
		diag_t d = diag("%smodecfgclient=yes does not expect %saddresspool=",
				leftright, other_src->leftright);
		if (!is_opportunistic_wm(host_addrs)) {
			return d;
		}
		vlog("opportunistic: %s", str_diag(d));
		pfree_diag(&d);
	}

	if (src->cat == YN_YES && other_src->addresspool != NULL) {
		diag_t d = diag("both %scat=yes and %saddresspool= defined",
				leftright, other_src->leftright);
		if (!is_opportunistic_wm(host_addrs)) {
			return d;
		}
		vlog("opportunistic: %s", str_diag(d));
		pfree_diag(&d);
	}

	/*
	 * Update client/server based on config and addresspool
	 *
	 * The update uses OR so that the truth is blended with both
	 * the ADDRESSPOOL code's truth (see further down) and the
	 * reverse calls sense of truth.
	 *
	 * Unfortunately, no!
	 *
	 * This end having an addresspool should imply that this host
	 * is the client and the other host is the server.  Right?
	 *
	 * OE configurations have leftmodecfgclient=yes
	 * rightaddresspool= which creates a the connection that is
	 * both a client and a server.
	 */

	host_config->modecfg.server |= (src->modecfgserver == YN_YES);
	host_config->modecfg.client |= (src->modecfgclient == YN_YES);

	if (src->addresspool != NULL) {
		other_host_config->modecfg.server = true;
		host_config->modecfg.client = true;
		vdbg("forced %s modecfg client=%s %s modecfg server=%s",
		     host_config->leftright, bool_str(host_config->modecfg.client),
		     other_host_config->leftright, bool_str(other_host_config->modecfg.server));
	}

	return NULL;
}

static diag_t extract_child_end_config(const struct whack_message *wm,
				       const struct whack_end *src,
				       const struct host_addr_config *host_addr,
				       ip_protoport protoport,
				       enum ike_version ike_version,
				       struct connection *c,
				       struct child_end_config *child_config,
				       struct verbose verbose)
{
	diag_t d = NULL;
	const char *leftright = src->leftright;

	switch (ike_version) {
	case IKEv2:
#ifdef USE_CAT
		child_config->has_client_address_translation = (src->cat == YN_YES);
#endif
		break;
	case IKEv1:
		if (src->cat != YN_UNSET) {
			name_buf nb;
			vwarning("IKEv1, ignoring %scat=%s (client address translation)",
				 leftright, str_sparse_long(&yn_option_names, src->cat, &nb));
		}
		break;
	default:
		bad_case(ike_version);
	}

	child_config->vti_ip =
		extract_cidr_num(leftright, "vti", src->vti, wm, &d, verbose);
	if (d != NULL) {
		return d;
	}

	child_config->ipsec_interface_ip =
		extract_cidr_num(leftright, "interface-ip", src->interface_ip, wm, &d, verbose);
	if (d != NULL) {
		return d;
	}

	child_config->protoport = protoport;

	/*
	 * Support for skipping updown, eg leftupdown="" or %disabled.
	 *
	 * Useful on busy servers that do not need to use updown for
	 * anything.
	 */
	if (never_negotiate_string_option(leftright, "updown", src->updown, wm, verbose)) {
		vdbg("never-negotiate updown");
	} else {
		/* Note: "" disables updown; but no updown gets default */
		child_config->updown =
			(src->updown == NULL ? clone_str(DEFAULT_UPDOWN, "default_updown") :
			 streq(src->updown, UPDOWN_DISABLED) ? NULL :
			 streq(src->updown, "") ? NULL :
			 clone_str(src->updown, "child_config.updown"));
	}


	ip_selectors *child_selectors = &child_config->selectors;

	/*
	 * Figure out the end's child selectors.
	 */
	if (src->addresspool != NULL) {

		/*
		 * Both ends can't add an address pool (cross
		 * checked).
		 */
		FOR_EACH_ELEMENT(pool, c->pool) {
			vassert((*pool) == NULL);
		}

		if (src->subnets != NULL) {
			/* XXX: why? */
			return diag("cannot specify both %saddresspool= and %ssubnets=",
				    leftright, leftright);
		}

		if (src->subnet != NULL) {
			/* XXX: why? */
			return diag("cannot specify both %saddresspool= and %ssubnet=",
				    leftright, leftright);
		}

		diag_t d = ttoranges_num(shunk1(src->addresspool), ", ", NULL,
					 &child_config->addresspools);
		if (d != NULL) {
			return diag_diag(&d, "%saddresspool=%s invalid, ", leftright, src->addresspool);
		}

		FOR_EACH_ITEM(range, &child_config->addresspools) {

			const struct ip_info *afi = range_type(range);

			if (ike_version == IKEv1 && afi == &ipv6_info) {
				return diag("%saddresspool=%s invalid, IKEv1 does not support IPv6 address pool",
					    leftright, src->addresspool);
			}

			if (afi == &ipv6_info && !range_is_cidr((*range))) {
				range_buf rb;
				return diag("%saddresspool=%s invalid, IPv6 range %s is not a subnet",
					    leftright, src->addresspool,
					    str_range(range, &rb));
			}

			/*
			 * Create the address pool regardless of
			 * orientation.  Orienting will then add a
			 * reference as needed.
			 *
			 * This way, conflicting addresspools are
			 * detected early (OTOH, they may be detected
			 * when they don't matter).
			 *
			 * This also detetects and rejects multiple
			 * pools with the same address family.
			 */
			diag_t d = install_addresspool((*range), child_config->addresspool,
						       verbose.logger);
			if (d != NULL) {
				return diag_diag(&d, "%saddresspool=%s invalid, ",
						 leftright, src->addresspool);
			}

		}

	} else if (src->subnet != NULL) {

		/*
		 * Parse new syntax (protoport= is not used).
		 *
		 * Of course if NARROWING is allowed, this can be
		 * refined regardless of .has_client.
		 */
		vdbg("%s child selectors from %ssubnet (selector); %s.config.has_client=true",
		     leftright, leftright, leftright);
		ip_address nonzero_host;
		diag_t d = ttoselectors_num(shunk1(src->subnet), ", ", NULL,
					    &child_config->selectors, &nonzero_host);
		if (d != NULL) {
			return diag_diag(&d, "%ssubnet=%s invalid, ",
					 leftright, src->subnet);
		}

		if (protoport.ip.is_set) {
			if (child_config->selectors.len > 1) {
				return diag("%ssubnet= must be a single subnet when combined with %sprotoport=",
					    leftright, leftright);
			}
			if (!selector_is_subnet(child_config->selectors.list[0])) {
				return diag("%ssubnet= cannot be a selector when combined with %sprotoport=",
					    leftright, leftright);
			}
			ip_subnet subnet = selector_subnet(child_config->selectors.list[0]);
			vdbg("%s child selectors from %ssubnet + %sprotoport; %s.config.has_client=true",
			     leftright, leftright, leftright, leftright);
			child_selectors->list[0] =
				selector_from_subnet_protoport(subnet, protoport);
		}

		if (nonzero_host.ip.is_set) {
			address_buf hb;
			vlog("zeroing non-zero address identifier %s in %ssubnet=%s",
			     str_address(&nonzero_host, &hb), leftright, src->subnet);
		}

	} else {
		vdbg("%s child selectors unknown; probably derived from host?!?",
		     leftright);
	}

	/*
	 * Also extract .virt.
	 *
	 * While subnet= can only specify .virt XOR .client, the end
	 * result can be that both .virt and .client are set.
	 *
	 * XXX: don't set .has_client as update_child_ends*() will see
	 * it and skip updating the client address from the host.
	 */
	if (src->virt != NULL) {
		if (ike_version > IKEv1) {
			return diag("IKEv%d does not support virtual subnets",
				    ike_version);
		}
		vdbg("%s %s child has a virt-end", wm->name, leftright);
		diag_t d = create_virtual(leftright, src->virt,
					  &child_config->virt);
		if (d != NULL) {
			return d;
		}
	}

	/*
	 * Get the SOURCEIPs and check that they all fit within at
	 * least one selector determined above (remember, when the
	 * selector isn't specified (i.e., subnet=), the selector is
	 * set to the .host_addr).
	 */

	if (src->sourceip != NULL) {
		if (src->interface_ip != NULL) {
			return diag("cannot specify %sinterface-ip=%s and %sssourceip=%s",
				    leftright, src->interface_ip,
				    leftright, src->sourceip);
		}

		diag_t d = ttoaddresses_num(shunk1(src->sourceip), ", ",
					    NULL/*UNSPEC*/, &child_config->sourceip);
		if (d != NULL) {
			return diag_diag(&d, "%ssourceip=%s invalid, ",
					 src->leftright, src->sourceip);
		}
		/* valid? */
		ip_address seen[IP_VERSION_ROOF] = {0};
		FOR_EACH_ITEM(sourceip, &child_config->sourceip) {

			/* i.e., not :: and not 0.0.0.0 */
			if (!address_is_specified(*sourceip)) {
				return diag("%ssourceip=%s invalid, must be a valid address",
					    leftright, src->sourceip);
			}

			/* i.e., not 1::1,1::2 */
			const struct ip_info *afi = address_type(sourceip);
			vassert(afi != NULL); /* since specified */
			if (seen[afi->ip.version].ip.is_set) {
				address_buf sb, ipb;
				return diag("%ssourceip=%s invalid, multiple %s addresses (%s and %s) specified",
					    leftright, src->sourceip, afi->ip_name,
					    str_address(&seen[afi->ip.version], &sb),
					    str_address(sourceip, &ipb));
			}
			seen[afi->ip.version] = (*sourceip);

			if (child_config->selectors.len > 0) {
				/* skip aliases; they hide the selectors list */
				if (wm->connalias != NULL) {
					continue;
				}
				bool within = false;
				FOR_EACH_ITEM(sel, &child_config->selectors) {
					/*
					 * Only compare the address
					 * against the selector's
					 * address range (not the
					 * /protocol/port).
					 *
					 * For instance when the
					 * selector is:
					 *
					 *   1::/128/tcp/22
					 *
					 * the sourceip=1:: is still
					 * ok.
					 */
					if (address_in_selector_range(*sourceip, *sel)) {
						within = true;
						break;
					}
				}
				if (!within) {
					address_buf sipb;
					return diag("%ssourceip=%s invalid, address %s is not within %ssubnet=%s",
						    leftright, src->sourceip,
						    str_address(sourceip, &sipb),
						    leftright, src->subnet);
				}
			} else if (host_addr->addr.ip.is_set) {
				if (!address_eq_address(*sourceip, host_addr->addr)) {
					address_buf sipb;
					address_buf hab;
					return diag("%ssourceip=%s invalid, address %s does not match %s=%s and %ssubnet= was not specified",
						    leftright, src->sourceip,
						    str_address(sourceip, &sipb),
						    leftright, str_address(&host_addr->addr, &hab),
						    leftright);
				}
			} else {
				return diag("%ssourceip=%s invalid, %ssubnet= unspecified and %s IP address unknown",
					    leftright, src->sourceip,
					    leftright/*subnet=*/, leftright/*host=*/);
			}
		}
	}
	return NULL;
}

/* only used by add_connection() */

static diag_t mark_parse(const char *leftright, const char *name, const char *mark,
			 struct sa_mark *sa_mark)
{
	(*sa_mark) = (struct sa_mark) {
		.unique = false,
		.val = UINT32_MAX,
		.mask = UINT32_MAX,
	};

	shunk_t cursor = shunk1(mark);
	intmax_t value;
	err_t e = shunk_to_intmax(cursor, &cursor, 0, &value);
	if (e != NULL) {
		return diag("%s%s=\"%s\" value invalid, %s",
			    leftright, name, mark, e);
	}
	if (value > UINT32_MAX) {
		return diag("%s%s=\"%s\" value invalid, %jd is larger than %#08"PRIx32,
			    leftright, name, mark,
			    value, UINT32_MAX);
	}
	if (value < -1) {
		return diag("%s%s=\"%s\" value invalid, %jd is less than -1",
			    leftright, name, mark, value);
	}
	if (cursor.len > 0 && hunk_char(cursor, 0) != '/') {
		return diag("%s%s=\"%s\" value invalid, contains trailing junk \""PRI_SHUNK"\"",
			    leftright, name, mark, pri_shunk(cursor));
	}
	sa_mark->val = value;

	if (hunk_streat(&cursor, "/")) {
		uintmax_t mask;
		err_t e = shunk_to_uintmax(cursor, &cursor, 0, &mask);
		if (e != NULL) {
			return diag("%s%s=\"%s\" mask invalid, %s",
				    leftright, name, mark, e);
		}
		if (mask > UINT32_MAX) {
			return diag("%s%s=\"%s\" mask invalid, %jd is larger than %#08"PRIx32,
				    leftright, name, mark,
				    mask, UINT32_MAX);
		}
		if (cursor.len > 0) {
			return diag("%s%s=\"%s\" mask invalid, contains trailing junk \""PRI_SHUNK"\"",
				    leftright, name, mark, pri_shunk(cursor));
		}
		sa_mark->mask = mask;
	}
	if ((sa_mark->val & ~sa_mark->mask) != 0) {
		return diag("%s%s=\"%s\" invalid, value %#08"PRIx32" has bits outside mask %#08"PRIx32,
			    leftright, name, mark, sa_mark->val, sa_mark->mask);
	}
	return NULL;
}

/*
 * Extract the connection detail from the whack message WM and store
 * them in the connection C.
 *
 * This code is responsible for cloning strings and other structures
 * so that they out live the whack message.  When things go wrong,
 * return false, the caller will then use discard_connection() to free
 * the partially constructed connection.
 *
 * Checks from confread/whack should be moved here so it is similar
 * for all methods of loading a connection.
 *
 * XXX: at one point this code was populating the connection with
 * pointer's to the whack message's strings and then trying to use
 * unshare_connection() to create local copies.  Bad idea.  For
 * instance, it duplicated the proposal pointers yet here the pointer
 * was freshy allocated so no duplication should be needed (or at
 * least shouldn't be) (look for strange free() vs delref() sequence).
 */

static diag_t extract_lifetime(deltatime_t *lifetime,
			       const char *lifetime_name,
			       deltatime_t whack_lifetime,
			       deltatime_t default_lifetime,
			       deltatime_t lifetime_max,
			       deltatime_t lifetime_fips,
			       deltatime_t rekeymargin,
			       uintmax_t rekeyfuzz_percent,
			       struct verbose verbose,
			       const struct whack_message *wm)
{
	const char *source;
	if (whack_lifetime.is_set) {
		source = "whack";
		*lifetime = whack_lifetime;
	} else {
		source = "default";
		*lifetime = default_lifetime;
	}

	/*
	 * Determine the MAX lifetime
	 *
	 * http://csrc.nist.gov/publications/nistpubs/800-77/sp800-77.pdf
	 */
	const char *fips;
	deltatime_t max_lifetime;
	if (is_fips_mode()) {
		fips = "FIPS: ";
		max_lifetime = lifetime_fips;
	} else {
		fips = "";
		max_lifetime = lifetime_max;
	}

	if (impair.lifetime) {
		vlog("IMPAIR: skipping %s=%jd checks",
		     lifetime_name, deltasecs(*lifetime));
		return NULL;
	}

	/*
	 * Determine the minimum lifetime.  Use:
	 *
	 *    rekeymargin*(100+rekeyfuzz)/100
	 *
	 * which is the maximum possible rekey margin.  INT_MAX is
	 * arbitrary as an upper bound - anything to stop overflow.
	 */

	deltatime_t min_lifetime = deltatime_scale(rekeymargin,
						   100 + rekeyfuzz_percent,
						   100);

	if (deltatime_cmp(max_lifetime, <, min_lifetime)) {
		return diag("%s%s=%jd must be greater than rekeymargin=%jus + rekeyfuzz=%jd%% yet less than the maximum allowed %ju",
			    fips, 
			    lifetime_name, deltasecs(*lifetime),
			    deltasecs(rekeymargin), rekeyfuzz_percent,
			    deltasecs(min_lifetime));
	}

	if (deltatime_cmp(*lifetime, >, max_lifetime)) {
		vlog("%s%s=%ju seconds exceeds maximum of %ju seconds, setting to the maximum allowed",
		     fips,
		     lifetime_name, deltasecs(*lifetime),
		     deltasecs(max_lifetime));
		source = "max";
		*lifetime = max_lifetime;
	} else if (deltatime_cmp(*lifetime, <, min_lifetime)) {
		vlog("%s=%jd must be greater than rekeymargin=%jus + rekeyfuzz=%jd%%, setting to %jd seconds",
		     lifetime_name, deltasecs(*lifetime),
		     deltasecs(wm->rekeymargin),
		     rekeyfuzz_percent,
		     deltasecs(min_lifetime));
		source = "min";
		*lifetime = min_lifetime;
	}

	deltatime_buf db;
	vdbg("%s=%s (%s)", lifetime_name, source, str_deltatime(*lifetime, &db));
	return NULL;
}

static enum connection_kind extract_connection_end_kind(const struct whack_message *wm,
							enum end this_end,
							const struct host_addr_config *const host_addrs[END_ROOF],
							const ip_protoport protoport[END_ROOF],
							struct verbose verbose)
{
	const struct whack_end *this = &wm->end[this_end];
	enum end that_end = !this_end;
	const struct whack_end *that = &wm->end[that_end];

	if (is_group_wm(host_addrs)) {
		vdbg("%s connection is CK_GROUP: by is_group_wm()",
		     this->leftright);
		return CK_GROUP;
	}
	if (wm->sec_label != NULL) {
		vdbg("%s connection is CK_LABELED_TEMPLATE: has security label: %s",
		     this->leftright, wm->sec_label);
		return CK_LABELED_TEMPLATE;
	}
	if(wm->narrowing == YN_YES) {
		vdbg("%s connection is CK_TEMPLATE: narrowing=yes",
		     this->leftright);
		return CK_TEMPLATE;
	}
	if (that->virt != NULL) {
		/*
		 * A peer with subnet=vnet:.. needs instantiation so
		 * we can accept multiple subnets from that peer.
		 */
		vdbg("%s connection is CK_TEMPLATE: %s has vnets at play",
		     this->leftright, that->leftright);
		return CK_TEMPLATE;
	}
	if (that->addresspool != NULL) {
		vdbg("%s connection is CK_TEMPLATE: %s has an address pool",
		     this->leftright, that->leftright);
		return CK_TEMPLATE;
	}
	if (protoport[that_end].ip.is_set /*technically redundant but good form*/ &&
	    protoport[that_end].has_port_wildcard) {
		vdbg("%s connection is CK_TEMPLATE: %s child has protoport wildcard port",
		     this->leftright, that->leftright);
		return CK_TEMPLATE;
	}
	if (!is_never_negotiate_wm(wm)) {
		FOR_EACH_THING(lr, LEFT_END, RIGHT_END) {
			const struct host_addr_config *re = host_addrs[lr];
			if (re->type != KH_IPADDR &&
			    re->type != KH_IFACE &&
			    re->type != KH_DEFAULTROUTE &&
			    re->type != KH_IPHOSTNAME) {
				name_buf tb;
				vdbg("%s connection is CK_TEMPLATE: has policy negotiate yet %s address is %s",
				     this->leftright,
				     wm->end[lr].leftright,
				     str_sparse_short(&keyword_host_names, re->type, &tb));
				return CK_TEMPLATE;
			}
		}
	}
	vdbg("%s connection is CK_PERMANENT: by default",
	     this->leftright);
	return CK_PERMANENT;
}

static bool shunt_ok(enum shunt_kind shunt_kind, enum shunt_policy shunt_policy)
{
	static const bool ok[SHUNT_KIND_ROOF][SHUNT_POLICY_ROOF] = {
		[SHUNT_KIND_NONE] = {
			[SHUNT_UNSET] = true,
		},
		[SHUNT_KIND_NEVER_NEGOTIATE] = {
			[SHUNT_UNSET] = true,
			[SHUNT_NONE] = false, [SHUNT_TRAP] = false, [SHUNT_PASS] = true,  [SHUNT_DROP] = true,
		},
		[SHUNT_KIND_NEGOTIATION] = {
			[SHUNT_NONE] = false, [SHUNT_TRAP] = false, [SHUNT_PASS] = true,  [SHUNT_DROP] = true,
		},
		[SHUNT_KIND_FAILURE] = {
			[SHUNT_NONE] = true,  [SHUNT_TRAP] = false, [SHUNT_PASS] = true,  [SHUNT_DROP] = true,
		},
		/* hard-wired */
		[SHUNT_KIND_IPSEC] = { [SHUNT_IPSEC] = true, },
		[SHUNT_KIND_BLOCK] = { [SHUNT_DROP] = true, },
		[SHUNT_KIND_ONDEMAND] = { [SHUNT_TRAP] = true, },
	};
	return ok[shunt_kind][shunt_policy];
}

static diag_t extract_shunt(struct config *config,
			    const struct whack_message *wm,
			    enum shunt_kind shunt_kind,
			    const struct sparse_names *shunt_names,
			    enum shunt_policy unset_shunt)
{
	enum shunt_policy shunt_policy = wm->shunt[shunt_kind];
	if (shunt_policy == SHUNT_UNSET) {
		shunt_policy = unset_shunt;
	}
	if (!shunt_ok(shunt_kind, shunt_policy)) {
		JAMBUF(buf) {
			jam_enum_human(buf, &shunt_kind_names, shunt_kind);
			jam_string(buf, "shunt=");
			jam_sparse_long(buf, shunt_names, shunt_policy);
			jam_string(buf, " invalid");
			return diag_jambuf(buf);
		}
	}
	config->shunt[shunt_kind] = shunt_policy;
	return NULL;
}

static diag_t extract_cisco_host_config(struct cisco_host_config *cisco,
					const struct whack_message *wm,
					struct verbose verbose)
{
	diag_t d = NULL;

	enum remote_peer_type remote_peer_type = extract_sparse_name("", "remote-peer-type",
								     wm->remote_peer_type,
								     REMOTE_PEER_IETF,
								     &remote_peer_type_names,
								     wm, &d, verbose);
	if (d != NULL) {
		return d;
	}

	enum yn_options cisco_unity = extract_sparse_name("", "cisco-unity", wm->cisco_unity,
							  /*value_when_unset*/YN_NO,
							  &yn_option_names,
							  wm, &d, verbose);
	if (d != NULL) {
		return d;
	}

	enum yn_options nm_configured = extract_sparse_name("", "nm-configured", wm->nm_configured,
							    /*value_when_unset*/YN_NO,
							    &yn_option_names,
							    wm, &d, verbose);
	if (d != NULL) {
		return d;
	}

	enum yn_options cisco_split = extract_sparse_name("", "cisco-split", wm->cisco_split,
							  /*value_when_unset*/YN_NO,
							  &yn_option_names,
							  wm, &d, verbose);
	if (d != NULL) {
		return d;
	}

	cisco->peer = (remote_peer_type == REMOTE_PEER_CISCO);
	cisco->unity = (cisco_unity == YN_YES);
	cisco->nm = (nm_configured == YN_YES);
	cisco->split = (cisco_split == YN_YES);

	return NULL;
}


static const struct ike_info *const ike_info[] = {
	[IKEv1] = &ikev1_info,
	[IKEv2] = &ikev2_info,
};

static enum ike_version extract_ike_version(const struct whack_message *wm,
					    diag_t *d, struct verbose verbose)
{
	enum ike_version keyexchange = extract_sparse_name("", "keyexchange", wm->keyexchange,
							   /*value_when_unset*/0,
							   &keyexchange_option_names,
							   wm, d, verbose);
	if ((*d) != NULL) {
		return 0;
	}

	enum yn_options ikev2 = extract_sparse_name("", "ikev2", wm->ikev2,
						    /*value_when_unset*/0,
						    &ikev2_option_names,
						    wm, d, verbose);
	if ((*d) != NULL) {
		return 0;
	}

	enum ike_version ike_version;
	if (keyexchange == 0 || keyexchange == IKE_VERSION_ROOF) {
		ike_version = (ikev2 == YN_NO ? IKEv1 : IKEv2);
	} else {
		ike_version = keyexchange;
	}

	if ((ike_version == IKEv1 && ikev2 == YN_YES) ||
	    (ike_version == IKEv2 && ikev2 == YN_NO)) {
		/* can only get conflict when both keyexchange= and
		 * ikev2= are specified */
		name_buf ib, ivb;
		vlog("ignoring ikev2=%s which conflicts with keyexchange=%s",
		     str_sparse_short(&ikev2_option_names, ikev2, &ib),
		     str_sparse_short(&keyexchange_option_names, ike_version, &ivb));
	} else if (ikev2 != 0) {
		name_buf ib, ivb;
		vlog("ikev2=%s has been replaced by keyexchange=%s",
		     str_sparse_short(&ikev2_option_names, ikev2, &ib),
		     str_sparse_short(&keyexchange_option_names, ike_version, &ivb));
	}

	return ike_version;
}

static diag_t extract_encap_alg(const char **encap_alg,
				const char *name, const char *value,
				const struct whack_message *wm)
{
	if (wm->phase2alg == NULL) {
		(*encap_alg) = value; /* could be NULL */
		return NULL;
	}
	if (value == NULL) {
		(*encap_alg) = wm->phase2alg; /* can't be NULL */
		return NULL;
	}
	return diag("'%s=%s conficts with 'phase2alg=%s'",
		    name, value, wm->phase2alg);
}

static diag_t extract_encap_proto(enum encap_proto *encap_proto, const char **encap_alg,
				  const struct whack_message *wm, struct verbose verbose)
{
	if (never_negotiate_enum_option("", "phase2", wm->phase2,
					&encap_proto_story, wm, verbose)) {
		vdbg("never-negotiate phase2");
		(*encap_proto) = ENCAP_PROTO_UNSET;
		(*encap_alg) = NULL;
		return NULL;
	}

	/*
	 * Given phase2=... esp=... ah=..., pick the one that matches
	 * phase2=...
	 */

	(*encap_proto) = wm->phase2;

	switch ((*encap_proto)) {

	case ENCAP_PROTO_AH:
		return extract_encap_alg(encap_alg, "ah", wm->ah, wm);

	case ENCAP_PROTO_ESP:
		return extract_encap_alg(encap_alg, "esp", wm->esp, wm);

	case ENCAP_PROTO_UNSET:
		if (wm->ah == NULL && wm->esp == NULL) {
			(*encap_alg) = wm->phase2alg;
			(*encap_proto) = ENCAP_PROTO_ESP;
			break;
		}

		if (wm->ah != NULL) {
			(*encap_proto) = ENCAP_PROTO_AH;
			(*encap_alg) = wm->ah;
			break;
		}

		if (wm->esp != NULL) {
			(*encap_proto) = ENCAP_PROTO_ESP;
			(*encap_alg) = wm->esp;
			break;
		}

		return diag("can not distinguish between 'ah=%s' and 'esp=%s' without 'phase2='",
			    wm->ah, wm->esp);
	}

	return NULL;
}

diag_t extract_connection(const struct whack_message *wm,
			  struct connection *c,
			  struct config *config,
			  struct verbose verbose)
{
	diag_t d = NULL;

	enum ike_version ike_version = extract_ike_version(wm, &d, verbose);
	if (d != NULL) {
		return d;
	}

	config->ike_version = ike_version;

	const struct whack_end *whack_ends[] = {
		[LEFT_END] = &wm->end[LEFT_END],
		[RIGHT_END] = &wm->end[RIGHT_END],
	};

	/*
	 * Extract {left,right} and {left,right}nexthop.
	 *
	 * To make cleanup easier (the code clones whack message's
	 * .host and .nexthop strings) the results are stored directly
	 * into CONFIG.
	 *
	 * To stop follow-on code directly accessing CONFIG values,
	 * the table HOST_ADDRS[] is created and passed around.
	 */

	d = extract_host_addrs(wm, config, verbose);
	if (d != NULL) {
		return d;
	}

	const struct ip_info *host_afi = config->host.afi;
	vassert(host_afi != NULL);

	const struct host_addr_config *const host_addrs[END_ROOF] = {
		[LEFT_END] = &config->end[LEFT_END].host.host,
		[RIGHT_END] = &config->end[RIGHT_END].host.host,
	};

	/*
	 * Turn the .authby string into struct authby bit struct.
	 */
	struct authby whack_authby = {0};
	lset_t sighash_policy = LEMPTY;
	d = extract_authby(&whack_authby, &sighash_policy, ike_version, wm);
	if (d != NULL) {
		return d;
	}

	/*
	 * Unpack and verify the ends.
	 */

	bool same_ca[END_ROOF] = { false, };

	FOR_EACH_THING(this, LEFT_END, RIGHT_END) {
		diag_t d;
		int that = (this + 1) % END_ROOF;
		d = extract_host_end(&c->end[this].host,
				     &config->end[this].host,
				     &config->end[that].host,
				     wm,
				     whack_ends[this],
				     whack_ends[that],
				     host_addrs[this],
				     host_addrs,
				     ike_version, whack_authby,
				     &same_ca[this],
				     verbose);
		if (d != NULL) {
			return d;
		}
	}

	/*
	 * Pre-extract the protoport.  It's merged into the subnet
	 * forming selectors.  Valid both with never-negotiate and
	 * normal connections.
	 */

	ip_protoport protoport[END_ROOF] = {0};
	FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
		const char *pp = wm->end[end].protoport;
		const char *leftright = wm->end[end].leftright;
		if (pp != NULL) {
			err_t ugh = ttoprotoport(shunk1(pp), &protoport[end]);
			if (ugh != NULL) {
				return diag("%sprotoport=%s invalid, %s",
					    leftright, pp, ugh);
			}
		}
	}

	/* some port stuff */

	if (protoport[LEFT_END].ip.is_set && protoport[LEFT_END].has_port_wildcard &&
	    protoport[RIGHT_END].ip.is_set && protoport[RIGHT_END].has_port_wildcard) {
		return diag("cannot have protoports with wildcard (%%any) ports on both sides");
	}

	/*
	 * Determine the connection KIND from the wm.
	 *
	 * Save it in a local variable so code can use that (and be
	 * forced to only use value after it's been determined).  Yea,
	 * hack.
	 */
	FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
		c->end[end].kind = extract_connection_end_kind(wm, end,
							       host_addrs,
							       protoport,
							       verbose);
	}

	vassert(c->base_name != NULL); /* see alloc_connection() */

	/*
	 * Extract policy bits.
	 */

	bool pfs = extract_yn("", "pfs", wm->pfs,
			      /*value_when_unset*/YN_YES,
			      wm, verbose);
	config->child.pfs = pfs;

	bool compress = extract_yn("", "compress", wm->compress,
				   /*value_when_unset*/YN_NO,
				   wm, verbose);
	config->child.ipcomp = compress;

	/*
	 * Extract the encapsulation protocol ESP/AH.
	 */

	enum encap_proto encap_proto = ENCAP_PROTO_UNSET;
	const char *encap_alg = NULL;
	d = extract_encap_proto(&encap_proto, &encap_alg, wm, verbose);
	if (d != NULL) {
		return d;
	}

	config->child.encap_proto = encap_proto;

	enum encap_mode encap_mode;
	if (wm->type == KS_UNSET) {
		encap_mode = ENCAP_MODE_TUNNEL;
	} else if (wm->type == KS_TUNNEL) {
		encap_mode = ENCAP_MODE_TUNNEL;
	} else if (wm->type == KS_TRANSPORT) {
		encap_mode = ENCAP_MODE_TRANSPORT;
	} else {
		if (!is_never_negotiate_wm(wm)) {
			name_buf sb;
			vlog_pexpect(HERE,
				     "type=%s should be never-negotiate",
				     str_sparse_long(&type_option_names, wm->type, &sb));
		}
		encap_mode = ENCAP_MODE_UNSET;
	}
	config->child.encap_mode = encap_mode;

	if (encap_mode == ENCAP_MODE_TRANSPORT) {
		if (wm->vti_interface != NULL) {
			return diag("VTI requires tunnel mode but connection specifies type=transport");
		}
	}

	if (whack_authby.never) {
		if (wm->never_negotiate_shunt == SHUNT_UNSET) {
			return diag("connection with authby=never must specify shunt type via type=");
		}
	}
	if (wm->never_negotiate_shunt != SHUNT_UNSET) {
		if (!authby_eq(whack_authby, AUTHBY_NONE) &&
		    !authby_eq(whack_authby, AUTHBY_NEVER)) {
			authby_buf ab;
			name_buf sb;
			return diag("kind=%s shunt connection cannot have authby=%s authentication",
				    str_sparse_short(&never_negotiate_shunt_names, wm->never_negotiate_shunt, &sb),
				    str_authby(whack_authby, &ab));
		}
	}

	if (ike_version == IKEv1) {
#ifdef USE_IKEv1
		/* avoid using global */
		enum global_ikev1_policy ikev1_policy =
			config_setup_option(config_setup_singleton(), KBF_IKEv1_POLICY);
		if (ikev1_policy != GLOBAL_IKEv1_ACCEPT) {
			name_buf pb;
			return diag("global ikev1-policy=%s does not allow IKEv1 connections",
				    str_sparse_long(&global_ikev1_policy_names,
						    ikev1_policy, &pb));
		}
#else
		return diag("IKEv1 support not compiled in");
#endif
	}

	vassert(ike_version < elemsof(ike_info));
	vassert(ike_info[ike_version] != NULL);
	config->ike_info = ike_info[ike_version];
	vassert(config->ike_info->version > 0);

#if 0
	PASSERT(verbose,
		is_opportunistic_wm(host_addr) == ((wm->policy & POLICY_OPPORTUNISTIC) != LEMPTY));
	vassert(is_group_wm(host_addr) == wm->is_connection_group);
#endif

	if (is_opportunistic_wm(host_addrs) && c->config->ike_version < IKEv2) {
		return diag("opportunistic connection MUST have IKEv2");
	}
	config->opportunistic = is_opportunistic_wm(host_addrs);

#if 0
	if (is_opportunistic_wm(host_addr)) {
		if (whack_authby.psk) {
			return diag("PSK is not supported for opportunism");
		}
		if (!authby_has_digsig(whack_authby)) {
			return diag("only Digital Signatures are supported for opportunism");
		}
		if (!pfs) {
			return diag("PFS required for opportunism");
		}
	}
#endif

	bool intermediate = extract_yn("", "intermediate", wm->intermediate,
				       /*value_when_unset*/YN_NO,
				       wm, verbose);
	if (intermediate) {
		if (ike_version < IKEv2) {
			return diag("intermediate requires IKEv2");
		}
	}
	config->intermediate = intermediate;

	config->session_resumption = extract_yn("", "session_resumption", wm->session_resumption,
						/*value_when_unset*/YN_NO,
						wm, verbose);
	if (config->session_resumption) {
		if (ike_version < IKEv2) {
			return diag("session resumption requires IKEv2");
		}
	}

	config->sha2_truncbug = extract_yn("", "sha2-truncbug", wm->sha2_truncbug,
					   /*value_when_unset*/YN_NO,
					   wm, verbose);
	config->share_lease = extract_yn("", "share_lease", wm->share_lease,
					   /*value_when_unset*/YN_YES,
					   wm, verbose);
	config->overlapip = extract_yn("", "overlapip", wm->overlapip,
				       /*value_when_unset*/YN_NO, wm, verbose);

	bool ms_dh_downgrade = extract_yn("", "ms-dh-downgrade", wm->ms_dh_downgrade,
					  /*value_when_unset*/YN_NO, wm, verbose);
	bool pfs_rekey_workaround = extract_yn("", "pfs-rekey-workaround", wm->pfs_rekey_workaround,
					       /*value_when_unset*/YN_NO, wm, verbose);
	if (ms_dh_downgrade && pfs_rekey_workaround) {
		return diag("cannot specify both ms-dh-downgrade=yes and pfs-rekey-workaround=yes");
	}
	config->ms_dh_downgrade = ms_dh_downgrade;
	config->pfs_rekey_workaround = pfs_rekey_workaround;

	config->dns_match_id = extract_yn("", "dns-match-id", wm->dns_match_id,
					  /*value_when_unset*/YN_NO, wm, verbose);
	/* IKEv2 only; IKEv1 uses xauth=pam */
	config->ikev2_pam_authorize = extract_yn("", "pam-authorize", wm->pam_authorize,
						 /*value_when_unset*/YN_NO, wm, verbose);

	if (ike_version >= IKEv2) {
		if (wm->ikepad != YNA_UNSET) {
			name_buf vn, pn;
			vwarning("%s connection ignores ikepad=%s",
			     str_enum_long(&ike_version_names, ike_version, &vn),
			     str_sparse_long(&yna_option_names, wm->ikepad, &pn));
		}
		/* default */
		config->v1_ikepad.message = true;
		config->v1_ikepad.modecfg = false;
	} else {
		config->v1_ikepad.modecfg = (wm->ikepad == YNA_YES);
		config->v1_ikepad.message = (wm->ikepad != YNA_NO);
	}

	config->require_id_on_certificate = extract_yn("", "require-id-on-certificate", wm->require_id_on_certificate,
						       /*value_when_unset*/YN_YES,wm, verbose);

	if (wm->aggressive == YN_YES && ike_version >= IKEv2) {
		return diag("cannot specify aggressive mode with IKEv2");
	}
	if (wm->aggressive == YN_YES && wm->ike == NULL) {
		return diag("cannot specify aggressive mode without ike= to set algorithm");
	}
	config->aggressive = extract_yn("", "aggressive", wm->aggressive,
					/*value_when_unset*/YN_NO,
					wm, verbose);

	config->decap_dscp = extract_yn("", "decap-dscp", wm->decap_dscp,
					/*value_when_unset*/YN_NO,
					wm, verbose);

	config->encap_dscp = extract_yn("", "encap-dscp", wm->encap_dscp,
					/*value_when_unset*/YN_YES,
					wm, verbose);

	config->nopmtudisc = extract_yn("", "nopmtudisc", wm->nopmtudisc,
					/*value_when_unset*/YN_NO,
					wm, verbose);

	bool mobike = extract_yn("", "mobike", wm->mobike,
				 /*value_when_unset*/YN_NO,
				 wm, verbose);
	config->mobike = mobike;
	if (mobike) {
		if (ike_version < IKEv2) {
			return diag("MOBIKE requires IKEv2");
		}
		if (encap_mode != ENCAP_MODE_TUNNEL) {
			return diag("MOBIKE requires tunnel mode");
		}
		if (kernel_ops->migrate_ipsec_sa_is_enabled == NULL) {
			return diag("MOBIKE is not supported by %s kernel interface",
				    kernel_ops->interface_name);
		}
		/* probe the interface */
		err_t err = kernel_ops->migrate_ipsec_sa_is_enabled(verbose.logger);
		if (err != NULL) {
			return diag("MOBIKE support is not enabled for %s kernel interface: %s",
				    kernel_ops->interface_name, err);
		}
	}

	uintmax_t tfc = extract_uintmax("", "", "tfc", wm->tfc,
					(struct range) {
						.value_when_unset = 0,
						.limit.max = UINT32_MAX,
					},
					wm, &d, verbose);
	if (d != NULL) {
		return d;
	}

	if (tfc > 0) {
		if (encap_mode == ENCAP_MODE_TRANSPORT) {
			return diag("connection with type=transport cannot specify tfc=");
		}
		if (encap_proto == ENCAP_PROTO_AH) {
			return diag("connection with encap_proto=ah cannot specify tfc=");
		}
		config->child.tfcpad = tfc;
	}


	/* this warns when never_negotiate() */
	bool iptfs = extract_yn("", "iptfs", wm->iptfs,
				/*value_when_unset*/YN_NO,
				wm, verbose);
	if (iptfs) {
		/* lots of incompatibility */
		if (ike_version < IKEv2) {
			return diag("IPTFS requires IKEv2");
		}
		if (encap_mode != ENCAP_MODE_TUNNEL) {
			name_buf sb;
			return diag("type=%s must be transport",
				    str_sparse_long(&type_option_names, wm->type, &sb));
		}
		if (tfc > 0) {
			return diag("IPTFS is not compatible with tfc=%ju", tfc);
		}
		if (compress) {
			return diag("IPTFS is not compatible with compress=yes");
		}
		if (encap_mode == ENCAP_MODE_TRANSPORT) {
			return diag("IPTFS is not compatible with type=transport");
		}
		if (encap_proto != ENCAP_PROTO_ESP) {
			name_buf eb;
			return diag("IPTFS is not compatible with %s=",
				    str_enum_short(&encap_proto_story, encap_proto, &eb));
		}

		err_t err = kernel_ops->iptfs_ipsec_sa_is_enabled(verbose.logger);
		if (err != NULL) {
			return diag("IPTFS is not supported by the kernel: %s", err);
		}

		deltatime_t uint32_max = deltatime_from_microseconds(UINT32_MAX);

		config->child.iptfs.enabled = true;
		config->child.iptfs.packet_size =
			extract_scaled_uintmax("", "", "iptfs-packet-size",
					       wm->iptfs_packet_size,
					       &binary_scales,
					       (struct range) {
						       .value_when_unset = 0/*i.e., disable*/,
					       },
					       wm, &d, verbose);
		if (d != NULL) {
			return d;
		}

		config->child.iptfs.max_queue_size =
			extract_scaled_uintmax("", "", "iptfs-max-queue-size",
					       wm->iptfs_max_queue_size,
					       &binary_scales,
					       (struct range) {
						       .value_when_unset = 0/*i.e., disable*/,
					       },
					       wm, &d, verbose);
		if (d != NULL) {
			return d;
		}

		if (deltatime_cmp(wm->iptfs_drop_time, >=, uint32_max)) {
			deltatime_buf tb;
			return diag("iptfs-drop-time cannot larger than %s",
				    str_deltatime(uint32_max, &tb));
		}
		config->child.iptfs.drop_time = wm->iptfs_drop_time;

			if (deltatime_cmp(wm->iptfs_init_delay, >=, uint32_max)) {
			deltatime_buf tb;
			return diag("iptfs-init-delay cannot larger than %s",
				    str_deltatime(uint32_max, &tb));
		}
		config->child.iptfs.init_delay = wm->iptfs_init_delay;

		config->child.iptfs.reorder_window =
			extract_scaled_uintmax("", "", "iptfs-reorder-window",
					       wm->iptfs_reorder_window,
					       &binary_scales,
					       (struct range) {
						       .value_when_unset = 0/*i.e., disable*/,
						       .limit.max = 65535,
					       },
					       wm, &d, verbose);
		if (d != NULL) {
			return d;
		}
	}

	/*
	 * Extract iptfs parameters regardless; so that the default is
	 * consistent and toggling iptfs= doesn't seem to change the
	 * field.  Could warn about this but meh.
	 */
	config->child.iptfs.fragmentation =
		extract_yn_p("", "iptfs-fragmentation", wm->iptfs_fragmentation,
			     /*value_when_unset*/YN_YES,
			     wm, verbose,
			     "", "iptfs", wm->iptfs);

	/*
	 * RFC 5685 - IKEv2 Redirect mechanism.
	 */
	config->redirect.to = clone_str(wm->redirect_to, "connection redirect_to");
	config->redirect.accept_to = clone_str(wm->accept_redirect_to, "connection accept_redirect_to");
	if (ike_version == IKEv1) {
		if (wm->send_redirect != YNA_UNSET) {
			vwarning("IKEv1 connection ignores send-redirect=");
		}
	} else {
		switch (wm->send_redirect) {
		case YNA_YES:
			if (wm->redirect_to == NULL) {
				vwarning("send-redirect=yes ignored, redirect-to= was not specified");
			}
			/* set it anyway!?!  the code checking it
			 * issues a second warning */
			config->redirect.send_always = true;
			break;

		case YNA_NO:
			if (wm->redirect_to != NULL) {
				vwarning("send-redirect=no, redirect-to= is ignored");
			}
			config->redirect.send_never = true;
			break;

		case YNA_UNSET:
		case YNA_AUTO:
			break;
		}
	}

	if (ike_version == IKEv1) {
		if (wm->accept_redirect != YN_UNSET) {
			vwarning("IKEv1 connection ignores accept-redirect=");
		}
	} else {
		config->redirect.accept =
			extract_yn("", "acceept-redirect", wm->accept_redirect,
				   /*value_when_unset*/YN_NO,
				   wm, verbose);
	}

	/* fragmentation */

	/*
	 * some options are set as part of our default, but
	 * some make no sense for shunts, so remove those again
	 */
	if (never_negotiate_sparse_option("", "fragmentation", wm->fragmentation,
					  &ynf_option_names, wm, verbose)) {
		vdbg("never-negotiate fragmentation");
	} else if (ike_version >= IKEv2 && wm->fragmentation == YNF_FORCE) {
		name_buf fb;
		vwarning("IKEv1 only fragmentation=%s ignored; using fragmentation=yes",
			 str_sparse_long(&ynf_option_names, wm->fragmentation, &fb));
		config->ike_frag.allow = true;
	} else {
		switch (wm->fragmentation) {
		case YNF_UNSET: /*default*/
		case YNF_YES:
			config->ike_frag.allow = true;
			break;
		case YNF_NO:
			break;
		case YNF_FORCE:
			config->ike_frag.allow = true;
			config->ike_frag.v1_force = true;
		}
	}

	/* RFC 8229 TCP encap*/

	enum tcp_options iketcp;
	if (never_negotiate_sparse_option("", "enable-tcp", wm->enable_tcp,
					  &tcp_option_names, wm, verbose)) {
		/* cleanup inherited default; XXX: ? */
		vdbg("never-negotiate enable-tcp");
		iketcp = IKE_TCP_NO;
	} else if (c->config->ike_version < IKEv2) {
		if (wm->enable_tcp != 0 &&
		    wm->enable_tcp != IKE_TCP_NO) {
			return diag("enable-tcp= requires IKEv2");
		}
		iketcp = IKE_TCP_NO;
	} else if (wm->enable_tcp == 0) {
		iketcp = IKE_TCP_NO; /* default */
	} else {
		iketcp = wm->enable_tcp;
	}
	config->end[LEFT_END].host.iketcp = config->end[RIGHT_END].host.iketcp = iketcp;

	switch (iketcp) {
	case IKE_TCP_NO:
		if (wm->tcp_remoteport != 0) {
			vwarning("tcp-remoteport=%ju ignored for non-TCP connections",
				 wm->tcp_remoteport);
		}
		/* keep tests happy, value ignored */
		config->remote_tcpport = ip_hport(NAT_IKE_UDP_PORT);
		break;
	case IKE_TCP_ONLY:
	case IKE_TCP_FALLBACK:
		if (wm->tcp_remoteport == 500) {
			return diag("tcp-remoteport cannot be 500");
		}
		if (wm->tcp_remoteport > 65535/*magic?*/) {
			return diag("tcp-remoteport=%ju is too big", wm->tcp_remoteport);
		}
		config->remote_tcpport =
			ip_hport(wm->tcp_remoteport == 0 ? NAT_IKE_UDP_PORT:
				 wm->tcp_remoteport);
		break;
	default:
		/* must  have been set */
		bad_sparse(verbose.logger, &tcp_option_names, iketcp);
	}


	/* authentication (proof of identity) */

	if (is_never_negotiate_wm(wm)) {
		vdbg("ignore sighash, never negotiate");
	} else if (c->config->ike_version == IKEv1) {
		vdbg("ignore sighash, IKEv1");
	} else {
		config->sighash_policy = sighash_policy;
	}

	/* duplicate any alias, adding spaces to the beginning and end */
	config->connalias = clone_str(wm->connalias, "connection alias");

	/*
	 * narrowing=?
	 *
	 * In addition to explicit narrowing=yes, seeing any sort of
	 * port wildcard (tcp/%any) implies narrowing.  This is
	 * largely IKEv1 and L2TP (it's the only test) but nothing
	 * implies that they can't.
	 */

	if (wm->narrowing == YN_NO && ike_version < IKEv2) {
		return diag("narrowing=yes requires IKEv2");
	}
	if (wm->narrowing == YN_NO) {
		FOR_EACH_THING(end, &wm->end[LEFT_END], &wm->end[RIGHT_END]) {
			if (end->addresspool != NULL) {
				return diag("narrowing=no conflicts with %saddresspool=%s",
					    end->leftright,
					    end->addresspool);
			}
		}
	}
	bool narrowing =
		extract_yn("", "narrowing", wm->narrowing,
			   /*value_when_unset*/(ike_version < IKEv2 ? YN_NO :
						wm->end[LEFT_END].addresspool != NULL ? YN_YES :
						wm->end[RIGHT_END].addresspool != NULL ? YN_YES :
						YN_NO),
			   wm, verbose);
#if 0
	/*
	 * Not yet: tcp/%any means narrow past the selector and down
	 * to a single port; while narrwing means narrow down to the
	 * selector.
	 */
	FOR_EACH_THING(end, &wm->end[LEFT_END], &wm->end[RIGHT_END]) {
		narrowing |= (end->protoport.ip.is_set &&
			      end->protoport.has_port_wildcard);
	}
#endif
	config->narrowing = narrowing;

	config->rekey = extract_yn("", "rekey", wm->rekey,
				   /*value_when_unset*/YN_YES,
				   wm, verbose);
	config->reauth = extract_yn("", "reauth", wm->reauth,
				    /*value_when_unset*/YN_NO,
				    wm, verbose);

	switch (wm->autostart) {
	case AUTOSTART_UP:
	case AUTOSTART_START:
	{
		name_buf nb;
		vdbg("autostart=%s implies +UP",
		     str_sparse_long(&autostart_names, wm->autostart, &nb));
		add_policy(c, policy.up);
		break;
	}
	case AUTOSTART_ROUTE:
	case AUTOSTART_ONDEMAND:
	{
		name_buf nb;
		vdbg("autostart=%s implies +ROUTE",
		     str_sparse_long(&autostart_names, wm->autostart, &nb));
		add_policy(c, policy.route);
		break;
	}
	case AUTOSTART_KEEP:
	{
		name_buf nb;
		vdbg("autostart=%s implies +KEEP",
		     str_sparse_long(&autostart_names, wm->autostart, &nb));
		add_policy(c, policy.keep);
		break;
	}
	case AUTOSTART_IGNORE:
	case AUTOSTART_ADD:
	case AUTOSTART_UNSET:
		break;
	}

	/*
	 * Extract configurable shunts, set hardwired shunts.
	 */

	d = extract_shunt(config, wm, SHUNT_KIND_NEVER_NEGOTIATE,
			  &never_negotiate_shunt_names, /*unset*/SHUNT_UNSET);
	if (d != NULL) {
		return d;
	}

	d = extract_shunt(config, wm, SHUNT_KIND_NEGOTIATION,
			  &negotiation_shunt_names, /*unset*/SHUNT_DROP);
	if (d != NULL) {
		return d;
	}

	if (is_fips_mode() && config->negotiation_shunt == SHUNT_PASS) {
		name_buf sb;
		vlog("FIPS: ignored negotiationshunt=%s - packets MUST be blocked in FIPS mode",
		     str_sparse_short(&negotiation_shunt_names, config->negotiation_shunt, &sb));
		config->negotiation_shunt = SHUNT_DROP;
	}

	d = extract_shunt(config, wm, SHUNT_KIND_FAILURE,
			  &failure_shunt_names, /*unset*/SHUNT_NONE);
	if (d != NULL) {
		return d;
	}

	/* make kernel code easier */
	config->shunt[SHUNT_KIND_BLOCK] = SHUNT_DROP;
	config->shunt[SHUNT_KIND_ONDEMAND] = SHUNT_TRAP;
	config->shunt[SHUNT_KIND_IPSEC] = SHUNT_IPSEC;

	if (is_fips_mode() && config->failure_shunt != SHUNT_NONE) {
		name_buf eb;
		vlog("FIPS: ignored failureshunt=%s - packets MUST be blocked in FIPS mode",
		     str_sparse_short(&failure_shunt_names, config->failure_shunt, &eb));
		config->failure_shunt = SHUNT_NONE;
	}

	for (enum shunt_kind sk = SHUNT_KIND_FLOOR; sk < SHUNT_KIND_ROOF; sk++) {
		vassert(sk < elemsof(config->shunt));
		vassert(shunt_ok(sk, config->shunt[sk]));
	}

	/*
	 * Should ESN be disabled?
	 *
	 * Order things so that a lack of kernel support is the last
	 * resort (fixing the kernel will break less tests).
	 */

	uintmax_t replay_window =
		extract_uintmax("", "", "replay-window", wm->replay_window,
				(struct range) {
					.value_when_unset = IPSEC_SA_DEFAULT_REPLAY_WINDOW,
					.limit.max = kernel_ops->max_replay_window,
				},
				wm, &d, verbose);
	if (d != NULL) {
		return d;
	}
	config->child.replay_window = replay_window;

	if (never_negotiate_sparse_option("", "esn", wm->esn,
					  &yne_option_names, wm, verbose)) {
		vdbg("never-negotiate esn");
	} else if (replay_window == 0) {
		/*
		 * RFC 4303 states:
		 *
		 * Note: If a receiver chooses to not enable
		 * anti-replay for an SA, then the receiver SHOULD NOT
		 * negotiate ESN in an SA management protocol.  Use of
		 * ESN creates a need for the receiver to manage the
		 * anti-replay window (in order to determine the
		 * correct value for the high-order bits of the ESN,
		 * which are employed in the ICV computation), which
		 * is generally contrary to the notion of disabling
		 * anti-replay for an SA.
		 */
		if (wm->esn != YNE_UNSET && wm->esn != YNE_NO) {
			vwarning("forcing esn=no as replay-window=0");
		} else {
			vdbg("ESN: disabled as replay-window=0"); /* XXX: log? */
		}
		config->esn.no = true;
	} else if (!kernel_ops->esn_supported) {
		/*
		 * Only warn when there's an explicit esn=yes.
		 */
		if (wm->esn == YNE_YES ||
		    wm->esn == YNE_EITHER) {
			name_buf nb;
			vwarning("%s kernel interface does not support ESN, ignoring esn=%s",
				 kernel_ops->interface_name,
				 str_sparse_long(&yne_option_names, wm->esn, &nb));
		}
		config->esn.no = true;
#ifdef USE_IKEv1
	} else if (ike_version == IKEv1) {
		/*
		 * Ignore ESN when IKEv1.
		 *
		 * XXX: except it isn't; it still gets decoded and
		 * stuffed into the config.  It just isn't acted on.
		 */
		vdbg("ESN: ignored as not implemented with IKEv1");
#if 0
		if (wm->esn != YNE_UNSET) {
			name_buf nb;
			vwarning("ignoring esn=%s as not implemented with IKEv1",
				 str_sparse_long(yne_option_names, wm->esn, &nb));
		}
#endif
		switch (wm->esn) {
		case YNE_UNSET:
		case YNE_EITHER:
			config->esn.no = true;
			config->esn.yes = true;
			break;
		case YNE_NO:
			config->esn.no = true;
			break;
		case YNE_YES:
			config->esn.yes = true;
			break;
		}
#endif
	} else {
		switch (wm->esn) {
		case YNE_UNSET:
		case YNE_EITHER:
			config->esn.no = true;
			config->esn.yes = true;
			break;
		case YNE_NO:
			config->esn.no = true;
			break;
		case YNE_YES:
			config->esn.yes = true;
			break;
		}
	}

	if (ike_version == IKEv1) {
		if (wm->ppk != NPPI_UNSET) {
			name_buf sb;
			vwarning("ignoring ppk=%s as IKEv1",
				 str_sparse_long(&nppi_option_names, wm->ppk, &sb));
		}
	} else {
		switch (wm->ppk) {
		case NPPI_UNSET:
		case NPPI_NEVER:
			break;
		case NPPI_PERMIT:
		case NPPI_PROPOSE:
			config->ppk.allow = true;
			break;
		case NPPI_INSIST:
			config->ppk.allow = true;
			config->ppk.insist = true;
			break;
		}
	}

	policy_buf pb;
	vdbg("added new %s connection %s with policy %s",
	     c->config->ike_info->version_name,
	     c->name, str_connection_policies(c, &pb));

	/* IKE cipher suites */

	if (never_negotiate_string_option("", "ike", wm->ike, wm, verbose)) {
		vdbg("never-negotiate ike");
	} else {
		const struct proposal_policy proposal_policy = {
			/* logic needs to match pick_initiator() */
			.version = c->config->ike_version,
			.alg_is_ok = ike_alg_is_ike,
			.pfs = pfs,
			.check_pfs_vs_ke = false,
			.stream = ALL_STREAMS,
			.logger = verbose.logger, /* on-stack */
			/* let defaults stumble on regardless */
			.ignore_parser_errors = (wm->ike == NULL),
			.addke = intermediate,
		};

		struct proposal_parser *parser = ike_proposal_parser(&proposal_policy);
		config->ike_proposals.p = proposals_from_str(parser, wm->ike);

		if (c->config->ike_proposals.p == NULL) {
			vexpect(parser->diag != NULL); /* something */
			diag_t d = parser->diag; parser->diag = NULL;
			free_proposal_parser(&parser);
			return d;
		}
		free_proposal_parser(&parser);

		VDBG_JAMBUF(buf) {
			jam_string(buf, "ike (phase1) algorithm values: ");
			jam_proposals(buf, c->config->ike_proposals.p);
		}

		if (c->config->ike_version == IKEv2) {
			vdbg("constructing local IKE proposals for %s",
			     c->name);
			config->v2_ike_proposals =
				ikev2_proposals_from_proposals(IKEv2_SEC_PROTO_IKE,
							       config->ike_proposals.p,
							       verbose);
			llog_v2_proposals(LOG_STREAM/*not-whack*/, verbose.logger,
					  config->v2_ike_proposals,
					  "IKE SA proposals (connection add)");
		}
	}

	/* ESP or AH cipher suites (but not both) */

	if (encap_proto != ENCAP_PROTO_UNSET) {

		const struct proposal_policy proposal_policy = {
			/*
			 * logic needs to match pick_initiator()
			 *
			 * XXX: Once pluto is changed to IKEv1 XOR
			 * IKEv2 it should be possible to move this
			 * magic into pluto proper and instead pass a
			 * simple boolean.
			 */
			.version = c->config->ike_version,
			.alg_is_ok = kernel_alg_is_ok,
			.pfs = pfs,
			.check_pfs_vs_ke = true,
			.stream = ALL_STREAMS,
			.logger = verbose.logger, /* on-stack */
			/* let defaults stumble on regardless */
			.ignore_parser_errors = (encap_alg == NULL),
			.addke = intermediate,
		};

		/*
		 * We checked above that exactly one of POLICY_ENCRYPT
		 * and POLICY_AUTHENTICATE is on.  The only difference
		 * in processing is which function is called (and
		 * those functions are almost identical).
		 */
		struct proposal_parser *(*fn)(const struct proposal_policy *policy) =
			(encap_proto == ENCAP_PROTO_ESP) ? esp_proposal_parser :
			(encap_proto == ENCAP_PROTO_AH) ? ah_proposal_parser :
			NULL;
		vassert(fn != NULL);
		struct proposal_parser *parser = fn(&proposal_policy);
		config->child.proposals.p = proposals_from_str(parser, encap_alg);
		if (c->config->child.proposals.p == NULL) {
			vexpect(parser->diag != NULL);
			diag_t d = parser->diag; parser->diag = NULL;
			free_proposal_parser(&parser);
			return d;
		}
		free_proposal_parser(&parser);

		VDBG_JAMBUF(buf) {
			jam_string(buf, "ESP/AH string values: ");
			jam_proposals(buf, c->config->child.proposals.p);
		};

		/*
		 * For IKEv2, also generate the Child proposal that
		 * will be used during IKE AUTH.
		 *
		 * Since a Child SA established during an IKE_AUTH
		 * exchange does not propose DH (keying material is
		 * taken from the IKE SA's SKEYSEED), DH is stripped
		 * from the proposals.
		 *
		 * Since only things that affect this proposal suite
		 * are the connection's .policy bits and the contents
		 * .child_proposals, and modifying those triggers the
		 * creation of a new connection (true?), the
		 * connection can be cached.
		 */
		if (c->config->ike_version == IKEv2) {
			config->child.v2_ike_auth_proposals =
				get_v2_IKE_AUTH_new_child_proposals(c);
			llog_v2_proposals(LOG_STREAM/*not-whack*/, verbose.logger,
					  config->child.v2_ike_auth_proposals,
					  "Child SA proposals (connection add)");
		}
	}

	config->encapsulation = extract_yna("", "encapsulation", wm->encapsulation,
					    /*value_when_unset*/YNA_AUTO,
					    /*value_when_never_negotiate*/YNA_NO,
					    wm, verbose);

	config->vti.shared = extract_yn("", "vti-shared", wm->vti_shared,
					/*value_when_unset*/YN_NO, wm, verbose);
	config->vti.routing = extract_yn("", "vti-routing", wm->vti_routing,
					 /*value_when_unset*/YN_NO, wm, verbose);
	if (wm->vti_interface != NULL && strlen(wm->vti_interface) >= IFNAMSIZ) {
		vwarning("length of vti-interface '%s' exceeds IFNAMSIZ (%u)",
			 wm->vti_interface, (unsigned) IFNAMSIZ);
	}
	config->vti.interface = extract_string("",  "vti-interface", wm->vti_interface,
					       wm, verbose);

	if (never_negotiate_sparse_option("", "nic-offload", wm->nic_offload,
					  &nic_offload_option_names, wm, verbose)) {
		vdbg("never-negotiate nic-offload");
		/* keep <<ipsec connectionstatus>> simple */
		config->nic_offload = NIC_OFFLOAD_NO;
	} else {
		switch (wm->nic_offload) {
		case NIC_OFFLOAD_UNSET:
		case NIC_OFFLOAD_NO:
			config->nic_offload = NIC_OFFLOAD_NO; /* default */
			break;
		case NIC_OFFLOAD_PACKET:
		case NIC_OFFLOAD_CRYPTO:
			if (kernel_ops->detect_nic_offload == NULL) {
				name_buf nb;
				return diag("no kernel support for nic-offload[=%s]",
					    str_sparse_long(&nic_offload_option_names, wm->nic_offload, &nb));
			}
			config->nic_offload = wm->nic_offload;
		}

		if (wm->nic_offload == NIC_OFFLOAD_PACKET) {
			if (encap_mode != ENCAP_MODE_TRANSPORT) {
				return diag("nic-offload=packet restricted to type=transport");
			}
			if (encap_proto != ENCAP_PROTO_ESP) {
				return diag("nic-offload=packet restricted to phase2=esp");
			}
			if (compress) {
				return diag("nic-offload=packet restricted to compression=no");
			}
			if (config->encapsulation == YNA_YES) {
				return diag("nic-offload=packet cannot specify encapsulation=yes");
			}

			/* byte/packet counters for packet offload on linux requires >= 6.7 */
			if (wm->ipsec_max_bytes != NULL ||
			    wm->ipsec_max_packets != NULL) {
				if (!kernel_ge(KINFO_LINUX, 6, 7, 0)) {
					return diag("Linux kernel 6.7+ required for byte/packet counters and hardware offload");
				}
				vdbg("kernel >= 6.7 is GTG for h/w offload");
			}

			/* limited replay windows supported for packet offload */
			switch (replay_window) {
			case 32:
			case 64:
			case 128:
			case 256:
				vdbg("packet offload replay-window compatible with all known hardware and Linux kernels");
				break;
			default:
				return diag("current packet offload hardware only supports replay-window of 32, 64, 128 or 256");
			}
			/* check if we need checks for tfcpad= , encap-dscp, nopmtudisc, ikepad, encapsulation, etc? */
		}

	}

	/*
	 * Cisco interop: remote peer type.
	 */
	d = extract_cisco_host_config(&config->host.cisco, wm, verbose);
	if (d != NULL) {
		return d;
	}

	uintmax_t rekeyfuzz_percent = extract_percent("", "rekeyfuzz", wm->rekeyfuzz,
						      SA_REPLACEMENT_FUZZ_DEFAULT,
						      wm, &d, verbose);

	if (is_never_negotiate_wm(wm)) {
		vdbg("skipping over misc settings as NEVER_NEGOTIATE");
	} else {

		if (d != NULL) {
			return d;
		}

		deltatime_t rekeymargin;
		if (wm->rekeymargin.is_set) {
			if (deltasecs(wm->rekeymargin) > (INT_MAX / (100 + (intmax_t)rekeyfuzz_percent))) {
				return diag("rekeymargin=%jd is so large it causes overflow",
					    deltasecs(wm->rekeymargin));
			}
			rekeymargin = wm->rekeymargin;
		} else {
			rekeymargin = deltatime(SA_REPLACEMENT_MARGIN_DEFAULT);
		};
		config->sa_rekey_margin = rekeymargin;

		d = extract_lifetime(&config->sa_ike_max_lifetime,
				     "ikelifetime", wm->ikelifetime,
				     IKE_SA_LIFETIME_DEFAULT,
				     IKE_SA_LIFETIME_MAXIMUM,
				     FIPS_IKE_SA_LIFETIME_MAXIMUM,
				     rekeymargin, rekeyfuzz_percent,
				     verbose, wm);
		if (d != NULL) {
			return d;
		}
		d = extract_lifetime(&config->sa_ipsec_max_lifetime,
				     "ipsec-lifetime", wm->ipsec_lifetime,
				     IPSEC_SA_LIFETIME_DEFAULT,
				     IPSEC_SA_LIFETIME_MAXIMUM,
				     FIPS_IPSEC_SA_LIFETIME_MAXIMUM,
				     rekeymargin, rekeyfuzz_percent,
				     verbose, wm);
		if (d != NULL) {
			return d;
		}

		config->sa_rekey_fuzz = rekeyfuzz_percent;

		config->retransmit_timeout =
			(wm->retransmit_timeout.is_set ? wm->retransmit_timeout :
			 deltatime_from_milliseconds(RETRANSMIT_TIMEOUT_DEFAULT * 1000));
		config->retransmit_interval =
			extract_deltatime("", "retransmit-interval", wm->retransmit_interval,
					  TIMESCALE_MILLISECONDS,
					  /*value_when_unset*/deltatime_from_milliseconds(RETRANSMIT_INTERVAL_DEFAULT_MS),
					  wm, &d, verbose);
		if (d != NULL) {
			return d;
		}

		/*
		 * A 1500 mtu packet requires 1500/16 ~= 90 crypto
		 * operations.  Always use NIST maximums for
		 * bytes/packets.
		 *
		 * https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
		 * "The total number of invocations of the
		 * authenticated encryption function shall not exceed
		 * 2^32 , including all IV lengths and all instances
		 * of the authenticated encryption function with the
		 * given key."
		 *
		 * Note "invocations" is not "bytes" or "packets", but
		 * the safest assumption is the most wasteful
		 * invocations which is 1 byte per packet.
		 *
		 * XXX: this code isn't yet doing this.
		 */

		config->sa_ipsec_max_bytes =
			extract_scaled_uintmax("IPsec max bytes",
					       "", "ipsec-max-bytes", wm->ipsec_max_bytes,
					       &binary_byte_scales,
					       (struct range) {
						       .value_when_unset = IPSEC_SA_MAX_OPERATIONS,
						       .clamp.max = IPSEC_SA_MAX_OPERATIONS,
					       },
					       wm, &d, verbose);
		if (d != NULL) {
			return d;
		}

		config->sa_ipsec_max_packets =
			extract_scaled_uintmax("IPsec max packets",
					       "", "ipsec-max-packets", wm->ipsec_max_packets,
					       &binary_scales,
					       (struct range) {
						       .value_when_unset = IPSEC_SA_MAX_OPERATIONS,
						       .clamp.max = IPSEC_SA_MAX_OPERATIONS,
					       },
					       wm, &d, verbose);
		if (d != NULL) {
			return d;
		}

		if (deltatime_cmp(config->sa_rekey_margin, >=, config->sa_ipsec_max_lifetime)) {
			deltatime_t new_rkm = deltatime_scale(config->sa_ipsec_max_lifetime, 1, 2);

			vlog("rekeymargin (%jds) >= salifetime (%jds); reducing rekeymargin to %jds seconds",
			     deltasecs(config->sa_rekey_margin),
			     deltasecs(config->sa_ipsec_max_lifetime),
			     deltasecs(new_rkm));

			config->sa_rekey_margin = new_rkm;
		}

		const enum timescale dpd_timescale = TIMESCALE_SECONDS;
		switch (ike_version) {
		case IKEv1:
			/* IKEv1's RFC 3706 DPD */
			if (wm->dpddelay != NULL &&
			    wm->dpdtimeout != NULL) {
				diag_t d;
				d = ttodeltatime(shunk1(wm->dpddelay),
						 &config->dpd.delay,
						 dpd_timescale);
				if (d != NULL) {
					return diag_diag(&d, "dpddelay=%s invalid, ",
							 wm->dpddelay);
				}
				d = ttodeltatime(shunk1(wm->dpdtimeout),
						 &config->dpd.timeout,
						 dpd_timescale);
				if (d != NULL) {
					return diag_diag(&d, "dpdtimeout=%s invalid, ",
							 wm->dpdtimeout);
				}
				deltatime_buf db, tb;
				vdbg("IKEv1 dpd.timeout=%s dpd.delay=%s",
				     str_deltatime(config->dpd.timeout, &db),
				     str_deltatime(config->dpd.delay, &tb));
			} else if (wm->dpddelay != NULL  ||
				   wm->dpdtimeout != NULL) {
				vwarning("IKEv1 dpd settings are ignored unless both dpdtimeout= and dpddelay= are set");
			}
			break;
		case IKEv2:
			if (wm->dpddelay != NULL) {
				diag_t d;
				d = ttodeltatime(shunk1(wm->dpddelay),
						 &config->dpd.delay,
						 dpd_timescale);
				if (d != NULL) {
					return diag_diag(&d, "dpddelay=%s invalid, ",
							 wm->dpddelay);
				}
			}
			if (wm->dpdtimeout != NULL) {
				/* actual values don't matter */
				vwarning("IKEv2 ignores dpdtimeout==; use dpddelay= and retransmit-timeout=");
			}
			break;
		}

		config->child.metric = wm->metric;

		config->child.mtu = extract_scaled_uintmax("Maximum Transmission Unit",
							      "", "mtu", wm->mtu,
							      &binary_byte_scales,
							      (struct range) {
								      .value_when_unset = 0,
							      },
							      wm, &d, verbose);
		if (d != NULL) {
			return d;
		}

		config->nat_keepalive = extract_yn("", "nat-keepalive", wm->nat_keepalive,
						   /*value_when_unset*/YN_YES,
						   wm, verbose);
		if (wm->nat_ikev1_method == 0) {
			config->ikev1_natt = NATT_BOTH;
		} else {
			config->ikev1_natt = wm->nat_ikev1_method;
		}
		config->send_initial_contact = extract_yn("", "initial-contact", wm->initial_contact,
							  /*value_when_unset*/YN_NO,
							  wm, verbose);
		config->send_vid_fake_strongswan = extract_yn("", "fake-strongswan", wm->fake_strongswan,
							      /*value_when_unset*/YN_NO,
							      wm, verbose);
		config->send_vendorid = extract_yn("", "send-vendorid", wm->send_vendorid,
						   /*value_when_unset*/YN_NO,
						   wm, verbose);

		config->send_ca = extract_enum_name("", "sendca", wm->sendca,
						    CA_SEND_ALL,
						    &send_ca_policy_names,
						    wm, &d, verbose);

		config->xauthby = extract_sparse("", "xauthby", wm->xauthby,
						 /*value_when_unset*/XAUTHBY_FILE,
						 /*value_when_never_negotiate*/XAUTHBY_FILE,
						 &xauthby_names, wm, verbose);
		config->xauthfail = extract_sparse("", "xauthfail", wm->xauthfail,
						   /*value_when_unset*/XAUTHFAIL_HARD,
						   /*value_when_never_negotiate*/XAUTHFAIL_HARD,
						   &xauthfail_names, wm, verbose);

		/* RFC 8784 and draft-ietf-ipsecme-ikev2-qr-alt-04 */
		config->ppk_ids = clone_str(wm->ppk_ids, "connection ppk_ids");
		if (config->ppk_ids != NULL) {
			config->ppk_ids_shunks = ttoshunks(shunk1(config->ppk_ids),
							   ", ",
							   EAT_EMPTY_SHUNKS); /* process into shunks once */
		}
	}

	/*
	 * modecfg/cp
	 */

	config->modecfg.pull = extract_yn("", "modecfgpull", wm->modecfgpull,
					  /*value_when_unset*/YN_NO,
					  wm, verbose);

	if (can_extract_string("", "modecfgdns", wm->modecfgdns, wm, verbose)) {
		diag_t d = ttoaddresses_num(shunk1(wm->modecfgdns), ", ",
					    /* IKEv1 doesn't do IPv6 */
					    (ike_version == IKEv1 ? &ipv4_info : NULL),
					    &config->modecfg.dns);
		if (d != NULL) {
			return diag_diag(&d, "modecfgdns=%s invalid: ", wm->modecfgdns);
		}
	}

	if (can_extract_string("", "modecfgdomains", wm->modecfgdomains, wm, verbose)) {
		config->modecfg.domains = clone_shunk_tokens(shunk1(wm->modecfgdomains),
							     ", ", HERE);
		if (ike_version == IKEv1 &&
		    config->modecfg.domains != NULL &&
		    config->modecfg.domains[1].ptr != NULL) {
			vlog("IKEv1 only uses the first domain in modecfgdomain=%s",
			     wm->modecfgdomains);
			config->modecfg.domains[1] = null_shunk;
		}
	}

	config->modecfg.banner = extract_string("", "modecfgbanner", wm->modecfgbanner,
						wm, verbose);

	/*
	 * Marks.
	 *
	 * parse mark and mask values form the mark/mask string
	 * acceptable string formats are
	 * ( -1 | <nat> | <hex> ) [ / ( <nat> | <hex> ) ]
	 * examples:
	 *   10
	 *   10/0xffffffff
	 *   0xA/0xFFFFFFFF
	 *
	 * defaults:
	 *  if mark is provided and mask is not mask will default to 0xFFFFFFFF
	 *  if nothing is provided mark and mask are set to 0;
	 *
	 * mark-in= and mark-out= overwrite mark=
	 */

	if (can_extract_string("", "mark", wm->mark, wm, verbose)) {
		d = mark_parse("", "mark", wm->mark, &c->sa_marks.in);
		if (d != NULL) {
			return d;
		}
		d = mark_parse("", "mark", wm->mark, &c->sa_marks.out);
		if (d != NULL) {
			return d;
		}
	}

	if (can_extract_string("", "mark-in", wm->mark_in, wm, verbose)) {
		if (wm->mark != NULL) {
			vwarning("mark-in=%s overrides mark=%s",
				 wm->mark_in, wm->mark);
		}
		d = mark_parse("", "mark-in", wm->mark_in, &c->sa_marks.in);
		if (d != NULL) {
			return d;
		}
	}

	if (can_extract_string("", "mark-out", wm->mark_out, wm, verbose)) {
		if (wm->mark != NULL) {
			vwarning("mark-out=%s overrides mark=%s",
				 wm->mark_out, wm->mark);
		}
		d = mark_parse("", "mark-out", wm->mark_out, &c->sa_marks.out);
		if (d != NULL) {
			return d;
		}
	}

	/*
	 * ipsec-interface
	 */

	struct ipsec_interface_config ipsec_interface = {0};
	if (can_extract_string("", "ipsec-interface", wm->ipsec_interface, wm, verbose)) {
		diag_t d;
		d = parse_ipsec_interface(wm->ipsec_interface, &ipsec_interface, verbose.logger);
		if (d != NULL) {
			return d;
		}
		config->ipsec_interface = ipsec_interface;
	}

#ifdef USE_NFLOG
	c->nflog_group = extract_uintmax("", "", "nflog-group", wm->nflog_group,
					 (struct range) {
						 .value_when_unset = 0,
						 .limit.min = 1,
						 .limit.max = 65535,
					 },
					 wm, &d, verbose);
	if (d != NULL) {
		return d;
	}
#endif

	config->child.priority = extract_uintmax("", "", "priority", wm->priority,
						 (struct range) {
							 .value_when_unset = 0,
							 .limit.max = UINT32_MAX,
						 },
						 wm, &d, verbose);
	if (d != NULL) {
		return d;
	}

	config->child.send.esp_tfc_padding_not_supported =
		extract_yn("", "send-esp-tfc-padding-not-supported",
			   wm->send_esp_tfc_padding_not_supported,
			   YN_NO, wm, verbose);

	/*
	 * Since security labels use the same REQID for everything,
	 * pre-assign it.
	 *
	 * HACK; extract_uintmax() returns 0, when there's no reqid.
	 */

	uintmax_t reqid = extract_uintmax("", "", "reqid", wm->reqid,
					  (struct range) {
						  .value_when_unset = 0,
						  .limit.min = 1,
						  .limit.max = IPSEC_MANUAL_REQID_MAX,
					  },
					  wm, &d, verbose);
	if (d != NULL) {
		return d;
	}

	config->sa_reqid = (reqid != 0 ? reqid :
			    wm->sec_label != NULL ? gen_reqid() :
			    ipsec_interface.enabled ? ipsec_interface_reqid(ipsec_interface.id, verbose.logger) :
			    /*generated later*/0);

	vdbg("c->sa_reqid="PRI_REQID" because wm->reqid=%s and sec-label=%s",
	     pri_reqid(config->sa_reqid),
	     (wm->reqid != NULL ? wm->reqid : "n/a"),
	     (wm->sec_label != NULL ? wm->sec_label : "n/a"));

	/*
	 * Set both end's sec_label to the same value.
	 */

	if (wm->sec_label != NULL) {
		vdbg("received sec_label '%s' from whack", wm->sec_label);
		if (ike_version == IKEv1) {
			return diag("IKEv1 does not support Labeled IPsec");
		}
		/* include NUL! */
		shunk_t sec_label = shunk2(wm->sec_label, strlen(wm->sec_label)+1);
		err_t ugh = vet_seclabel(sec_label);
		if (ugh != NULL) {
			return diag("%s: policy-label=%s", ugh, wm->sec_label);
		}
		config->sec_label = clone_hunk(sec_label, "struct config sec_label");
	}

	/*
	 * Look for contradictions.
	 */

	if (wm->end[LEFT_END].addresspool != NULL &&
	    wm->end[RIGHT_END].addresspool != NULL) {
		return diag("both leftaddresspool= and rightaddresspool= defined");
	}

	if (wm->end[LEFT_END].modecfgserver == YN_YES &&
	    wm->end[RIGHT_END].modecfgserver == YN_YES) {
		diag_t d = diag("both leftmodecfgserver=yes and rightmodecfgserver=yes defined");
		if (!is_opportunistic_wm(host_addrs)) {
			return d;
		}
		vlog("opportunistic: %s", str_diag(d));
		pfree_diag(&d);
	}

	if (wm->end[LEFT_END].modecfgclient == YN_YES &&
	    wm->end[RIGHT_END].modecfgclient == YN_YES) {
		diag_t d = diag("both leftmodecfgclient=yes and rightmodecfgclient=yes defined");
		if (!is_opportunistic_wm(host_addrs)) {
			return d;
		}
		vlog("opportunistic: %s", str_diag(d));
		pfree_diag(&d);
	}

	if (wm->end[LEFT_END].cat == YN_YES && wm->end[RIGHT_END].cat == YN_YES) {
		diag_t d = diag("both leftcat=yes and rightcat=yes defined");
		if (!is_opportunistic_wm(host_addrs)) {
			return d;
		}
		vlog("opportunistic: %s", str_diag(d));
		pfree_diag(&d);
	}

	if (wm->end[LEFT_END].virt != NULL && wm->end[RIGHT_END].virt != NULL) {
		return diag("both leftvirt= and rightvirt= defined");
	}

	if (is_group_wm(host_addrs) && (wm->end[LEFT_END].virt != NULL ||
					wm->end[RIGHT_END].virt != NULL)) {
		return diag("connection groups do not support virtual subnets");
	}

	FOR_EACH_THING(this, LEFT_END, RIGHT_END) {
		int that = (this + 1) % END_ROOF;
		if (same_ca[that]) {
			config->end[that].host.ca = clone_hunk(config->end[this].host.ca,
							       "same ca");
			break;
		}
	}

	/*
	 * Connections can't be both client and server right?
	 *
	 * Unfortunately, no!
	 *
	 * OE configurations have configurations such as
	 * leftmodecfgclient=yes rightaddresspool= and
	 * leftmodeconfigclient=yes leftmodeconfigserver=yes which
	 * create a connection that is both a client and a server.
	 */

	if (config->end[LEFT_END].host.modecfg.server &&
	    config->end[RIGHT_END].host.modecfg.server) {
		diag_t d = diag("both left and right are configured as a server");
		if (!is_opportunistic_wm(host_addrs)) {
			return d;
		}
		vlog("opportunistic: %s", str_diag(d));
		pfree_diag(&d);
	}

	if (config->end[LEFT_END].host.modecfg.client &&
	    config->end[RIGHT_END].host.modecfg.client) {
		diag_t d = diag("both left and right are configured as a client");
		if (!is_opportunistic_wm(host_addrs)) {
			return d;
		}
		vlog("opportunistic: %s", str_diag(d));
		pfree_diag(&d);
	}

	/*
	 * Cross-check the auth= vs authby= results.
	 */

	if (never_negotiate(c)) {
		if (!vexpect(c->local->host.config->auth == AUTH_NEVER &&
			     c->remote->host.config->auth == AUTH_NEVER)) {
			return diag("internal error");
		}
	} else {
		if (c->local->host.config->auth == AUTH_UNSET ||
		    c->remote->host.config->auth == AUTH_UNSET) {
			/*
			 * Since an unset auth is set from authby,
			 * authby= must have somehow been blanked out
			 * or left with something useless (such as
			 * never).
			 */
			return diag("no authentication (auth=, authby=) was set");
		}

		if ((c->local->host.config->auth == AUTH_PSK && c->remote->host.config->auth == AUTH_NULL) ||
		    (c->local->host.config->auth == AUTH_NULL && c->remote->host.config->auth == AUTH_PSK)) {
			name_buf lab, rab;
			return diag("cannot mix PSK and NULL authentication (%sauth=%s and %sauth=%s)",
				    c->local->config->leftright,
				    str_enum_long(&keyword_auth_names, c->local->host.config->auth, &lab),
				    c->remote->config->leftright,
				    str_enum_long(&keyword_auth_names, c->remote->host.config->auth, &rab));
		}
	}

	/*
	 * For templates; start the instance counter.  Each time the
	 * connection is instantiated this is updated; ditto for
	 * instantiated instantiations such as is_labeled_child().
	 */
	c->instance_serial = 0;
	c->next_instance_serial = (is_template(c) ? 1 : 0);

	/* set internal fields */
	c->iface = NULL; /* initializing */

	c->redirect.attempt = 0;

	/* non configurable */
	config->ike_window = IKE_V2_OVERLAPPING_WINDOW_SIZE;

	/*
	 * Extract the child configuration and save it.
	 */

	FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
		d = extract_child_end_config(wm, whack_ends[end],
					     host_addrs[end],
					     protoport[end],
					     ike_version,
					     c, &config->end[end].child,
					     verbose);
		if (d != NULL) {
			return d;
		}
	}

	/*
	 * Note: this checks the whack message (WM), and not the
	 * connection (C) being construct - it could be done before
	 * extract_end(), but do it here.
	 *
	 * XXX: why not allow this?
	 */
	if ((config->end[LEFT_END].host.auth == AUTH_UNSET) !=
	    (config->end[RIGHT_END].host.auth == AUTH_UNSET)) {
		    return diag("leftauth= and rightauth= must both be set or both be unset");
	}


	/*
	 * Limit IKEv1 with selectors
	 */
	if (ike_version == IKEv1) {
		FOR_EACH_THING(lr, LEFT_END, RIGHT_END) {
			const char *leftright = config->end[lr].leftright;
			if (config->end[lr].child.selectors.len <= 1) {
				continue;
			}
			if (config->host.cisco.split &&
			    config->end[lr].host.modecfg.server) {
				vlog("allowing IKEv1 %ssubnet= with multiple selectors as cisco-split=yes and %smodecfgserver=yes",
				     leftright, leftright);
				continue;
			}
			return diag("IKEv1 does not support %ssubnet= with multiple selectors without cisco-split=yes and %smodecfgserver=yes",
				    leftright, leftright);
		}
	}

	/*
	 * Now cross check the configuration looking for IP version
	 * conflicts.
	 *
	 * First build a table of the IP address families that each
	 * end's child is using and then cross check it with the other
	 * end.  Either both ends use a AFI or both don't.
	 */

	struct end_family {
		bool used;
		const char *field;
		const char *value;
	} end_family[END_ROOF][IP_VERSION_ROOF] = {0};
	FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
		const ip_selectors *const selectors = &c->end[end].config->child.selectors;
		const ip_ranges *const pools = &c->end[end].config->child.addresspools;
		if (selectors->len > 0) {
			FOR_EACH_ITEM(selector, selectors) {
				const struct ip_info *afi = selector_type(selector);
				struct end_family *family = &end_family[end][afi->ip.version];
				if (!family->used) {
					family->used = true;
					family->field = "subnet";
					family->value = whack_ends[end]->subnet;
				}
			}
		} else if (pools->len > 0) {
			FOR_EACH_ITEM(range, pools) {
				const struct ip_info *afi = range_type(range);
				/* only one for now */
				struct end_family *family = &end_family[end][afi->ip.version];
				vassert(family->used == false);
				family->used = true;
				family->field = "addresspool";
				family->value = whack_ends[end]->addresspool;
			}
		} else {
			struct end_family *family = &end_family[end][host_afi->ip.version];
			family->used = true;
			family->field = "";
			family->value = whack_ends[end]->host;
		}
	}

	/* now check there's a match */
	FOR_EACH_ELEMENT(afi, ip_families) {
		enum ip_version i = afi->ip.version;

		/* both ends do; or both ends don't */
		if (end_family[LEFT_END][i].used == end_family[RIGHT_END][i].used) {
			continue;
		}
		/*
		 * Flip the AFI for RIGHT.  Presumably it being
		 * non-zero is the reason for the conflict?
		 */
		enum ip_version j = (i == IPv4 ? IPv6 : IPv4);
		if (end_family[LEFT_END][i].used) {
			/* oops, no winner */
			vexpect(end_family[RIGHT_END][j].used);
		} else {
			swap(i, j);
			vexpect(end_family[LEFT_END][i].used);
			vexpect(end_family[RIGHT_END][j].used);
		}
		/*
		 * Both ends used child AFIs.
		 *
		 * Since no permutation was valid one end must
		 * be pure IPv4 and the other end pure IPv6
		 * say.
		 *
		 * Use the first list entry to get the AFI.
		 */
		return diag("address family of left%s=%s conflicts with right%s=%s",
			    end_family[LEFT_END][i].field,
			    end_family[LEFT_END][i].value,
			    end_family[RIGHT_END][j].field,
			    end_family[RIGHT_END][j].value);
	}

	/*
	 * Is spd.reqid necessary for all c?  CK_INSTANCE or
	 * CK_PERMANENT need one.  Does CK_TEMPLATE need one?
	 */
	c->child.reqid = child_reqid(c->config, verbose.logger);

	/*
	 * All done, enter it into the databases.  Since orient() may
	 * switch ends, triggering an spd rehash, insert things into
	 * the database first.
	 */
	connection_db_add(c);
	vdbg_connection(c, verbose, HERE, "extracted");

	/*
	 * Now try to resolve the host/nexthop in .config, copying the
	 * result into the connection.
	 */

	if (!resolve_connection_hosts_from_configs(c, verbose)) {
		vdbg("could not resolve connection");
	}

	/*
	 * Fill in the child's selector proposals from the config.  It
	 * might use subnet or host or addresspool.
	 */

	build_connection_proposals_from_hosts_and_configs(c, verbose);
	if (VDBGP()) {
		VDBG_log("proposals built");
		connection_db_check(verbose.logger, HERE);
	}

	/*
	 * Force orientation (currently kind of unoriented?).
	 *
	 * If the connection orients,the SPDs and host-pair hash
	 * tables are updated.
	 *
	 * This function holds the just allocated reference.
	 */
	vassert(!oriented(c));
	orient(c, verbose.logger);

	if (VDBGP()) {
		VDBG_log("oriented; maybe");
		connection_db_check(verbose.logger, HERE);
	}

	return NULL;
}
