/* XXX: header from name_constant.h */

#ifndef IP_INFO_H
#define IP_INFO_H

/* socket address family info */

#include "ip_address.h"
#include "ip_subnet.h"
#include "ip_selector.h"
#include "ip_sockaddr.h"
#include "ip_version.h"
#include "ip_index.h"
#include "constants.h"			/* for enum ikev2_ts_addr_range_type; et.al. */

struct ip_info {
	/*
	 * address family
	 */
	struct {
		/* ip.version matches field in ip structs */
		enum ip_version version; /* 4 or 6 */
	} ip;
	enum ip_index ip_index; /* 1 or 2 */
	const char *ip_name; /* "IPv4" or "IPv6" */
	const char *inet_name;		/* "inet" or "inet6" */

	size_t ip_size; /* 4 or 16 */
	unsigned mask_cnt; /* 32 or 128 */

	/*
	 * Formatting primitives.
	 */
	struct {
		/* N.N.N.N or N:N:N:N */
		size_t (*address)(struct jambuf *buf, const struct ip_info *info, const struct ip_bytes *bytes);
		/* N.N.N.N or [MM:MM:MM...] */
		size_t (*address_wrapped)(struct jambuf *buf, const struct ip_info *info, const struct ip_bytes *bytes);
	} jam;

	/*
	 * ip_address
	 */
	struct {
		const ip_address unspec;	/* 0.0.0.0 or :: */
		const ip_address loopback;	/* 127.0.0.1 or ::1 */
		const ip_address unset;
	} address;

	/*
	 * ip_endpoint
	 */
	struct {
		const ip_address unset;
	} endpoint;

	/*
	 * ip_subnet.
	 */
	struct {
		const ip_subnet zero;		/* ::/128 or 0.0.0.0/32 */
		const ip_subnet all;		/* ::/0 or 0.0.0.0/0 */
		const ip_address unset;
	} subnet;

	/*
	 * ip_range.
	 */
	struct {
		const ip_range zero;
		const ip_range all;
		const ip_address unset;
	} range;

	/*
	 * ip_selector
	 *
	 * none: match no endpoints/addresses
	 * all: matches all endpoints/addresses
	 *
	 * (if nothing else, used for edge case testing)
	 */
	struct {
		/* matches no addresses */
		const ip_selector zero;		/* ::/128 or 0.0.0.0/32 */
		/* matches all addresses */
		const ip_selector all;		/* ::/0 or 0.0.0.0/0 */
		/* not set yet has family */
		const ip_selector unset;
	} selector;

	/*
	 * ike
	 */
	/* IPv4 and IPv6 have different fragment sizes */
	unsigned ikev1_max_fragment_size;
	unsigned ikev2_max_fragment_size;

	/*
	 * socket(domain, type, protocol)
	 *
	 * AKA protocol family (hence PF in PF_INET and PF_INET6).
	 * The values are the same as AF_INET and AF_INET6, and Linux
	 * documents those instead.
	 */
	struct {
		int domain;			/* PF_INET or PF_INET6 */
		const char *domain_name;	/* "PF_INET" or "PF_INET6" */
	} socket;

	/*
	 * Sockaddr.
	 */
	int af;				/* AF_INET or AF_INET6 */
	const char *af_name;		/* "AF_INET" or "AF_INET6" */

	/* misc */
	size_t sockaddr_size;		/* sizeof(sockaddr_in) | sizeof(sockaddr_in6)? */
	ip_address (*address_from_sockaddr)(const ip_sockaddr sa);
	ip_port (*port_from_sockaddr)(const ip_sockaddr sa);

	/*
	 * IKEv2 Traffic Selector Stuff.
	 */
	enum ikev2_ts_type ikev2_ts_addr_range_type;
	enum ikev2_cp_attribute_type ikev2_internal_address;
	enum ikev2_cp_attribute_type ikev2_internal_dns;

	/*
	 * ID stuff.
	 */
	enum ike_id_type id_ip_addr;
	enum ike_id_type id_ip_addr_subnet;
	enum ike_id_type id_ip_addr_range;

};

extern const struct ip_info ip_families[IP_INDEX_ROOF];

#define ipv4_info ip_families[IPv4_INDEX]
#define ipv6_info ip_families[IPv6_INDEX]
extern const struct ip_info unspec_ip_info;

extern const struct ip_info *aftoinfo(int af);

const struct ip_info *ttoinfo(const char *name);

const struct ip_info *ip_version_info(enum ip_version version);

/*
 * Internal.
 */

diag_t ttoips_num(shunk_t input, const struct ip_info *afi,
		  void **ptr, unsigned *len,
		  err_t (*parse_token)(shunk_t, const struct ip_info *,
				       void **ptr, unsigned len));

#endif
