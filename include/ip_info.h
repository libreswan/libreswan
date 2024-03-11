/* XXX: header from name_constant.h */

#ifndef IP_INFO_H
#define IP_INFO_H

/* socket address family info */

#include "ip_address.h"
#include "ip_subnet.h"
#include "ip_selector.h"
#include "ip_sockaddr.h"
#include "ip_index.h"

struct ip_info {
	/*
	 * address family
	 */
	enum ip_version ip_version; /* 4 or 6 */
	const char *ip_name; /* "IPv4" or "IPv6" */
	size_t ip_size; /* 4 or 16 */
	unsigned mask_cnt; /* 32 or 128 */

	/*
	 * ip_address
	 */
	struct {
		const ip_address unspec;	/* 0.0.0.0 or :: */
		const ip_address loopback;	/* 127.0.0.1 or ::1 */
		size_t (*jam)(struct jambuf *buf, const struct ip_info *info, const struct ip_bytes *bytes);
		/* N.N.N.N or [MM:MM:MM...] */
		size_t (*jam_wrapped)(struct jambuf *buf, const struct ip_info *info, const struct ip_bytes *bytes);
	} address;

	/*
	 * ip_endpoint
	 */
	struct {
		size_t (*jam)(struct jambuf *buf, const struct ip_info *info, const struct ip_bytes *bytes, unsigned hport);
	} endpoint;

	/*
	 * ip_subnet.
	 */
	struct {
		const ip_subnet zero;		/* ::/128 or 0.0.0.0/32 */
		const ip_subnet all;		/* ::/0 or 0.0.0.0/0 */
	} subnet;

	/*
	 * ip_range.
	 */
	struct {
		const ip_range zero;
		const ip_range all;
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
		int domain;
		const char *domain_name;
	} socket;

	/*
	 * Sockaddr.
	 *
	 * AF_INET or AF_INET6
	 */
	int af;
	const char *af_name;
	/* misc */
	size_t sockaddr_size; /* sizeof(sockaddr_in) | sizeof(sockaddr_in6)? */
	ip_address (*address_from_sockaddr)(const ip_sockaddr sa);
	ip_port (*port_from_sockaddr)(const ip_sockaddr sa);

	/*
	 * IKEv2 Traffic Selector Stuff.
	 */
	enum ikev2_ts_type ikev2_ts_addr_range_type;

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

extern const struct ip_info *aftoinfo(int af);

const struct ip_info *ip_version_info(unsigned version);

#endif
