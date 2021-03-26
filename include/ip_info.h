/* XXX: header from name_constant.h */

#ifndef IP_INFO_H
#define IP_INFO_H

/* socket address family info */

#include "ip_address.h"
#include "ip_subnet.h"
#include "ip_selector.h"

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
		const ip_address any;		/* 0.0.0.0 or :: */
		const ip_address loopback;	/* 127.0.0.1 or ::1 */
	} address;

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
	 * Sockaddr.
	 */
	int af; /* AF_INET or AF_INET6 */
	const char *af_name;
	size_t sockaddr_size; /* sizeof(sockaddr_in) | sizeof(sockaddr_in6)? */

	/*
	 * ID stuff.
	 */
	enum ike_id_type id_ip_addr;
	enum ike_id_type id_ip_addr_subnet;
	enum ike_id_type id_ip_addr_range;

	size_t (*jam_address)(struct jambuf *buf, const struct ip_info *info, const struct ip_bytes *bytes);
};

extern const struct ip_info ipv4_info;
extern const struct ip_info ipv6_info;

extern const struct ip_info *aftoinfo(int af);

const struct ip_info *ip_version_info(unsigned version);

#endif
