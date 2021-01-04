/* XXX: header from name_constant.h */

#ifndef IP_INFO_H
#define IP_INFO_H

/* socket address family info */

#include "ip_address.h"
#include "ip_subnet.h"

struct ip_info {
	/*
	 * ip_address
	 */
	unsigned ip_version; /* 4 or 6 */
	const char *ip_name; /* "IPv4" or "IPv6" */
	size_t ip_size; /* 4 or 16 */
	/* 0.0.0.0 or :: */
	const ip_address any_address;
	/* 127.0.0.1 or ::1 */
	const ip_address loopback_address;

	/*
	 * ip_endpoint
	 */
	/* 0.0.0.0:0 or [::]:0 */
	const ip_endpoint any_endpoint;

	/*
	 * ip_subnet.
	 */
	unsigned mask_cnt; /* 32 or 128 */
	/* unspecified address - ::/128 or 0.0.0.0/32 - matches no addresses */
	const ip_subnet no_addresses;
	/* default route - ::/0 or 0.0.0.0/0 - matches all addresses */
	const ip_subnet all_addresses;

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
