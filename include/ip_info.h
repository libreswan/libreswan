/* XXX: header from name_constant.h */

#ifndef IP_INFO_H
#define IP_INFO_H

/* socket address family info */

#include "ip_subnet.h"

struct ip_info {
	int af; /* AF_INET or AF_INET6 */
	const char *af_name;
	int ip_version; /* 4 or 6 */
	size_t ip_size; /* 4 or 16 */
	size_t sockaddr_size; /* sizeof(sockaddr_in) | sizeof(sockaddr_in6)? */
	int mask_cnt; /* 32 or 128 */
	uint8_t id_addr, id_subnet, id_range;
	/*
	 * some pre-defined values
	 */
	const ip_address *any_address;
	const ip_address *loopback_address;
	/* unspecified address - ::/128 or 0.0.0.0/32 - matches no addresses */
	const ip_subnet *no_addresses;
	/* default route - ::/0 or 0.0.0.0/0 - matches all addresses */
	const ip_subnet *all_addresses;
};

extern const struct ip_info ipv4_info;
extern const struct ip_info ipv6_info;

extern const struct ip_info *aftoinfo(int af);

extern void init_ip_info(void);

#endif
