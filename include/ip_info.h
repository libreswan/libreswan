/* XXX: header from name_constant.h */

#ifndef IP_INFO_H
#define IP_INFO_H

/* socket address family info */

#include "ip_subnet.h"

struct ip_info {
	int af; /* AF_INET or AF_INET6 */
	const char *af_name;
	int version; /* 4 or 6 */
	size_t ia_sz;
	size_t sa_sz;
	int mask_cnt; /* 32 or 128 */
	uint8_t id_addr, id_subnet, id_range;
	const ip_subnet *none;  /* 0.0.0.0/32 or IPv6 equivalent */
	const ip_subnet *all;   /* 0.0.0.0/0 or IPv6 equivalent */
};

extern const struct ip_info ipv4_info;
extern const struct ip_info ipv6_info;

extern const struct ip_info *aftoinfo(int af);

extern void init_ip_info(void);

#endif
