/* XXX: header from name_constant.h */

#ifndef AF_INFO_H
#define AF_INFO_H

/* socket address family info */

#include "ip_address.h"
#include "ip_subnet.h"

struct af_info {
	int af;
	const char *name;
	size_t ia_sz;
	size_t sa_sz;
	int mask_cnt;
	uint8_t id_addr, id_subnet, id_range;
	const ip_address *any;
	const ip_subnet *none;  /* 0.0.0.0/32 or IPv6 equivalent */
	const ip_subnet *all;   /* 0.0.0.0/0 or IPv6 equivalent */
};

extern const struct af_info
	af_inet4_info,
	af_inet6_info;

extern const struct af_info *aftoinfo(int af);

extern void init_af_info(void);

#endif
