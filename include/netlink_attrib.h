#ifndef _NETLINK_H
# define _NETLINK_H

/* work around weird combo's of glibc and kernel header conflicts */
#ifndef GLIBC_KERN_FLIP_HEADERS
# include "linux/xfrm.h" /* local (if configured) or system copy */
# include "libreswan.h"
#else
# include "libreswan.h"
# include "linux/xfrm.h" /* local (if configured) or system copy */
#endif

#include <linux/netlink.h>

#define NETLINK_REQ_DATA_SIZE 8192

struct nlm_resp {
        struct nlmsghdr n;
        union {
		struct nlmsgerr e;
		struct xfrm_userpolicy_info pol;        /* netlink_policy_expire */
		struct xfrm_usersa_info sa;     /* netlink_get_spi */
		struct xfrm_usersa_info info;   /* netlink_get_sa */
		char data[NETLINK_REQ_DATA_SIZE];
        } u;
};

void nl_addattr_l(struct nlmsghdr *n, const unsigned short maxlen,
                const unsigned short type, const void *data, int alen);
struct rtattr *nl_addattr_nest(struct nlmsghdr *n, int maxlen,
			       int type);
void nl_addattr_nest_end(struct nlmsghdr *n, struct rtattr *nest);
void nl_addattrstrz(struct nlmsghdr *n, int maxlen, int type,
		const char *str);
void nl_addattr32(struct nlmsghdr *n, int maxlen, int type, const uint32_t data);

#endif
