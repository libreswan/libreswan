#ifndef NETLINK_ATTRIB_H
#define NETLINK_ATTRIB_H

#include <stdint.h>	/* for uint32_t */

/*
 * GRRR:
 *
 * GLIBC/Linux and MUSL/Linux define sockaddr_in et.al. in
 * <netinet/in.h>, and the generic network code uses this.
 * Unfortunately (cough) the Linux kernel headers also provide
 * definitions of those structures in <linux/in.h> et.al. which,
 * depending on header include order can result in conflicting
 * definitions.  For instance, if sockaddr_in is not defined,
 * <linux/xfrm.h> will include the definition in <linux/in.h> but that
 * will then clash with a later include of <netinet/in.h>.
 *
 * GLIBC/Linux has hacks on hacks to work-around this, not MUSL.
 * Fortunately, including <netinet/in.h> first will force the Linux
 * kernel headers to use that definition.
 */
#include <netinet/in.h>
#include "linux/xfrm.h"		/* local (if configured) or system copy; for xfrm_user... */

#include <linux/netlink.h>	/* for nlmmsghdr et.al. */

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
void nl_addattr8(struct nlmsghdr *n, int maxlen, int type, const uint8_t data);

const struct nlattr *nl_getattr(const struct nlmsghdr *n, size_t *offset);
const char *nl_getattrvalstrz(const struct nlmsghdr *n,
			      const struct nlattr *attr);

#endif
