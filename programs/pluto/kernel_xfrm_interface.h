#include <linux/if_link.h>
#include "linux/xfrm.h"
#include "err.h"

#if defined(NETKEY_SUPPORT) && defined(USE_XFRM_INTERFACE)
/* how to check defined(XFRMA_IF_ID) && defined(IFLA_XFRM_LINK)? those are enums */
# define IS_XFRMI TRUE
#else
# define IS_XFRMI FALSE
#endif

/* xfrmi interface format. start with ipsec1 IFNAMSIZ - 1 */
#define XFRMI_DEV_FORMAT "ipsec%" PRIu32
struct connection;

struct pluto_xfrmi {
	char *name;
	uint32_t if_id; /* IFLA_XFRM_IF_ID */
	uint32_t dev_if_id;  /* if_id of device, IFLA_XFRM_LINK */
	unsigned int refcount;
	bool shared;
	bool pluto_added;
	struct pluto_xfrmi *next;
};
extern bool setup_xfrm_interface(struct connection *c, uint32_t xfrm_if_id);
extern bool add_xfrmi(struct connection *c);
extern bool ip_link_set_up(const char *if_name);
extern bool stale_xfrmi_interfaces(void);
extern err_t xfrm_iface_supported(void);
extern void free_xfrmi_ipsec1(void);
extern void unreference_xfrmi(struct connection *c);
extern void reference_xfrmi(struct connection *c);

