/*
 * xfrmi declarations, linux kernel IPsec interface/device
 *
 * Copyright (C) 2018-2020 Antony Antony <antony@phenome.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "err.h"

#if defined(linux) && defined(XFRM_SUPPORT) && defined(USE_XFRM_INTERFACE)
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
extern bool add_xfrmi(struct connection *c, struct logger *logger);
extern bool ip_link_set_up(const char *if_name, struct logger *logger);
extern void stale_xfrmi_interfaces(void);
extern err_t xfrm_iface_supported(struct logger *logger);
extern void free_xfrmi_ipsec1(struct logger *logger);
extern void unreference_xfrmi(struct connection *c, struct logger *logger);
extern void reference_xfrmi(struct connection *c);
