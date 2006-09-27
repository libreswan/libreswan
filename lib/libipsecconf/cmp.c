/* FreeS/WAN comparisons functions (cmp.c)
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * RCSID $Id: cmp.c,v 1.7 2004/12/01 07:33:14 ken Exp $
 */

#include <sys/queue.h>
#include <string.h>

#include "ipsecconf/keywords.h"

#include "ipsecconf/confread.h"
#include "ipsecconf/cmp.h"

#define streqn(a,b) (a)?((b)?(strcmp(a,b)):(-1)):(b!=NULL)

#define STRCMP(obj)  if (streqn(c1->obj,c2->obj)) return -1
#define STRCMPU(obj) if (streqn((char *)c1->obj, (char *)c2->obj)) return -1
#define VARCMP(obj) if (c1->obj!=c2->obj) return -1
#define MEMCMP(obj) if (memcmp(&c1->obj,&c2->obj,sizeof(c1->obj))) return -1
#define ADDCMP(obj) if (addrcmp(&c1->obj,&c2->obj)) return -1
#define SUBCMP(obj) if (samesubnet(&c1->obj,&c2->obj)==0) return -1

static int starter_cmp_end (struct starter_end *c1, struct starter_end *c2)
{
	if ((!c1) || (!c2)) return -1;
	VARCMP(addr_family);
	ADDCMP(addr);
	ADDCMP(nexthop);
	VARCMP(has_client);
	SUBCMP(subnet);
	STRCMP(iface);
	STRCMP(id);
	STRCMPU(rsakey1);
	STRCMPU(rsakey2);
	STRCMP(strings[KSCF_UPDOWN]);
	STRCMP(cert);
	VARCMP(has_client_wildcard);
	VARCMP(port);
	VARCMP(protocol);
#ifdef VIRTUAL_IP
	STRCMP(virt);
#endif
	return 0;
}

int starter_cmp_conn (struct starter_conn *c1, struct starter_conn *c2)
{
	if ((!c1) || (!c2)) return -1;
	STRCMP(name);
	VARCMP(policy);
	VARCMP(options[KBF_IKELIFETIME]);
	VARCMP(options[KBF_SALIFETIME]);
	VARCMP(options[KBF_REKEYMARGIN]);
	VARCMP(options[KBF_REKEYFUZZ]);
	VARCMP(options[KBF_KEYINGTRIES]);
	if (starter_cmp_end(&c1->left,&c2->left)) return -1;
	if (starter_cmp_end(&c1->right,&c2->right)) return -1;
	VARCMP(options[KBF_AUTO]);
	STRCMP(esp);
	STRCMP(ike);
	return 0;
}

int starter_cmp_klips (struct starter_config *c1, struct starter_config *c2)
{
	if ((!c1) || (!c2)) return -1;
	VARCMP(setup.options[KBF_KLIPSDEBUG]);
	VARCMP(setup.options[KBF_FRAGICMP]);
	VARCMP(setup.options[KBF_HIDETOS]);
	return 0;
}

int starter_cmp_pluto (struct starter_config *c1, struct starter_config *c2)
{
	if ((!c1) || (!c2)) return -1;
	VARCMP(setup.options[KBF_PLUTODEBUG]);
	STRCMP(setup.strings[KSF_PREPLUTO]);
	STRCMP(setup.strings[KSF_POSTPLUTO]);
	VARCMP(setup.options[KBF_UNIQUEIDS]);
	VARCMP(setup.options[KBF_STRICTCRLPOLICY]);
	VARCMP(setup.options[KBF_NOCRSEND]);
	VARCMP(setup.options[KBF_NHELPERS]);
#ifdef NAT_TRAVERSAL
	VARCMP(setup.options[KBF_NATTRAVERSAL]);
	VARCMP(setup.options[KBF_KEEPALIVE]);
#endif
#ifdef VIRTUAL_IP
	STRCMP(setup.strings[KSF_VIRTUALPRIVATE]);
#endif
	return 0;
}

