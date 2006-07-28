/* FreeS/WAN config file parser (confread.h)
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
 * RCSID $Id: confread.h,v 1.14 2004/12/01 07:33:14 ken Exp $
 */

#ifndef _IPSEC_CONFREAD_H_
#define _IPSEC_CONFREAD_H_

#include "ipsecconf/keywords.h"

#ifndef _OPENSWAN_H
#include <openswan.h>
#include "constants.h"  
#endif


/* define an upper limit to number of times also= can be used */
#define ALSO_LIMIT 32

typedef char *ksf[KEY_STRINGS_MAX];
typedef int   knf[KEY_NUMERIC_MAX];
typedef bool  str_set[KEY_STRINGS_MAX];
typedef bool  int_set[KEY_NUMERIC_MAX];

struct starter_end {
    sa_family_t addr_family;
    enum keyword_host addrtype;
    enum keyword_host nexttype;
    ip_address addr, nexthop;
    bool has_client;
    ip_subnet subnet;
    char *iface;
    char *id;
    unsigned char *rsakey1;
    unsigned char *rsakey2;
    u_int16_t port;
    u_int8_t protocol;
    bool has_client_wildcard;
    bool key_from_DNS_on_demand;
    char *cert;
    char *virt;
    ksf  strings;
    knf  options;

    str_set strings_set;
    int_set options_set;
};

struct starter_conn {
    TAILQ_ENTRY(starter_conn) link;
    char *name;

    ksf   strings;
    knf   options;
    str_set strings_set;
    int_set options_set;

    bool  changed;

    bool  manualkey;         /* TRUE if this conn is going to be manually keyed */
    
    lset_t policy;
    char **alsos;

    struct starter_end left, right;

    unsigned long id;

    enum keyword_auto desired_state;

    enum {
	STATE_INVALID,
	STATE_LOADED,
	STATE_TO_ADD,
	STATE_ADDED,
	STATE_UP,
	STATE_REPLACED,
	STATE_FAILED,
	STATE_IGNORE
    } state;

	char *esp;
	char *ike;
};

struct starter_config {
    struct {
	ksf   strings;
	knf   options;
	str_set strings_set;
	int_set options_set;
	
	/* derived types */
	char **interfaces;
	bool strictcrlpolicy;
	bool nocrsend;
	bool nat_traversal;
	unsigned int keep_alive;
	char *virtual_private;
    } setup;

    /* conn %default */
    struct starter_conn conn_default;
    bool                got_default;

    struct starter_conn conn_oedefault;
    bool                got_oedefault;

    ip_address dr;  /* default route */
    ip_address dnh; /* next hop value */

    char *ctlbase;  /* location of pluto control socket */

    /* connections list (without %default) */
    TAILQ_HEAD(, starter_conn) conns;
};

extern struct starter_config *confread_load(const char *file
					    , err_t *perr
					    , char *ctlbase);
extern struct starter_conn *alloc_add_conn(struct starter_config *cfg
					   , char *name, err_t *perr);
extern int init_load_conn(struct starter_config *cfg
			  , struct config_parsed *cfgp
			  , struct section_list *sconn
			  , bool alsoprocessing
			  , err_t *perr);
extern bool translate_conn (struct starter_conn *conn
			    , struct section_list *sl
			    , bool permitreplace
			    , err_t *error);

void confread_free(struct starter_config *cfg);

#endif /* _IPSEC_CONFREAD_H_ */

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
