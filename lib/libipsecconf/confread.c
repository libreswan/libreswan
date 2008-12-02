/* Openswan config file parser (confread.c)
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2004 Xelerance Corporation
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
 * RCSID $Id: confread.c,v 1.11 2004/04/11 15:17:30 ken Exp $
 */

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <sys/queue.h>

#include "oswalloc.h"

#include "ipsecconf/parser.h"
#include "ipsecconf/files.h"
#include "ipsecconf/confread.h"
#include "ipsecconf/interfaces.h"
#include "ipsecconf/starterlog.h"
#include "ipsecconf/oeconns.h"

static char _tmp_err[512];

/** 
 * A policy only conn means that we load it, and do the appropriate firewalling to make
 * sure that no packets get out that this conn would apply to, but we refuse to negotiate
 * it in any way, either incoming or outgoing.
 */
#define POLICY_ONLY_CONN(conn) if(conn->options[KBF_AUTO] > STARTUP_ROUTE) { conn->options[KBF_AUTO]=STARTUP_POLICY; }

void free_list(char **list);
char **new_list(char *value);


/** 
 * Set up hardcoded defaults, from data in programs/pluto/constants.h
 *
 * @param cfg starter_config struct
 * @return void
 */
static void default_values (struct starter_config *cfg)
{
	if (!cfg) return;
	memset(cfg, 0, sizeof(struct starter_config));

	TAILQ_INIT(&cfg->conns);

	cfg->setup.options[KBF_FRAGICMP] = TRUE;
	cfg->setup.options[KBF_HIDETOS]  = TRUE;
	cfg->setup.options[KBF_PLUTORESTARTONCRASH]  = TRUE;
	cfg->setup.options[KBF_UNIQUEIDS]= FALSE;
#ifdef NAT_TRAVERSAL
	cfg->setup.options[KBF_DISABLEPORTFLOATING]= FALSE;
	cfg->setup.options[KBF_FORCE_KEEPALIVE]= FALSE;
	cfg->setup.options[KBF_KEEPALIVE]= 0;
#endif
	cfg->conn_default.options[KBF_TYPE] = KS_TUNNEL;

	cfg->conn_default.policy = POLICY_RSASIG|POLICY_TUNNEL|POLICY_ENCRYPT|POLICY_PFS;

	cfg->conn_default.options[KBF_IKELIFETIME] = OAKLEY_ISAKMP_SA_LIFETIME_DEFAULT;
	cfg->conn_default.options[KBF_SALIFETIME]  = SA_LIFE_DURATION_DEFAULT;
	cfg->conn_default.options[KBF_REKEYMARGIN] = SA_REPLACEMENT_MARGIN_DEFAULT;
	cfg->conn_default.options[KBF_REKEYFUZZ]   = SA_REPLACEMENT_FUZZ_DEFAULT;
	cfg->conn_default.options[KBF_KEYINGTRIES] = SA_REPLACEMENT_RETRIES_DEFAULT;

	/* now here is a sticker.. we want it on. But pluto has to be smarter first */
	cfg->conn_default.options[KBF_OPPOENCRYPT] = FALSE;

	cfg->conn_default.left.addr_family = AF_INET;
	anyaddr(AF_INET, &cfg->conn_default.left.addr);
	cfg->conn_default.left.nexttype  = KH_NOTSET;
	anyaddr(AF_INET, &cfg->conn_default.left.nexthop);

	cfg->conn_default.right.addr_family = AF_INET;
	anyaddr(AF_INET, &cfg->conn_default.right.addr);
	cfg->conn_default.right.nexttype = KH_NOTSET;
	anyaddr(AF_INET, &cfg->conn_default.right.nexthop);

	/* default is to look in DNS */
	cfg->conn_default.left.key_from_DNS_on_demand = TRUE;
	cfg->conn_default.right.key_from_DNS_on_demand = TRUE;


	cfg->conn_default.options[KBF_AUTO] = STARTUP_NO;
	cfg->conn_default.state = STATE_LOADED;

	cfg->ctlbase = clone_str(CTL_FILE, "default base");
}

/* format error, and append to string of errors */
int error_append(char **perr, const char *fmt, ...) 
{
    va_list args;

    if(perr) {
	char *nerr; 
	int len; 
	
	va_start(args, fmt);
	vsnprintf(_tmp_err, sizeof(_tmp_err)-1, fmt, args);
	va_end(args);
	
	len = 1+ strlen(_tmp_err) + (*perr ? strlen(*perr) : 0);	
	nerr = xmalloc(len);
	nerr[0]='\0';
	if(*perr) strcpy(nerr, *perr); 
	strcat(nerr, _tmp_err);			
	
	if(*perr) free(*perr);
	*perr = nerr;

	return 1;
    }
    return 0;
}

#define ERR_FOUND(args...) do { err += error_append(&err_str, ##args); } while(0)


#define KW_POLICY_FLAG(val,fl) if(conn->options_set[val]) \
        { if(conn->options[val]) \
	  { \
	    conn->policy |= fl; \
	  } else { \
	    conn->policy &= ~fl;\
	  }}

#define KW_POLICY_NEGATIVE_FLAG(val,fl) if(conn->options_set[val]) \
        { if(!conn->options[val]) \
	  { \
	    conn->policy |= fl; \
	  } else { \
	    conn->policy &= ~fl;\
	  }}

/**
 * Free the pointer list
 *
 * @param list list of pointers
 * @return void
 */
void free_list(char **list)
{
	char **s;
	for (s=list; *s; s++) free(*s);
	free(list);
}


/**
 * Create a new list of pointers
 *
 * @param value 
 * @return new_list (pointer to list of pointers)
 */
char **new_list(char *value)
{
	char *val, *b, *e, *end, **nlist;
	int count;

	if(value == NULL) return NULL;

	/* avoid damaging original string */
	val = xstrdup(value);
	if(val == NULL) return NULL;

	end = val + strlen(val);

	/* count number of items in string */
	for (b=val, count=0; b<end; ) {
		for (e=b; ((*e!=' ') && (*e!='\0')); e++);
		*e = '\0';
		if (e!=b) { count++; }
		b=e+1;
	}
	if (count==0) {
		free(val);
		return NULL;
	}
	
	nlist = (char **)malloc((count+1) * sizeof(char *));
	if (!nlist) {
		free(val);
		return NULL;
	}
	for (b=val, count=0; b<end; ) {
		for (e=b; (*e!='\0'); e++);
		if (e!=b) {
			nlist[count++] = xstrdup(b);
		}
		b=e+1;
	}
	nlist[count] = NULL;
	free(val);
	return nlist;
}

/**
 * Load a parsed config 
 *
 * @param cfg starter_config structure
 * @param cfgp config_parsed (ie: valid) struct
 * @param perr pointer to store errors in
 * @return int 0 if successfull
 */
static int load_setup (struct starter_config *cfg
		       , struct config_parsed *cfgp
		       , err_t *perr)
{
	unsigned int err = 0;
	struct kw_list *kw;

	for (kw=cfgp->config_setup; kw; kw=kw->next) {

	    /**
	     * the parser already made sure that only config keywords were used,
	     * but we double check!
	     */
	    assert(kw->keyword.keydef->validity & kv_config);

	    switch(kw->keyword.keydef->type)
	    {
	    case kt_string:
	    case kt_filename:
	    case kt_dirname:
	    case kt_loose_enum:
		/* all treated as strings for now */
		assert(kw->keyword.keydef->field < sizeof(cfg->setup.strings));
		if(cfg->setup.strings[kw->keyword.keydef->field]) free(cfg->setup.strings[kw->keyword.keydef->field]);
		cfg->setup.strings[kw->keyword.keydef->field] = xstrdup(kw->string);
		cfg->setup.strings_set[kw->keyword.keydef->field]=TRUE;
		break;

	    case kt_appendstring:
	    case kt_appendlist:
		assert(kw->keyword.keydef->field < KEY_STRINGS_MAX);
		if(!cfg->setup.strings[kw->keyword.keydef->field])
		{
		    cfg->setup.strings[kw->keyword.keydef->field] = xstrdup(kw->string);
		    cfg->setup.strings_set[kw->keyword.keydef->field]=TRUE;
		} else {
		    int len;
		    char *s;
		    
		    len = strlen(cfg->setup.strings[kw->keyword.keydef->field])+1;
		    len += strlen(kw->string)+1;
		    
		    /* allocate the string */
		    s = cfg->setup.strings[kw->keyword.keydef->field];
		    s = xrealloc(s, len);
		    strncat(s, " ", len);
		    strncat(s, kw->string, len);
		    
		    cfg->setup.strings[kw->keyword.keydef->field] = s;
		    cfg->setup.strings_set[kw->keyword.keydef->field]=TRUE;
		}
		break;
		
	    case kt_list:
	    case kt_bool:
	    case kt_invertbool:
	    case kt_enum:
	    case kt_number:
	    case kt_time:
	    case kt_percent:
		/* all treated as a number for now */
		assert(kw->keyword.keydef->field < sizeof(cfg->setup.options));
		cfg->setup.options[kw->keyword.keydef->field] = kw->number;
		cfg->setup.options_set[kw->keyword.keydef->field]=TRUE;
		break;

	    case kt_bitstring:
	    case kt_rsakey:
	    case kt_ipaddr:
	    case kt_subnet:
	    case kt_idtype:
		err++;
		break;

	    case kt_comment:
		break;
	    }
	}
		
	/* now process some things with specific values */
	
	/* interfaces has to be chopped up */
	if (cfg->setup.interfaces) free_list(cfg->setup.interfaces);
	cfg->setup.interfaces = new_list(cfg->setup.strings[KSF_INTERFACES]);

	return err;
}

/**
 * Validate that yes in fact we are one side of the tunnel
 * 
 * The function checks that IP addresses are valid, nexthops are
 * present (if needed) as well as policies, and sets the leftID 
 * from the left= if it isn't set.
 *
 * @param conn_st a connection definition
 * @param end a connection end
 * @param left boolean (are we 'left'? 1 = yes, 0 = no)
 * @param perr pointer to char containing error value
 * @return int 0 if successfull
 */
static int validate_end(struct starter_conn *conn_st
			, struct starter_end *end
			, bool left
			, bool resolvip UNUSED
			, err_t *perr)
{
    err_t er = NULL;
    char *err_str = NULL;
    const char *leftright=(left ? "left" : "right");
    int err=0;

    if(!end->options_set[KNCF_IP]) {
	conn_st->state = STATE_INCOMPLETE;
    }

    end->addrtype=end->options[KNCF_IP];

    /* validate the KSCF_IP/KNCF_IP */
    switch(end->addrtype)
    {
    case KH_ANY:
	anyaddr(AF_INET, &(end->addr));
	break;

    case KH_IFACE:
	assert(end->strings[KSCF_IP] != NULL);

	if (end->iface) free(end->iface);
	end->iface = xstrdup(end->strings[KNCF_IP]);
	if (starter_iface_find(end->iface, AF_INET, &(end->addr),
			       &(end->nexthop)) == -1) {
	    conn_st->state = STATE_INVALID;
	}
	break;
	
    case KH_IPADDR:
	assert(end->strings[KSCF_IP] != NULL);

	er = ttoaddr_num(end->strings[KNCF_IP], 0, AF_INET, &(end->addr));
	if(er) {
	    /* not numeric, so set the type to the string type */
	    end->addrtype = KH_IPHOSTNAME; 
	}

        if(end->id == NULL) {
            char idbuf[ADDRTOT_BUF];
            addrtot(&end->addr, 0, idbuf, sizeof(idbuf));

            end->id=clone_str(idbuf, "end if");
        }
	break;
	
    case KH_OPPO:
	conn_st->policy |= POLICY_OPPO;
	break;

    case KH_OPPOGROUP:
	conn_st->policy |= POLICY_OPPO|POLICY_GROUP;
	break;

    case KH_GROUP:
	conn_st->policy |= POLICY_GROUP;
	break;
	
    case KH_IPHOSTNAME:
	/* generally, this doesn't show up at this stage */
	break;

    case KH_DEFAULTROUTE:
	break;

    case KH_NOTSET:
	break;
    }

    /* validate the KSCF_SUBNET */
    if(end->strings_set[KSCF_SUBNET])
    {
	char *value = end->strings[KSCF_SUBNET];

        if ( ((strlen(value)>=6) && (strncmp(value,"vhost:",6)==0)) ||
	     ((strlen(value)>=5) && (strncmp(value,"vnet:",5)==0)) ) {
	    er = NULL;
	    end->virt = xstrdup(value);
	    if (!end->virt) ERR_FOUND("can't alloc memory");
	}
	else {
	    end->has_client = TRUE;
	    er = ttosubnet(value, 0, AF_INET, &(end->subnet));
	}
	if (er) ERR_FOUND("bad subnet %ssubnet=%s [%s]", leftright, value, er);
    }

    /* set nexthop address to something consistent, by default */
    anyaddr(AF_INET, &end->nexthop);
    anyaddr(addrtypeof(&end->addr), &end->nexthop);

    /* validate the KSCF_NEXTHOP */
    if(end->strings_set[KSCF_NEXTHOP])
    {
	char *value = end->strings[KSCF_NEXTHOP];

	if(strcasecmp(value, "%defaultroute")==0) {
	    end->nexttype=KH_DEFAULTROUTE;
	} else {
	    er = ttoaddr(value, 0, AF_INET, &(end->nexthop));
	    if (er) ERR_FOUND("bad addr %snexthop=%s [%s]", leftright, value, er);

	    end->nexttype = KH_IPADDR;
	}
    } else {
#if 0
	if(conn_st->policy & POLICY_OPPO) {
	    end->nexttype = KH_DEFAULTROUTE;
	}
#endif
	anyaddr(AF_INET, &end->nexthop);
    }

    /* validate the KSCF_ID */
    if(end->strings_set[KSCF_ID])
    {
	char *value = end->strings[KSCF_ID];
	
	if (end->id) free(end->id);
	end->id = xstrdup(value);
    }

    if(end->options_set[KSCF_RSAKEY1]) {
	end->rsakey1_type = end->options[KSCF_RSAKEY1];
	end->rsakey2_type = end->options[KSCF_RSAKEY2];

	switch(end->options[KSCF_RSAKEY1]) {
	case PUBKEY_DNS:
	case PUBKEY_DNSONDEMAND:
	    end->key_from_DNS_on_demand = TRUE;
	    break;
	    
	default:
	    end->key_from_DNS_on_demand = FALSE;
	    /* validate the KSCF_RSAKEY1/RSAKEY2 */
	    if(end->strings[KSCF_RSAKEY1] != NULL)
	    {
		char *value = end->strings[KSCF_RSAKEY1];
		
		if (end->rsakey1) free(end->rsakey1);
		end->rsakey1 = (unsigned char *)xstrdup(value);
	    }
	    if(end->strings[KSCF_RSAKEY2] != NULL)
	    {
		char *value = end->strings[KSCF_RSAKEY2];
		
		if (end->rsakey2) free(end->rsakey2);
		end->rsakey2 = (unsigned char *)xstrdup(value);
	    }
	}
    }

    /* validate the KSCF_SOURCEIP, if any, and if set,
     * set the subnet to same value, if not set.
     */
    if(end->strings_set[KSCF_SOURCEIP])
    {
	char *value = end->strings[KSCF_SOURCEIP];
	
	er = ttoaddr(value, 0, AF_INET, &(end->sourceip));
	if (er) ERR_FOUND("bad addr %ssourceip=%s [%s]", leftright, value, er);

	if(!end->has_client) {
	    starter_log(LOG_LEVEL_INFO, "defaulting %ssubnet to %s\n", leftright, value);
	    er = addrtosubnet(&end->sourceip, &end->subnet);
	    if (er) ERR_FOUND("attempt to default %ssubnet from %s failed: %s", leftright, value, er);
	    end->has_client = TRUE;
	    end->has_client_wildcard = FALSE;
	}
    } 

    /* copy certificate path name */
    if(end->strings_set[KSCF_CERT]) {
	end->cert = xstrdup(end->strings[KSCF_CERT]);
    }

    if(end->strings_set[KSCF_CA]) {
	end->ca = xstrdup(end->strings[KSCF_CA]);
    }

    if(end->strings_set[KSCF_UPDOWN]) {
	end->updown = xstrdup(end->strings[KSCF_UPDOWN]);
    }

    if(end->strings_set[KSCF_PROTOPORT]) {
	err_t ugh;
	char *value = end->strings[KSCF_PROTOPORT];

	ugh = ttoprotoport(value, 0, &end->protocol, &end->port, &end->has_port_wildcard);

	if (ugh) ERR_FOUND("bad %sprotoport=%s [%s]", leftright, value, ugh);
    }

    /*
    KSCF_SUBNETWITHIN    --- not sure what to do with it.
    KSCF_ESPENCKEY       --- todo (manual keying)
    KSCF_ESPAUTHKEY      --- todo (manual keying)
    KSCF_SOURCEIP     = 16,
    KSCF_MAX          = 19
*/

    if(err) *perr = err_str;
    return err;
}


/**
 * Take keywords from ipsec.conf syntax and load into a conn struct
 * 
 *
 * @param conn a connection definition
 * @param sl a section_list
 * @param assigned_value is set to either k_set, or k_default.
 *        k_default is used when we are loading a conn that should be
 *        considered to be a "default" value, and that replacing this
 *        value is considered acceptable.
 * @return bool 0 if successfull
 */
bool translate_conn (struct starter_conn *conn
		     , struct section_list *sl
		     , enum keyword_set   assigned_value
		     , err_t *error)
{
    unsigned int err, field;
    ksf    *the_strings;
    knf    *the_options;
    str_set *set_strings;
    int_set *set_options;
    volatile int i;              /* just to keep it around for debugging */
    struct kw_list *kw = sl->kw;
	
    err = 0;
    i = 0;

    for ( ; kw; kw=kw->next)
    {
	i++;
	the_strings = &conn->strings;
	set_strings = &conn->strings_set;
	the_options = &conn->options;
	set_options = &conn->options_set;
	
	if((kw->keyword.keydef->validity & kv_conn) == 0)
	{
	    /* this isn't valid in a conn! */
	    *error = (const char *)_tmp_err;

	    snprintf(_tmp_err, sizeof(_tmp_err),
		     "keyword '%s' is not valid in a conn (%s) (#%d)\n",
		     kw->keyword.keydef->keyname, sl->name, i);
	    starter_log(LOG_LEVEL_INFO, _tmp_err);
	    continue;
	}
	
	if(kw->keyword.keydef->validity & kv_leftright)
	{
	    if(kw->keyword.keyleft)
	    {
		the_strings = &conn->left.strings;
		the_options = &conn->left.options;
		set_strings = &conn->left.strings_set;
		set_options = &conn->left.options_set;
	    } else {
		the_strings = &conn->right.strings;
		the_options = &conn->right.options;
		set_strings = &conn->right.strings_set;
		set_options = &conn->right.options_set;
	    }
	}
	
	field = kw->keyword.keydef->field;

#ifdef PARSER_TYPE_DEBUG
	starter_log(LOG_LEVEL_DEBUG, "#analyzing %s[%d] kwtype=%d\n",
		    kw->keyword.keydef->keyname, field,
		    kw->keyword.keydef->type);
#endif

	assert(kw->keyword.keydef != NULL);
	switch(kw->keyword.keydef->type)
	{
	case kt_string:
	case kt_filename:
	case kt_dirname:
	case kt_bitstring:
	case kt_ipaddr:
	case kt_subnet:
	case kt_idtype:
	    /* all treated as strings for now */
	    assert(kw->keyword.keydef->field < KEY_STRINGS_MAX);
	    if((*set_strings)[field] == k_set)
	    {
		*error = _tmp_err;
		
		snprintf(_tmp_err, sizeof(_tmp_err)
			 , "duplicate key '%s' in conn %s while processing def %s"
			 , kw->keyword.keydef->keyname
			 , conn->name
			 , sl->name);
		
		starter_log(LOG_LEVEL_INFO, _tmp_err);
		if(kw->keyword.string == NULL
		   || (*the_strings)[field] == NULL
		   || strcmp(kw->keyword.string, (*the_strings)[field])!=0)
		{
		    err++;
		    break;
		}
	    }
	    if((*the_strings)[field])
	    {
		    free((*the_strings)[field]);
	    }
	    
	    (*the_strings)[field] = xstrdup(kw->string);
	    (*set_strings)[field] = assigned_value;
	    break;
	    
	case kt_appendstring:
	case kt_appendlist:
	    /* implicitely, this field can have multiple values */
	    assert(kw->keyword.keydef->field < KEY_STRINGS_MAX);
	    if(!(*the_strings)[field])
	    {
		(*the_strings)[field] = xstrdup(kw->string);
	    } else {
		int len;
		char *s;
		
		len = strlen((*the_strings)[field])+1;
		len += strlen(kw->string)+1;
		
		/* allocate the string */
		s = (*the_strings)[field];
		s = xrealloc(s, len);
		strncat(s, " ", len);
		strncat(s, kw->string, len);
		
		(*the_strings)[field] = s;
	    }
	    (*set_strings)[field] = TRUE;
	    break;
	    
	case kt_rsakey:
	case kt_loose_enum:
	    assert(field < KEY_STRINGS_MAX);
	    assert(field < KEY_NUMERIC_MAX);
	    
	    if((*set_options)[field] == k_set)
	    {
		*error = _tmp_err;
		snprintf(_tmp_err, sizeof(_tmp_err)
			 , "duplicate key '%s' in conn %s while processing def %s"
			 , kw->keyword.keydef->keyname
			 , conn->name
			 , sl->name);
		
		starter_log(LOG_LEVEL_INFO, _tmp_err);
		
		/* only fatal if we try to change values */
		if((*the_options)[field] != kw->number
		   || !((*the_options)[field] == LOOSE_ENUM_OTHER
			&& kw->number == LOOSE_ENUM_OTHER
			&& kw->keyword.string != NULL
			&& (*the_strings)[field] != NULL
			&& strcmp(kw->keyword.string, (*the_strings)[field])==0))
		{
		    err++;
		    break;
		}
	    }

	    (*the_options)[field] = kw->number;
	    if(kw->number == LOOSE_ENUM_OTHER)
	    {
		assert(kw->keyword.string != NULL);
		if((*the_strings)[field]) free((*the_strings)[field]);
		(*the_strings)[field] = xstrdup(kw->keyword.string);
	    } 
	    (*set_options)[field] = assigned_value;
	    break;
	    
	case kt_list:
	case kt_bool:
	case kt_invertbool:
	case kt_enum:
	case kt_number:
	case kt_time:
	case kt_percent:
	    /* all treated as a number for now */
	    assert(field < KEY_NUMERIC_MAX);

	    if((*set_options)[field] == k_set)
	    {
		*error = _tmp_err;
		snprintf(_tmp_err, sizeof(_tmp_err)
			 , "duplicate key '%s' in conn %s while processing def %s"
			 , kw->keyword.keydef->keyname
			 , conn->name
			 , sl->name);
		starter_log(LOG_LEVEL_INFO, _tmp_err);
		if((*the_options)[field] != kw->number)
		{
		    err++;
		    break;
		}
	    }

#if 0
	    starter_log(LOG_LEVEL_DEBUG, "#setting %s[%d]=%u\n",
			kw->keyword.keydef->keyname, field, kw->number);
#endif
	    (*the_options)[field] = kw->number;
	    (*set_options)[field] = assigned_value;
	    break;
	    
	case kt_comment:
	    break;
	}
    }
    return err;
}


void move_comment_list(struct starter_comments_list *to,
		       struct starter_comments_list *from)
{
    struct starter_comments *sc, *scnext;
    
    for(sc = from->tqh_first;
	sc != NULL;
	sc = scnext) {
	scnext = sc->link.tqe_next;
	TAILQ_REMOVE(from, sc,link);
	TAILQ_INSERT_TAIL(to, sc,link);
    }
}

static int load_conn_basic(struct starter_conn *conn
			   , struct section_list *sl
			   , enum keyword_set assigned_value
			   , err_t *perr)
{
    int err;

    /*turn all of the keyword/value pairs into options/strings in left/right */
    err = translate_conn(conn, sl, assigned_value, perr);

    return err;
}



static int load_conn (struct starter_config *cfg
		      , struct starter_conn *conn
		      , struct config_parsed *cfgp
		      , struct section_list *sl
		      , bool alsoprocessing
		      , bool defaultconn
		      , bool resolvip
		      , err_t *perr)
{
    unsigned int err;
    char **alsos;
    char **newalsos;
    int   newalsoplace;
    int   alsoplace;
    int   alsosize;
    struct section_list *sl1;
	
    err = 0;

    err += load_conn_basic(conn, sl, defaultconn ? k_default : k_set, perr);

    move_comment_list(&conn->comments, &sl->comments);

    if(err) return err;

    if(conn->strings[KSF_ALSO] != NULL
       && !alsoprocessing)
    {
	starter_log(LOG_LEVEL_INFO
		    , "also= is not valid in section '%s'"
		    , sl->name);
	return 1;
    }

    /* now, process the also's */
    if (conn->alsos) free_list(conn->alsos);
    conn->alsos = new_list(conn->strings[KSF_ALSO]);

    if(alsoprocessing && conn->alsos)
    {
	/* reset all of the "beenhere" flags */
	for(sl1 = cfgp->sections.tqh_first; sl1 != NULL; sl1 = sl1->link.tqe_next)
	{
	    sl1->beenhere = FALSE;
	}
	sl->beenhere = TRUE;
	
	/* count them */
	alsos = conn->alsos;
	conn->alsos = NULL;
	for(alsosize=0; alsos[alsosize]!=NULL; alsosize++);

	alsoplace = 0;
	while(alsos != NULL
	      && alsoplace < alsosize && alsos[alsoplace] != NULL 
	      && alsoplace < ALSO_LIMIT)
	{
	    /*
	     * for each also= listed, go find this section's keyword list, and
	     * load it as well. This may extend the also= list (and the end),
	     * which we handle by zeroing the also list, and adding to it after
	     * checking for duplicates.
	     */
	    for(sl1 = cfgp->sections.tqh_first;
		sl1 != NULL && strcasecmp(alsos[alsoplace], sl1->name) != 0;
		sl1 = sl1->link.tqe_next);

	    starter_log(LOG_LEVEL_DEBUG, "\twhile loading conn '%s' also including '%s'"
			, conn->name, alsos[alsoplace]);
			    
	    /*
	     * if we found something that matches by name, and we haven't be
	     * there, then process it.
	     */
	    if(sl1 && !sl1->beenhere)
	    {
		conn->strings_set[KSF_ALSO]=FALSE;
		if(conn->strings[KSF_ALSO]) free(conn->strings[KSF_ALSO]);
		conn->strings[KSF_ALSO]=NULL;
		sl1->beenhere = TRUE;

		/* translate things, but do not replace earlier settings!*/
		err += translate_conn(conn, sl1, k_set, perr);

		if(conn->strings[KSF_ALSO])
		{
		    /* now, check out the KSF_ALSO, and extend list if we need to */
		    newalsos = new_list(conn->strings[KSF_ALSO]);		
		    
		    if(newalsos && newalsos[0]!=NULL)
		    {
			/* count them */
			for(newalsoplace=0; newalsos[newalsoplace]!=NULL; newalsoplace++);
			
			/* extend conn->alsos */
			alsos = xrealloc(alsos, (alsosize+newalsoplace+1) * sizeof(char *));
			for(newalsoplace=0; newalsos[newalsoplace]!=NULL; newalsoplace++)
			{
			    assert(conn != NULL);
			    assert(conn->name != NULL);
			    starter_log(LOG_LEVEL_DEBUG
					, "\twhile processing section '%s' added also=%s"
					, sl1->name, newalsos[newalsoplace]);
			    
			    alsos[alsosize++]=xstrdup(newalsos[newalsoplace]);
			}
			alsos[alsosize]=NULL;
		    }
		    
		    free_list(newalsos);
		}
	    }
	    alsoplace++;
	}
	
	if(alsoplace >= ALSO_LIMIT)
	{
	    starter_log(LOG_LEVEL_INFO
			, "while loading conn '%s', too many also= used at section %s. Limit is %d"
			, conn->name
			, conn->alsos[alsoplace]
			, ALSO_LIMIT);
	    return 1;
	}
	
	if(conn->alsos != alsos && conn->alsos != NULL)
	{
	    free_list(conn->alsos);
	}
	conn->alsos = alsos;
    }

#ifdef PARSER_TYPE_DEBUG
    /* translate strings/numbers into conn items */
    starter_log(LOG_LEVEL_DEBUG, "#checking options_set[KBF_TYPE,%d]=%d %d\n",
		KBF_TYPE,
		conn->options_set[KBF_TYPE], conn->options[KBF_TYPE]);
#endif

    if(conn->options_set[KBF_TYPE]) {
	switch((enum keyword_satype)conn->options[KBF_TYPE]) {
	case KS_TUNNEL:
	    conn->policy |= POLICY_TUNNEL;
	    conn->policy &= ~POLICY_SHUNT_MASK;
	    break;

	case KS_TRANSPORT:
	    conn->policy &= ~POLICY_TUNNEL;
	    conn->policy &= ~POLICY_SHUNT_MASK;
	    break;
	    
	case KS_UDPENCAP:
	    /* no way to specify this yet! */
	    break;

	case KS_PASSTHROUGH:
	    conn->policy &= ~(POLICY_ENCRYPT|POLICY_AUTHENTICATE|POLICY_TUNNEL|POLICY_RSASIG);
	    conn->policy &= ~POLICY_SHUNT_MASK;
	    conn->policy |= POLICY_SHUNT_PASS;
	    break;

	case KS_DROP:
	    conn->policy &= ~(POLICY_ENCRYPT|POLICY_AUTHENTICATE|POLICY_TUNNEL|POLICY_RSASIG);
	    conn->policy &= ~POLICY_SHUNT_MASK;
	    conn->policy |= POLICY_SHUNT_DROP;
	    break;

	case KS_REJECT:
	    conn->policy &= ~(POLICY_ENCRYPT|POLICY_AUTHENTICATE|POLICY_TUNNEL|POLICY_RSASIG);
	    conn->policy &= ~POLICY_SHUNT_MASK;
	    conn->policy |= POLICY_SHUNT_REJECT;
	    break;
	}
    }
	    
    KW_POLICY_FLAG(KBF_COMPRESS, POLICY_COMPRESS);
    KW_POLICY_FLAG(KBF_PFS,  POLICY_PFS);
    
    /* reset authby flags */
    if(conn->options_set[KBF_AUTHBY]) {
	conn->policy &= ~(POLICY_ID_AUTH_MASK);
	conn->policy |= conn->options[KBF_AUTHBY];

#if STARTER_POLICY_DEBUG
	starter_log(LOG_LEVEL_DEBUG,
		    "%s: setting conn->policy=%08x (%08x)\n",
		    conn->name,
		    (unsigned int)conn->policy,
		    conn->options[KBF_AUTHBY]);
#endif
    }
    
    KW_POLICY_NEGATIVE_FLAG(KBF_REKEY, POLICY_DONT_REKEY);

    KW_POLICY_FLAG(KBF_AGGRMODE, POLICY_AGGRESSIVE);

    KW_POLICY_FLAG(KBF_MODECONFIGPULL, POLICY_MODECFG_PULL);

    KW_POLICY_FLAG(KBF_OVERLAPIP, POLICY_OVERLAPIP);

    if(conn->strings_set[KSF_ESP]) {
	conn->esp = xstrdup(conn->strings[KSF_ESP]);
    }

    if(conn->strings_set[KSF_IKE]) {
	conn->ike = xstrdup(conn->strings[KSF_IKE]);
    }

    if(conn->strings_set[KSF_CONNALIAS]) {
	conn->connalias = xstrdup(conn->strings[KSF_CONNALIAS]);
    }

    if(conn->options_set[KBF_PHASE2]) {
	conn->policy &= ~(POLICY_AUTHENTICATE|POLICY_ENCRYPT);
	conn->policy |= conn->options[KBF_PHASE2];
    }

    err += validate_end(conn, &conn->left,  TRUE,  resolvip, perr);
    err += validate_end(conn, &conn->right, FALSE, resolvip, perr);

    if(conn->options_set[KBF_AUTO]) {
	conn->desired_state = conn->options[KBF_AUTO];
    }
    
    return err;
}

    
void conn_default (char *n, struct starter_conn *conn,
		   struct starter_conn *def)
{
    int i;

    /* structure copy to start */
    *conn = *def;

    /* unlink it */
    memset(&conn->link, 0, sizeof(conn->link));

#define CONN_STR2(v,T) if (v) v=(T)xstrdup((char *)v)
#define CONN_STR(v) if (v) v=xstrdup((char *)v)
    CONN_STR(conn->left.iface);
    CONN_STR(conn->left.id);
    CONN_STR2(conn->left.rsakey1, unsigned char * );
    CONN_STR2(conn->left.rsakey2, unsigned char * );
    CONN_STR(conn->right.iface);
    CONN_STR(conn->right.id);
    CONN_STR2(conn->right.rsakey1, unsigned char *);
    CONN_STR2(conn->right.rsakey2, unsigned char *);
    
    for(i=0; i<KSCF_MAX; i++)
    {
	CONN_STR(conn->left.strings[i]);
	CONN_STR(conn->right.strings[i]);
    }
    for(i=0; i<KNCF_MAX; i++)
    {
	conn->left.options[i] = def->left.options[i];
	conn->right.options[i]= def->right.options[i];
    }
    for(i=0 ;i<KSF_MAX; i++)
    {
	CONN_STR(conn->strings[i]);
    }
    for(i=0 ;i<KBF_MAX; i++)
    {
	conn->options[i] = def->options[i];
    }
    
    CONN_STR(conn->esp);
    CONN_STR(conn->ike);

    conn->policy = def->policy;
#undef CONN_STR
}

struct starter_conn *alloc_add_conn(struct starter_config *cfg, char *name, err_t *perr)
{
    struct starter_conn *conn;
    
    conn = (struct starter_conn *)malloc(sizeof(struct starter_conn));
    memset(conn, 0, sizeof(struct starter_conn));
    if (!conn) {
	if (perr) *perr = xstrdup("can't allocate mem in confread_load()");
	return NULL;
    }

    conn_default(name, conn, &cfg->conn_default);
    conn->name = xstrdup(name);
    conn->desired_state = STARTUP_NO;
    conn->state = STATE_FAILED;

    TAILQ_INIT(&conn->comments);
    
    TAILQ_INSERT_TAIL(&cfg->conns, conn, link);
    return conn;
}

int init_load_conn(struct starter_config *cfg
		   , struct config_parsed *cfgp
		   , struct section_list *sconn
		   , bool alsoprocessing
		   , bool defaultconn
		   , bool resolvip
		   , err_t *perr)
{
    int connerr;
    struct starter_conn *conn;
    starter_log(LOG_LEVEL_DEBUG, "Loading conn %s", sconn->name);

    conn = alloc_add_conn(cfg, sconn->name, perr);
    if(conn == NULL) {
	return -1;
    }
    
    connerr = load_conn (cfg, conn, cfgp, sconn, TRUE,
			 defaultconn, resolvip, perr);
		
    if(connerr != 0) {
	starter_log(LOG_LEVEL_INFO, "while loading '%s': %s\n",
		    sconn->name, *perr);
    }
    if(connerr == 0)
    {
	conn->state = STATE_LOADED;
    }
    return connerr;
}


struct starter_config *confread_load(const char *file
				     , err_t *perr
				     , bool resolvip
				     , char *ctlbase)
{
	struct starter_config *cfg = NULL;
	struct config_parsed *cfgp;
	struct section_list *sconn;
	unsigned int err = 0, connerr;

	/**
	 * Load file
	 */
	cfgp = parser_load_conf(file, perr);
	if (!cfgp) return NULL;

	cfg = (struct starter_config *)malloc(sizeof(struct starter_config));
	if (!cfg) {
		if (perr) *perr = xstrdup("can't allocate mem in confread_load()");
		parser_free_conf(cfgp);
		return NULL;
	}
	memset(cfg, 0, sizeof(*cfg));

	/**
	 * Set default values
	 */
	default_values(cfg);

	if(ctlbase) {
	    pfree(cfg->ctlbase);
	    cfg->ctlbase = clone_str(ctlbase, "control socket");
	}

	/**
	 * Load setup
	 */
	err += load_setup(cfg, cfgp, perr);

	if(err) {return NULL;}

	/**
	 * Find %default and %oedefault conn
	 *
	 */
	for(sconn = cfgp->sections.tqh_first; (!err) && sconn != NULL; sconn = sconn->link.tqe_next)
	{
		if (strcmp(sconn->name,"%default")==0) {
			starter_log(LOG_LEVEL_DEBUG, "Loading default conn");
			err += load_conn (cfg, &cfg->conn_default,
					  cfgp, sconn, FALSE,
					  /*default conn*/TRUE,
					  resolvip, perr);
		}

		if (strcmp(sconn->name,"%oedefault")==0) {
			starter_log(LOG_LEVEL_DEBUG, "Loading oedefault conn");
			err += load_conn (cfg, &cfg->conn_oedefault,
					  cfgp, sconn, FALSE,
					  /*default conn*/TRUE,
					  resolvip, perr);
			if(err == 0) {
			    cfg->got_oedefault=TRUE;
			}
		}
	}

	/**
	 * Load other conns
	 */
	for(sconn = cfgp->sections.tqh_first; sconn != NULL; sconn = sconn->link.tqe_next)
	{
		if (strcmp(sconn->name,"%default")==0) continue;
		if (strcmp(sconn->name,"%oedefault")==0) continue;

		connerr = init_load_conn(cfg, cfgp, sconn, TRUE, FALSE,
					 resolvip, perr);

		if(connerr == -1) {
		    parser_free_conf(cfgp);
		    confread_free(cfg);
		    return NULL;
		}
		err += connerr;
	}

	/* if we have OE on, then create any missing OE conns! */
	if(cfg->setup.options[KBF_OPPOENCRYPT]) {
	    starter_log(LOG_LEVEL_DEBUG, "Enabling OE conns\n");
	    add_any_oeconns(cfg, cfgp);
	}

	parser_free_conf(cfgp);

	return cfg;
}

#define FREE_STR(v) { if (v) { free(v); v=NULL; } }
#define FREE_LST(v) { if (v) { free_list(v); v=NULL; } }
static void confread_free_conn(struct starter_conn *conn)
{
    int i;
	FREE_STR(conn->left.iface);
	FREE_STR(conn->left.id);
	FREE_STR(conn->left.rsakey1);
	FREE_STR(conn->left.rsakey2);
	FREE_STR(conn->right.iface);
	FREE_STR(conn->right.id);
	FREE_STR(conn->right.rsakey1);
	FREE_STR(conn->right.rsakey2);
	for(i=0; i<KSCF_MAX; i++)
	{
	    FREE_STR(conn->left.strings[i]);
	    FREE_STR(conn->right.strings[i]);
	}
	for(i=0 ;i<KSF_MAX; i++)
	{
	    FREE_STR(conn->strings[i]);
	}

	FREE_STR(conn->connalias);
	FREE_STR(conn->name);

#ifdef ALG_PATCH
	FREE_STR(conn->esp);
	FREE_STR(conn->ike);
#endif
	FREE_STR(conn->left.virt);
	FREE_STR(conn->right.virt);
}

void confread_free(struct starter_config *cfg)
{
    int i;
	struct starter_conn *conn, *c;
	FREE_LST(cfg->setup.interfaces);
	FREE_STR(cfg->setup.virtual_private);
	for(i=0 ;i<KSF_MAX; i++)
	{
	    FREE_STR(cfg->setup.strings[i]);
	}
	confread_free_conn(&(cfg->conn_default));

	for(conn = cfg->conns.tqh_first; conn != NULL; )
	{
	    c = conn;
	    conn = conn->link.tqe_next;
	    confread_free_conn(c);
	    free(c);
	}
	free(cfg);
}
#undef FREE_STR

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
