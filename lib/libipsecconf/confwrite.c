/*
 * Openswan config file writer (confwrite.c)
 * Copyright (C) 2004-2006 Michael Richardson <mcr@xelerance.com>
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
 * RCSID $Id: confwrite.c,v 1.5 2004/12/07 00:28:18 ken Exp $
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <sys/queue.h>

#include "ipsecconf/parser.h"
#include "ipsecconf/confread.h"
#include "ipsecconf/confwrite.h"
#include "ipsecconf/keywords.h"

void confwrite_list(FILE *out, char *prefix, int val, struct keyword_def *k)
{
    struct keyword_enum_values *kevs = k->validenum;
    struct keyword_enum_value  *kev  = kevs->values;
    int i=0;
    unsigned int mask=1;
    char *sep="";

    while(i <kevs->valuesize) {
	mask = kev[i].value;
	if(mask != 0 && (val & mask) == mask) {
	    fprintf(out, "%s%s%s", sep, prefix, kev[i].name);
	    sep=" ";
	}
	i++;
    }
}

void confwrite_int(FILE *out,
		   char   *side,
		   unsigned int context,
		   unsigned int keying_context,
		   knf     options,
		   int_set options_set,
		   ksf     strings)
{
    struct keyword_def *k;

    for(k=ipsec_conf_keywords_v2; k->keyname!=NULL; k++) {
	
	if((k->validity & KV_CONTEXT_MASK) != context) continue;
	if(keying_context != 0 && (k->validity & keying_context)==0) continue;

	/* do not output aliases */
	if(k->validity & kv_alias) continue;
	
	/* do not output policy settings handled elsewhere */
	if(k->validity & kv_policy) continue;
	if(k->validity & kv_processed) continue;

	/* do not output aliases */
	if(k->validity & kv_alias) continue;
	
	/* do not output policy settings handled elsewhere */
	if(k->validity & kv_policy) continue;
	if(k->validity & kv_processed) continue;

#if 0
	printf("#side: %s  %s validity: %08x & %08x=%08x vs %08x\n", side,
	       k->keyname, k->validity, KV_CONTEXT_MASK, k->validity&KV_CONTEXT_MASK, context);
#endif
	
	switch(k->type) {
	case kt_string:
	case kt_appendstring:
	case kt_appendlist:
	case kt_filename:
	case kt_dirname:
	case kt_rsakey:

	case kt_percent:
	case kt_ipaddr:
	case kt_subnet:
	case kt_idtype:
	case kt_bitstring:
	    /* none of these are valid number types */
	    continue;

	case kt_time:
	    /* special number, but do work later XXX */
	    break;

	case kt_bool:
	case kt_invertbool:
	    /* special enumeration */
	    if(options_set[k->field]) {
		int val = options[k->field];
		if(k->type == kt_invertbool) {
		    val = !val;
		}

		fprintf(out, "\t%s%s=%s\n",side,
			k->keyname, val ? "yes" : "no");
	    }
	    continue;

	case kt_enum:
	case kt_loose_enum:
	    /* special enumeration */
	    if(options_set[k->field]) {
		int val = options[k->field];
		fprintf(out, "\t%s%s=",side, k->keyname);
		
		if(k->type == kt_loose_enum && val == LOOSE_ENUM_OTHER) {
		    fprintf(out, "%s\n", strings[k->field]);
		} else {
		    struct keyword_enum_values *kevs = k->validenum;
		    struct keyword_enum_value  *kev  = kevs->values;
		    int i=0;

		    while(i <kevs->valuesize) {
			if(kev[i].value == val) {
			    fprintf(out, "%s", kev[i].name);
			    break;
			}
			i++;
		    }
		    fprintf(out, "\n");
		}
	    }
	    continue;
	
	case kt_list:
	    /* special enumeration */
	    if(options_set[k->field]) {
		int val = options[k->field];

		if(val == 0) continue;

		fprintf(out, "\t%s%s=\"",side, k->keyname);
		confwrite_list(out, "", val, k);

		fprintf(out, "\"\n");
	    }
	    continue;

	case kt_number:
	    break;

	case kt_comment:
	    continue;
	}

	if(options_set[k->field]) {
	    fprintf(out, "\t%s%s=%d\n",side, k->keyname, options[k->field]);
	}
    }	
}    
		   
void confwrite_str(FILE *out,
		   char   *side,
		   int     context,
		   int     keying_context,
		   ksf     strings,
		   str_set strings_set)
{
    struct keyword_def *k;

    for(k=ipsec_conf_keywords_v2; k->keyname!=NULL; k++) {

	if((k->validity & KV_CONTEXT_MASK)!=context) continue;
	if(keying_context != 0 && (k->validity & keying_context)==0) continue;

	/* do not output aliases */
	if(k->validity & kv_alias) continue;
	
	/* do not output policy settings handled elsewhere */
	if(k->validity & kv_policy) continue;
	if(k->validity & kv_processed) continue;
	
	switch(k->type) {
	case kt_appendlist:
	    if(strings_set[k->field]) {
		fprintf(out, "\t%s%s={%s}\n",side, k->keyname, strings[k->field]);
	    }
	    continue;	    

	case kt_string:
	case kt_appendstring:
	case kt_filename:
	case kt_dirname:
	    /* these are strings */
	    break; 

	case kt_rsakey:
	case kt_ipaddr:
	case kt_subnet:
	case kt_idtype:
	case kt_bitstring:
	    continue;

	case kt_bool:
	case kt_invertbool:
	case kt_enum:
	case kt_list:
	case kt_loose_enum:
	    /* special enumeration */
	    continue;

	case kt_time:
	    /* special number, not a string */
	    continue;

	case kt_percent:
	case kt_number:
	    continue;

	case kt_comment:
	    continue;
	}

	if(strings_set[k->field]) {
	    char *quote="";

	    if(strchr(strings[k->field],' ')) quote="\"";
	    
	    fprintf(out, "\t%s%s=%s%s%s\n",side, k->keyname
		    , quote
		    , strings[k->field]
		    , quote);
	}
    }	
}    
		   
		   
void confwrite_side(FILE *out,
		    struct starter_conn *conn,
		    struct starter_end *end,
		    char   *side)
{
    char databuf[2048];  /* good for a 12288 bit rsa key */
    int  keyingtype;

    if(conn->manualkey) {
	keyingtype=kv_manual;
    } else {
	keyingtype=kv_auto;
    }

    switch(end->addrtype) {
    case KH_NOTSET:
	/* nothing! */
	break;
	
    case KH_DEFAULTROUTE:
	fprintf(out, "\t%s=%%defaultroute\n",side);
	break;
	
    case KH_ANY:
	fprintf(out, "\t%s=%%any\n",side);
	break;
	
    case KH_IFACE:
	fprintf(out, "\t%s=%%iface\n",side);   /* MCR: what does this do? XXX */
	break;
	
    case KH_OPPO:
	fprintf(out, "\t%s=%%opportunistic\n",side);   
	break;
	
    case KH_OPPOGROUP:
	fprintf(out, "\t%s=%%opportunisticgroup\n",side);   
	break;
	
    case KH_GROUP:
	fprintf(out, "\t%s=%%group\n",side);   
	break;

    case KH_IPHOSTNAME:
	if(end->strings_set[KSCF_IP]) {
	    fprintf(out, "\t%s=%s\n",side, end->strings[KSCF_IP]);
	}
	break;

    case KH_IPADDR:
	addrtot(&end->addr, 0, databuf, ADDRTOT_BUF);
	fprintf(out, "\t%s=%s\n", side, databuf);
	break;
    }

    if(end->strings_set[KSCF_ID] && end->id) {
	fprintf(out, "\t%sid=\"%s\"\n",     side, end->id);
    }

    switch(end->nexttype) {
    case KH_NOTSET:
	/* nothing! */
	break;
	
    case KH_DEFAULTROUTE:
	fprintf(out, "\t%snexthop=%%defaultroute\n",side);
	break;
	
    case KH_IPADDR:
	addrtot(&end->nexthop, 0, databuf, ADDRTOT_BUF);
	fprintf(out, "\t%snexthop=%s\n", side, databuf);
	break;

    default:
	break;
    }

    if(end->has_client) {
	if(isvalidsubnet(&end->subnet)
	   && (!subnetishost(&end->subnet)
	       || !addrinsubnet(&end->addr, &end->subnet)))
	{
	    subnettot(&end->subnet, 0, databuf, SUBNETTOT_BUF);
	    fprintf(out, "\t%ssubnet=%s\n", side, databuf);
	}
    }

    if(end->rsakey1) {
	fprintf(out, "\t%srsakey=%s\n", side, end->rsakey1);
    }

    if(end->rsakey2) {
	fprintf(out, "\t%srsakey2=%s\n", side, end->rsakey2);
    }

    if(end->port || end->protocol) {
	char b2[32];
	
	strcpy(b2, "%any");
	strcpy(databuf, "%any");

	if(end->port) {
	    sprintf(b2, "%u", end->port);
	}
	if(end->protocol) {
	    sprintf(databuf, "%u", end->protocol);
	}
	    
	fprintf(out, "\t%sprotoport=%s/%s\n", side,
		databuf, b2);
    }

    if(end->cert) {
	fprintf(out, "\t%scert=%s\n", side, end->cert);
    }

    if(!isanyaddr(&end->sourceip)) {
	addrtot(&end->sourceip, 0, databuf, ADDRTOT_BUF);
	fprintf(out, "\t%ssourceip=%s\n", side, databuf);
    }

    confwrite_int(out, side,
		  kv_conn|kv_leftright,
		  keyingtype,
		  end->options, end->options_set, end->strings);
    confwrite_str(out, side, kv_conn|kv_leftright,
		  keyingtype,
		  end->strings, end->strings_set);

}

void confwrite_comments(FILE *out, struct starter_conn *conn)
{
    struct starter_comments *sc, *scnext;

    for(sc = conn->comments.tqh_first;
	sc != NULL;
	sc = scnext) {
	scnext = sc->link.tqe_next;
	
	fprintf(out, "\t%s=%s\n",
		sc->x_comment, sc->commentvalue);
    }
}

void confwrite_conn(FILE *out,
		    struct starter_conn *conn)
{
    int  keyingtype;

    if(conn->manualkey) {
	keyingtype=kv_manual;
    } else {
	keyingtype=kv_auto;
    }

    fprintf(out,"# begin conn %s\n",conn->name);
    
    fprintf(out, "conn %s\n", conn->name);
    
    if(conn->alsos) 
    { /* handle also= as a comment */
	
	int alsoplace=0;
	fprintf(out, "\t#also = ");
	while(conn->alsos[alsoplace] != NULL)
	{
	    fprintf(out, "%s ", conn->alsos[alsoplace]);
	    alsoplace++;
	}
	fprintf(out, "\n");
    }
    confwrite_side(out, conn, &conn->left,  "left");
    confwrite_side(out, conn, &conn->right, "right");
    confwrite_int(out, "", kv_conn,
		  keyingtype,
		  conn->options, conn->options_set, conn->strings);
    confwrite_str(out, "", kv_conn,
		  keyingtype,
		  conn->strings, conn->strings_set);
    confwrite_comments(out, conn);

    if(conn->connalias) {
	fprintf(out, "\tconnalias=\"%s\"\n", conn->connalias);
    }

    if(conn->manualkey) {
	fprintf(out, "\tmanual=add\n");
    } else {
	switch(conn->desired_state) {
	case STARTUP_NO:
	    fprintf(out, "\tauto=ignore\n");
	    break;

	case STARTUP_POLICY:
	    fprintf(out, "\tauto=policy\n");
	    break;
	    
	case STARTUP_ADD:
	    fprintf(out, "\tauto=add\n");
	    break;
	    
	case STARTUP_ROUTE:
	    fprintf(out, "\tauto=route\n");
	    break;
	    
	case STARTUP_START:
	    fprintf(out, "\tauto=start\n");
	    break;
	}
    }

    if(conn->policy) {
	int auth_policy, phase2_policy, shunt_policy, failure_policy;

	phase2_policy = (conn->policy & (POLICY_AUTHENTICATE|POLICY_ENCRYPT));
	failure_policy = (conn->policy & POLICY_FAIL_MASK);
	shunt_policy=(conn->policy & POLICY_SHUNT_MASK);

	switch(shunt_policy) {
	case POLICY_SHUNT_TRAP:
	    if(conn->policy & POLICY_TUNNEL) {
		fprintf(out, "\ttype=tunnel\n");
	    } else {
		fprintf(out, "\ttype=transport\n");
	    }
	    
	    if(conn->policy & POLICY_COMPRESS) {
		fprintf(out, "\tcompress=yes\n");
	    } else {
		fprintf(out, "\tcompress=no\n");
	    }
	    
	    if(conn->policy & POLICY_PFS) {
		fprintf(out, "\tpfs=yes\n");
	    } else {
		fprintf(out, "\tpfs=no\n");
	    }
	    
	    if(conn->policy & POLICY_DONT_REKEY) {
		fprintf(out, "\trekey=no  #duplicate?\n");
	    } else {
		fprintf(out, "\trekey=yes\n");
	    }

	    if(conn->policy & POLICY_OVERLAPIP) {
		fprintf(out, "\toverlapip=yes\n");
	    } else {
		fprintf(out, "\toverlapip=no\n");
	    }
	    
	    auth_policy=(conn->policy & POLICY_ID_AUTH_MASK);
	    switch(auth_policy) {
	    case POLICY_PSK:
		fprintf(out, "\tauthby=secret\n");
		break;
		
	    case POLICY_RSASIG:
		fprintf(out, "\tauthby=rsasig\n");
		break;
		
	    default:
		fprintf(out, "\tauthby=never\n");
		break;
	    }
	    
	    switch(phase2_policy) {
	    case POLICY_AUTHENTICATE:
		fprintf(out, "\tphase2=ah\n");
		break;
		
	    case POLICY_ENCRYPT:
		fprintf(out, "\tphase2=esp\n");
		break;
		
	    case (POLICY_ENCRYPT|POLICY_AUTHENTICATE):
		fprintf(out, "\tphase2=ah+esp\n");
		break;
		
	    default:
		break;
	    }

	    switch(failure_policy) {
	    case POLICY_FAIL_NONE:
		break;
		
	    case POLICY_FAIL_PASS:
		fprintf(out, "\tfailureshunt=passthrough\n");
		break;
		
	    case POLICY_FAIL_DROP:
		fprintf(out, "\tfailureshunt=drop\n");
		break;
		
	    case POLICY_FAIL_REJECT:
		fprintf(out, "\tfailureshunt=reject\n");
		break;
	    }
	    break;

	case POLICY_SHUNT_PASS:
	    fprintf(out, "\ttype=passthrough\n");
	    break;
	    
	case POLICY_SHUNT_DROP:
	    fprintf(out, "\ttype=drop\n");
	    break;
	    
	case POLICY_SHUNT_REJECT:
	    fprintf(out, "\ttype=reject\n");
	    break;

	}
	
    }

    
    fprintf(out,"# end conn %s\n\n",conn->name);
}

void confwrite(struct starter_config *cfg, FILE *out)
{
	struct starter_conn *conn;
/*	int i;
*/
	/* output version number */
	fprintf(out, "\nversion 2.0\n\n");

	/* output config setup section */
	fprintf(out, "config setup\n");
	confwrite_int(out, "", 
		      kv_config, 0,
		      cfg->setup.options, cfg->setup.options_set, cfg->setup.strings);
	confwrite_str(out, "", 
		      kv_config, 0,
		      cfg->setup.strings, cfg->setup.strings_set);

	fprintf(out, "\n\n");

	/* output connections */
	for(conn = cfg->conns.tqh_first; conn != NULL; conn = conn->link.tqe_next)
	{
	    confwrite_conn(out, conn);
	}
	fprintf(out,"# end of config\n");
}

/*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset:4
 * End:
 */
