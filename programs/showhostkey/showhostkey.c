/*
 * show the host keys in various formats
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
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
 * replaces a shell script.
 *
 * RCSID $Id: ranbits.c,v 1.12 2004/04/04 01:50:56 ken Exp $
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openswan.h>
#include <sys/utsname.h>

#include <arpa/nameser.h>

#include "constants.h"
#include "oswalloc.h"
#include "oswlog.h"
#include "oswconf.h"
#include "secrets.h"
#include "mpzfuncs.h"

char usage[] = "Usage: ipsec showhostkey [--ipseckey {gateway}][--left ] [--right ]\n"
             "                         [--dump ] [--list ] [--x509self]\n"
             "                         [--x509req ] [--x509cert ]      \n"
             "                         [ --txt gateway ] [--dhclient ] \n"
             "                         [ --file secretfile ] \n"
             "                         [ --keynum count ] [ --id identity ]\n"
             "                         [ --rsaid keyid ] [--verbose] [--version]\n";

struct option opts[] = {
  {"key",	no_argument,	NULL,	'k',},
  {"left",	no_argument,	NULL,	'l',},
  {"right",	no_argument,	NULL,	'r',},
  {"dump",	no_argument,	NULL,	'D',},
  {"list",	no_argument,	NULL,	'L',},
  {"x509self",	no_argument,	NULL,	's',},
  {"x509req",	no_argument,	NULL,	'R',},
  {"x509cert",	no_argument,	NULL,	'c',},
  {"txt",	required_argument,NULL,	't',},
  {"ipseckey",	required_argument,NULL,	'K',},
  {"dhclient",	no_argument,    NULL,	'd',},
  {"file",	required_argument,NULL,	'f',},
  {"keynum",	required_argument,NULL,	'n',},
  {"id",	required_argument,NULL,	'i',},
  {"rsaid",	required_argument,NULL,	'I',},
  {"version",	no_argument,	 NULL,	'V',},
  {"verbose",	no_argument,	 NULL,	'v',},
  {0,		0,	NULL,	0,}
};

char *progname = "ipsec showhostkey";	/* for messages */

void exit_tool(int code)
{
    tool_close_log();
    exit(code);
}

void
showhostkey_log(int mess_no, const char *message, ...)
{
    va_list args;

    va_start(args, message);
    vfprintf(stderr, message, args);
    va_end(args);
}


int list_key(struct secret *secret,
	     struct private_key_stuff *pks,
	     void *uservoid)
{
    int lineno = osw_get_secretlineno(secret);
    struct id_list *l = osw_get_idlist(secret);
    char idb[IDTOA_BUF];

    while(l) {
	idtoa(&l->id, idb, IDTOA_BUF);

	switch(pks->kind) {
	case PPK_PSK:
	    printf("%d: PSK keyid: %s\n", lineno, idb);
	    break;
	    
	case PPK_RSA:
	    printf("%d: RSA keyid: %s with id: %s\n", lineno, pks->u.RSA_private_key.pub.keyid,idb);
	    break;
	    
	case PPK_PIN:
	    printf("%d PIN key-type not yet supported for id: %s\n", lineno, idb);
	    break;
	}
	
	l=l->next;
    }
    
    return 1;
}


int pickbyid(struct secret *secret,
	     struct private_key_stuff *pks,
	     void *uservoid)
{
    char *rsakeyid = (char *)uservoid;

    if(strcmp(pks->u.RSA_private_key.pub.keyid, rsakeyid)==0) {
	return 0;
    }
    return 1;
}

struct secret *get_key_byid(struct secret *host_secrets, char *rsakeyid)
{
    return osw_foreach_secret(host_secrets, pickbyid, rsakeyid);
}

void list_keys(struct secret *host_secrets)
{
    (void)osw_foreach_secret(host_secrets, list_key, NULL);
}

char *get_default_keyid(struct secret *host_secrets)
{
    struct private_key_stuff *pks = osw_get_pks(host_secrets);

    return pks->u.RSA_private_key.pub.keyid;
}

     
void dump_keys(struct secret *host_secrets)
{
    
}

struct secret *pick_key(struct secret *host_secrets
			, char *idname)
{
    struct id id;
    struct secret *s;
    err_t e;

    e = atoid(idname, &id, FALSE);
    if(e) {
	printf("%s: key '%s' is invalid\n", progname, idname);
	exit(4);
    }

    s = osw_find_secret_by_id(host_secrets, PPK_RSA
			      , &id, NULL, TRUE /* asymmetric */);
    
    if(s==NULL) {
	char abuf[IDTOA_BUF];
	idtoa(&id, abuf, IDTOA_BUF);
	printf("%s: can not find key: %s (%s)\n", progname, idname, abuf);
	exit(5);
    }

    return s;
}

unsigned char *pubkey_to_rfc3110(const struct RSA_public_key *pub,
				 unsigned int *keybuflen)
{
    unsigned char *buf;
    unsigned char *p;
    unsigned int elen;

    chunk_t e, n;


    e = mpz_to_n2(&pub->e);
    n = mpz_to_n2(&pub->n);
    elen = e.len;

    buf = alloc_bytes(e.len+n.len+3, "buffer for rfc3110");
    p = buf;
    
    if (elen <= 255)
	*p++ = elen;
    else if ((elen &~ 0xffff) == 0) {
	*p++ = 0;
	*p++ = (elen>>8) & 0xff;
	*p++ = elen & 0xff;
    } else
	return 0;	/* unrepresentable exponent length */

    memcpy(p, e.ptr, e.len);
    p+=e.len;
    memcpy(p, n.ptr, n.len);
    p+=n.len;

    *keybuflen=(p-buf);

    return buf;
}    

void show_dnskey(struct secret *s
		 , char *idname
		 , int precedence
		 , char *gateway
		 , int rr_type)
{
    char qname[256];
    char base64[8192];
    const struct private_key_stuff *pks = osw_get_pks(s);
    unsigned char *keyblob;
    unsigned int keybloblen;

    gethostname(qname, sizeof(qname));

    if(pks->kind != PPK_RSA) {
	printf("%s: wrong kind of key\n", progname);
	exit(5);
    }

    keyblob = pubkey_to_rfc3110(&pks->u.RSA_private_key.pub, &keybloblen);

    datatot((char *)keyblob, keybloblen, 's', base64, sizeof(base64));

    switch(rr_type) {
    case ns_t_key:
	printf("key not yet implemented\n");
	break;

    case ns_t_ipseckey:
	printf("ipseckey not yet implemented\n");
	break;

    case ns_t_txt:
	printf("; info about key: %s\n", 
	       pks->u.RSA_private_key.pub.keyid);
	printf("%s.    IN    TXT    \"X-IPsec-Server(%d)=%s \" ",
	       qname, precedence, gateway);
	{
	    int len = strlen(base64);
	    char *p=base64+2;  /* skip 0s */
	    while(len > 0) {
		int printlen = len;
		char saveit;
		if(printlen > 240) {
		    printlen=240;
		}
		saveit=p[printlen];
		p[printlen]='\0';
		printf("\"%s\" ",p);
		p[printlen]=saveit;
		p+=printlen;
		len-=printlen;
	    }
	}
	printf("\n");
	break;
    }
}
     
void show_confkey(struct secret *s
		  , char *idname
		  , char *side)
{
    char base64[8192];
    const struct private_key_stuff *pks = osw_get_pks(s);
    unsigned char *keyblob;
    unsigned int keybloblen;

    if(pks->kind != PPK_RSA) {
	printf("%s: wrong kind of key\n", progname);
	exit(5);
    }

    keyblob = pubkey_to_rfc3110(&pks->u.RSA_private_key.pub, &keybloblen);

    datatot((char *)keyblob, keybloblen, 's', base64, sizeof(base64));

    printf("\t# rsakey %s\n", 
	   pks->u.RSA_private_key.pub.keyid);
    printf("\t%srsasigkey=%s\n", side,
	   base64);
}
     


int main(int argc, char *argv[])
{
    char secrets_file[PATH_MAX];
    int opt;
    int errflg = 0;
    bool key_flg=FALSE;
    bool left_flg=FALSE;
    bool right_flg=FALSE;
    bool dump_flg=FALSE;
    bool list_flg=FALSE;
    bool x509self_flg=FALSE;
    bool x509req_flg=FALSE;
    bool x509cert_flg=FALSE;
    bool txt_flg=FALSE;
    bool ipseckey_flg=FALSE;
    bool dhclient_flg=FALSE;
    char *gateway = NULL;
    int precedence=10;
    int verbose=0;
    const struct osw_conf_options *oco = osw_init_options();
    char *rsakeyid, *keyid;
    struct secret *host_secrets = NULL;
    struct secret *s;
    prompt_pass_t pass;

    rsakeyid=NULL;
    keyid=NULL;

    /* start up logging system */
    tool_init_log();

    snprintf(secrets_file, PATH_MAX, "%s/ipsec.secrets", oco->confdir);
    
    while ((opt = getopt_long(argc, argv, "", opts, NULL)) != EOF) {
	switch (opt) {
	case 'k':
	    key_flg=TRUE;
	    break;

	case 'l':
	    left_flg=TRUE;
	    break;
	case 'r':
	    right_flg=TRUE;
	    break;

	case 'D': /* --dump */
	    dump_flg=TRUE;
	    break;

	case 'K':
	    ipseckey_flg=TRUE;
	    gateway=clone_str(optarg, "gateway");
	    break;

	case 'L':
	    list_flg=TRUE;
	    break;

	case 's':
	case 'R':
	case 'c':
	    break;

	case 't':
	    txt_flg=TRUE;
	    gateway=clone_str(optarg, "gateway");
	    break;

	case 'd':
	    break;

	case 'f':  /* --file arg */
	    secrets_file[0]='\0';
	    strncat(secrets_file, optarg, PATH_MAX);
	    break;

	case 'i':
	    keyid=clone_str(optarg, "keyname");
	    break;

	case 'I':
	    rsakeyid=clone_str(optarg, "rsakeyid");
	    break;

	case 'n':
	case 'h':
	    break;

	case 'v':
	    verbose++;
	    break;

	case 'V':
	    fprintf(stdout, "%s\n", ipsec_version_string());
	    exit(0);

	default:
	    goto usage;
	}
    }

    if(errflg) {
    usage:
	fputs(usage, stderr);
	exit(1);
    }
    
    if(!key_flg && !left_flg && !right_flg && !dump_flg && !list_flg
       && !x509self_flg && !x509req_flg && !x509cert_flg && !txt_flg
       && !ipseckey_flg && !dhclient_flg) {
	fprintf(stderr, "You must specify some operation\n");
	goto usage;
    }
    
    if((key_flg + left_flg + right_flg + dump_flg + list_flg
	+ x509self_flg + x509req_flg + x509cert_flg + txt_flg
	+ ipseckey_flg + dhclient_flg) > 1) {
	fprintf(stderr, "You must specify only one operation\n");
	goto usage;
    }

    /* now load file from indicated location */
    pass.prompt=showhostkey_log;
    pass.fd = 2; /* stderr */
    osw_load_preshared_secrets(&host_secrets, verbose>0?TRUE:FALSE,
			       secrets_file, &pass);

    /* options that apply to entire files */
    if(dump_flg) {
	/* dumps private key info too */
	dump_keys(host_secrets);
	exit(0);
    }

    if(list_flg) {
	list_keys(host_secrets);
	exit(0);
    }

    if(rsakeyid) {
	printf("; picking by rsakeyid=%s\n", rsakeyid);
	s = get_key_byid(host_secrets, rsakeyid);
	keyid=rsakeyid;
    } else if(keyid) {
	printf("; picking by keyid=%s\n", keyid);
	s = pick_key(host_secrets, keyid);
    } else {
	/* default key is the *LAST* key, because it is first in the file.*/
	s=osw_get_defaultsecret(host_secrets);
	keyid="default";
    }

    if(s==NULL) {
	printf("No keys found\n");
	exit(20);
    }

    if(left_flg) {
	show_confkey(s, keyid, "left");
	exit(0);
    }

    if(right_flg) {
	show_confkey(s, keyid, "right");
	exit(0);
    }

    if(key_flg || ipseckey_flg || txt_flg) {
	int rr_type = ns_t_invalid;
	if(key_flg) {
	    rr_type = ns_t_key;
	} else if(ipseckey_flg) {
	    rr_type = ns_t_ipseckey;
	} else if(txt_flg) {
	    rr_type = ns_t_txt;
	}
	show_dnskey(s, keyid,
		    precedence, gateway,
		    rr_type);
    }

    exit(0);
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
