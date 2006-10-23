/*
 * Algorithm info parsing and creation functions
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 *
 * alg_info.c,v 1.1.2.1 2003/11/21 18:12:23 jjo Exp
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
 */
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <openswan.h>
#include <openswan/ipsec_policy.h>
#include <openswan/passert.h>
#include <openswan/pfkeyv2.h>

#include "constants.h"
#include "alg_info.h"
#include "oswlog.h"
#include "oswalloc.h"

/* abstract reference */
struct oakley_group_desc;

/* sadb/ESP aa attrib converters */
int
alg_info_esp_aa2sadb(int auth)
{
	int sadb_aalg=0;
	switch(auth) {
		case AUTH_ALGORITHM_HMAC_MD5:
		case AUTH_ALGORITHM_HMAC_SHA1:
			sadb_aalg=auth+1;
			break;
		case AUTH_ALGORITHM_HMAC_SHA2_256:
		case AUTH_ALGORITHM_HMAC_SHA2_384:
		case AUTH_ALGORITHM_HMAC_SHA2_512:
		case AUTH_ALGORITHM_HMAC_RIPEMD:
			sadb_aalg=auth;
			break;
		default:
			/* loose ... */
			sadb_aalg=auth;
	}
	return sadb_aalg;
}

int /* __attribute__ ((unused)) */
alg_info_esp_sadb2aa(int sadb_aalg)
{
	int auth=0;
	switch(sadb_aalg) {
		case SADB_AALG_MD5HMAC:
		case SADB_AALG_SHA1HMAC:
			auth=sadb_aalg-1;
			break;
			/* since they are the same ...  :)  */
		case AUTH_ALGORITHM_HMAC_SHA2_256:
		case AUTH_ALGORITHM_HMAC_SHA2_384:
		case AUTH_ALGORITHM_HMAC_SHA2_512:
		case AUTH_ALGORITHM_HMAC_RIPEMD:
			auth=sadb_aalg;
			break;
		default:
			/* loose ... */
			auth=sadb_aalg;
	}
	return auth;
}

/*
 * 	Search enum_name array with in prefixed uppercase
 */
int
alg_enum_search_prefix (enum_names *ed, const char *prefix, const char *str, int strlen)
{
	char buf[64];
	char *ptr;
	int ret;
	int len=sizeof(buf)-1;	/* reserve space for final \0 */

	for (ptr=buf; *prefix; *ptr++=*prefix++, len--);

	while (strlen--&&len--&&*str) *ptr++=toupper(*str++);
	*ptr=0;

	DBG(DBG_CRYPT, DBG_log("enum_search_prefix () "
				"calling enum_search(%p, \"%s\")", ed, buf));

	ret=enum_search(ed, buf);
	return ret;
}
/*
 * 	Search enum_name array with in prefixed and postfixed uppercase
 */
int
alg_enum_search_ppfix (enum_names *ed, const char *prefix
		   , const char *postfix, const char *str
		   , int strlen)
{
	char buf[64];
	char *ptr;
	int ret;
	int len=sizeof(buf)-1;	/* reserve space for final \0 */
	for (ptr=buf; *prefix; *ptr++=*prefix++, len--);
	while (strlen--&&len--&&*str) *ptr++=toupper(*str++);
	while (len--&&*postfix) *ptr++=*postfix++;
	*ptr=0;
	DBG(DBG_CRYPT, DBG_log("enum_search_ppfixi () "
				"calling enum_search(%p, \"%s\")", ed, buf));
	ret=enum_search(ed, buf);
	return ret;
}

/*
 * 	Search esp_transformid_names for a match, eg:
 * 		"3des" <=> "ESP_3DES"
 */
#define ESP_MAGIC_ID 0x00ffff01
static int
ealg_getbyname_esp(const char *const str, int len)
{
	int ret=-1;
	if (!str||!*str)
		goto out;
	/* leave special case for eg:  "id248" string */
	if (strcmp("id", str)==0)
		return ESP_MAGIC_ID;
	ret=alg_enum_search_prefix(&esp_transformid_names, "ESP_", str, len);
out:
	return ret;
}


/*
 * 	Search auth_alg_names for a match, eg:
 * 		"md5" <=> "AUTH_ALGORITHM_HMAC_MD5"
 */
static int
aalg_getbyname_esp(const char *const str, int len)
{
	int ret=-1;
	unsigned num;
	if (!str||!*str)
		goto out;
	ret=alg_enum_search_prefix(&auth_alg_names,"AUTH_ALGORITHM_HMAC_",str,len);
	if (ret>=0) goto out;
	ret=alg_enum_search_prefix(&auth_alg_names,"AUTH_ALGORITHM_",str,len);
	if (ret>=0) goto out;
	sscanf(str, "id%d%n", &ret, &num);
	if (ret >=0 && num!=strlen(str))
		ret=-1;
out:
	return ret;
}
static int
modp_getbyname_esp(const char *const str, int len)
{
	int ret=-1;
	if (!str||!*str)
		goto out;
	ret=alg_enum_search_prefix(&oakley_group_names,"OAKLEY_GROUP_",str,len);
	if (ret>=0) goto out;
	ret=alg_enum_search_ppfix(&oakley_group_names, "OAKLEY_GROUP_", " (extension)", str, len);
out:
	return ret;
}

void 
alg_info_free(struct alg_info *alg_info) {
	pfreeany(alg_info);
}

/*	
 *	Raw add routine: only checks for no duplicates		
 */
static void
__alg_info_esp_add (struct alg_info_esp *alg_info
		    , int ealg_id, unsigned ek_bits
		    , int aalg_id, unsigned ak_bits)
{
	struct esp_info *esp_info=alg_info->esp;
	unsigned cnt=alg_info->alg_info_cnt, i;
	/* 	check for overflows 	*/
	passert(cnt < elemsof(alg_info->esp));
	/*	dont add duplicates	*/
	for (i=0;i<cnt;i++)
		if (	esp_info[i].esp_ealg_id==ealg_id &&
			(!ek_bits || esp_info[i].esp_ealg_keylen==ek_bits) &&
			esp_info[i].esp_aalg_id==aalg_id &&
			(!ak_bits || esp_info[i].esp_aalg_keylen==ak_bits))
			return;
	esp_info[cnt].esp_ealg_id=ealg_id;
	esp_info[cnt].esp_ealg_keylen=ek_bits;
	esp_info[cnt].esp_aalg_id=aalg_id;
	esp_info[cnt].esp_aalg_keylen=ak_bits;
	/* sadb values */
	esp_info[cnt].encryptalg=ealg_id;
	esp_info[cnt].authalg=alg_info_esp_aa2sadb(aalg_id);
	alg_info->alg_info_cnt++;
	DBG(DBG_CRYPT, DBG_log("__alg_info_esp_add() "
				"ealg=%d aalg=%d cnt=%d",
				ealg_id, aalg_id, alg_info->alg_info_cnt));
}

/*	
 *	Add ESP alg info _with_ logic (policy):
 */
static void
alg_info_esp_add (struct alg_info *alg_info,
		  int ealg_id, int ek_bits,
		  int aalg_id, int ak_bits,
		  int modp_id, bool permit_manconn)
{
	/*	Policy: default to 3DES */
	if (ealg_id==0)
		ealg_id=ESP_3DES;
	
	if (ealg_id>0) {

	    if(aalg_id > 0 ||
	       (permit_manconn && aalg_id == 0))
		{
			__alg_info_esp_add((struct alg_info_esp *)alg_info,
					ealg_id, ek_bits,
					aalg_id, ak_bits);
		}
	    else
		{
			/*	Policy: default to MD5 and SHA1 */
			__alg_info_esp_add((struct alg_info_esp *)alg_info,
					ealg_id, ek_bits, \
					AUTH_ALGORITHM_HMAC_MD5, ak_bits);
			__alg_info_esp_add((struct alg_info_esp *)alg_info,
					ealg_id, ek_bits, \
					AUTH_ALGORITHM_HMAC_SHA1, ak_bits);
		}
	}
}

/*	
 *	Add AH alg info _with_ logic (policy):
 */
static void
alg_info_ah_add (struct alg_info *alg_info,
		  int ealg_id, int ek_bits,
		  int aalg_id, int ak_bits,
		  int modp_id, bool permit_manconn)
{
    if(aalg_id > 0 ||
       (permit_manconn && aalg_id == 0))
    {
	__alg_info_esp_add((struct alg_info_esp *)alg_info,
			   ealg_id, ek_bits,
			   aalg_id, ak_bits);
    }
    else
    {
	/*	Policy: default to MD5 and SHA1 */
	__alg_info_esp_add((struct alg_info_esp *)alg_info,
			   ealg_id, ek_bits,				\
			   AUTH_ALGORITHM_HMAC_MD5, ak_bits);
	__alg_info_esp_add((struct alg_info_esp *)alg_info,
			   ealg_id, ek_bits,				\
			   AUTH_ALGORITHM_HMAC_SHA1, ak_bits);
    }
}

static const char *parser_state_esp_names[] = {
	"ST_INI",
	"ST_INI_AA",
	"ST_EA",
	"ST_EA_END",	
	"ST_EK",
	"ST_EK_END",
	"ST_AA",
	"ST_AA_END",
	"ST_AK",
	"ST_AK_END",
	"ST_MOPD",
	"ST_FLAG_STRICT",
	"ST_END",
	"ST_EOF",
	"ST_ERR"
};

static const char *parser_state_name_esp(enum parser_state_esp state) {
	return parser_state_esp_names[state];
}

static inline void parser_set_state(struct parser_context *p_ctx, enum parser_state_esp state) {
	if (state!=p_ctx->state) {
		p_ctx->old_state=p_ctx->state;
		p_ctx->state=state;
	}
	
}

static int 
parser_machine(struct parser_context *p_ctx)
{
	int ch=p_ctx->ch;
	/* special 'absolute' cases */
	p_ctx->err="No error.";

	/* chars that end algo strings */
	switch(ch){
	case 0:		/* end-of-string */
	case '!':	/* flag as strict algo list */
	case ',':	/* algo string separator */
	    switch(p_ctx->state) {
	    case ST_EA:
	    case ST_EK:
	    case ST_AA:
	    case ST_AK: 
	    case ST_MODP:
	    case ST_FLAG_STRICT:
		{
		    enum parser_state_esp next_state=0;
		    switch(ch) {
		    case 0:   next_state=ST_EOF;break;
		    case ',': next_state=ST_END;break;
		    case '!': next_state=ST_FLAG_STRICT;break;
		    }
		    /* ch? parser_set_state(p_ctx, ST_END) : parser_set_state(p_ctx, ST_EOF) ; */
		    parser_set_state(p_ctx, next_state);
		    goto out;
		}
	    default:
		p_ctx->err="String ended with invalid char";
		goto err;
	    }
	}
 re_eval:
	switch(p_ctx->state) {
	case ST_INI:
	    if (isspace(ch))
		break;
	    if (isalnum(ch)) {
		*(p_ctx->ealg_str++)=ch;
		parser_set_state(p_ctx, ST_EA);
		break;
	    }
	    p_ctx->err="No alphanum. char initially found";
	    goto err;

	case ST_INI_AA:
	    if (isspace(ch))
		break;
	    if (isalnum(ch)) {
		*(p_ctx->aalg_str++)=ch;
		parser_set_state(p_ctx, ST_AA);
		break;
	    }
	    p_ctx->err="No alphanum. char initially found";
	    goto err;

	case ST_EA:
	    if (isalpha(ch) || ch == '_') {
		*(p_ctx->ealg_str++)=ch;
		break;
	    }
	    if (isdigit(ch)) {
		/* bravely switch to enc keylen */
		*(p_ctx->ealg_str)=0;
		parser_set_state(p_ctx, ST_EK);
		goto re_eval;
	    }
	    if (ch=='-') {
		*(p_ctx->ealg_str)=0;
		parser_set_state(p_ctx, ST_EA_END);
		break;
	    }
	    p_ctx->err="No valid char found after enc alg string";
	    goto err;
	case ST_EA_END:
	    if (isdigit(ch)) {
		/* bravely switch to enc keylen */
		parser_set_state(p_ctx, ST_EK);
		goto re_eval;
	    }
	    if (isalpha(ch)) {
		parser_set_state(p_ctx, ST_AA);
		goto re_eval;
	    }
	    p_ctx->err="No alphanum char found after enc alg separator";
	    goto err;
	case ST_EK:
	    if (ch=='-') {
		parser_set_state(p_ctx, ST_EK_END);
		break;
	    }
	    if (isdigit(ch)) {
		p_ctx->eklen=p_ctx->eklen*10+ch-'0';
		break;
	    }
	    p_ctx->err="Non digit or valid separator found while reading enc keylen";
	    goto err;
	case ST_EK_END:
	    if (isalpha(ch)) {
		parser_set_state(p_ctx, ST_AA);
		goto re_eval;
	    }
	    p_ctx->err="Non alpha char found after enc keylen end separator";
	    goto err;
	case ST_AA:
	    if (ch=='-') {
		*(p_ctx->aalg_str++)=0;
		parser_set_state(p_ctx, ST_AA_END);
		break;
	    }
	    if (isalnum(ch) || ch=='_') {
		*(p_ctx->aalg_str++)=ch;
		break;
	    }
	    p_ctx->err="Non alphanum or valid separator found in auth string";
	    goto err;
	case ST_AA_END:
	    if (isdigit(ch)) {
		parser_set_state(p_ctx, ST_AK);
		goto re_eval;
	    }
	    /* Only allow modpXXXX string if we have
	     * a modp_getbyname method
	     */
	    if ((p_ctx->modp_getbyname) && isalpha(ch)) {
		parser_set_state(p_ctx, ST_MODP);
		goto re_eval;
	    }
	    p_ctx->err="Non initial digit found for auth keylen";
	    goto err;
	case ST_AK:
	    if (ch=='-') {
		parser_set_state(p_ctx, ST_AK_END);
		break;
	    }
	    if (isdigit(ch)) {
		p_ctx->aklen=p_ctx->aklen*10+ch-'0';
		break;
	    }
	    p_ctx->err="Non digit found for auth keylen";
	    goto err;
	case ST_AK_END:
	    /* Only allow modpXXXX string if we have
	     * a modp_getbyname method
	     */
	    if ((p_ctx->modp_getbyname) && isalpha(ch)) {
		parser_set_state(p_ctx, ST_MODP);
		goto re_eval;
	    }
	    p_ctx->err="Non alpha char found after auth keylen";
	    goto err;
	case ST_MODP:
	    if (isalnum(ch)) {
		*(p_ctx->modp_str++)=ch;
		break;
	    }
	    p_ctx->err="Non alphanum char found after in modp string";
	    goto err;
	case ST_FLAG_STRICT:
	    if (ch == 0) {
		parser_set_state(p_ctx, ST_END);
	    }
	    p_ctx->err="Flags character(s) must be at end of whole string";
	    goto err;
	    
	    /* XXX */
	case ST_END:
	case ST_EOF:
	case ST_ERR:
	    break;
	    /* XXX */
	}
 out:
	return p_ctx->state;
 err:
	parser_set_state(p_ctx, ST_ERR);
	return ST_ERR;
}

/*	
 *	Must be called for each "new" char, with new
 *	character in ctx.ch
 */
static void
parser_init_esp(struct parser_context *p_ctx)
{
    memset(p_ctx, 0, sizeof (*p_ctx));

    p_ctx->protoid=PROTO_IPSEC_ESP;
    p_ctx->ealg_str=p_ctx->ealg_buf;
    p_ctx->aalg_str=p_ctx->aalg_buf;
    p_ctx->modp_str=p_ctx->modp_buf;
    p_ctx->ealg_permit = TRUE;
    p_ctx->aalg_permit = TRUE;
    p_ctx->state=ST_INI;
    
    p_ctx->ealg_getbyname=ealg_getbyname_esp;
    p_ctx->aalg_getbyname=aalg_getbyname_esp;

}

/*	
 *	Must be called for each "new" char, with new
 *	character in ctx.ch
 */
static void
parser_init_ah(struct parser_context *p_ctx)
{
    memset(p_ctx, 0, sizeof (*p_ctx));

    p_ctx->protoid=PROTO_IPSEC_AH;
    p_ctx->ealg_str=NULL;
    p_ctx->ealg_permit = FALSE;
    p_ctx->aalg_str=p_ctx->aalg_buf;
    p_ctx->aalg_permit = TRUE;
    p_ctx->modp_str=p_ctx->modp_buf;
    p_ctx->state=ST_INI_AA;
    
    p_ctx->ealg_getbyname=NULL;
    p_ctx->aalg_getbyname=aalg_getbyname_esp;

}

static int
parser_alg_info_add(struct parser_context *p_ctx
		    , struct alg_info *alg_info
		    , void (*alg_info_add)(struct alg_info *alg_info
					  , int ealg_id, int ek_bits
					  , int aalg_id, int ak_bits
					  , int modp_id
					  , bool permitmann)
		    , const struct oakley_group_desc *(*lookup_group)(u_int16_t group)
		    , bool permitike)
{
	int ealg_id, aalg_id;
	int modp_id = 0;
	const struct oakley_group_desc *gd;

	ealg_id=aalg_id=-1;
	if (p_ctx->ealg_permit && *p_ctx->ealg_buf) {
	    ealg_id=p_ctx->ealg_getbyname(p_ctx->ealg_buf, strlen(p_ctx->ealg_buf));
	    if (ealg_id==ESP_MAGIC_ID) {
		ealg_id=p_ctx->eklen;
		p_ctx->eklen=0;
	    }
	    if (ealg_id<0) {
		p_ctx->err="enc_alg not found";
		goto out;
	    }
	    DBG(DBG_CRYPT, DBG_log("parser_alg_info_add() "
				   "ealg_getbyname(\"%s\")=%d",
				   p_ctx->ealg_buf,
				   ealg_id));
	}
	if (p_ctx->aalg_permit && *p_ctx->aalg_buf) {
	    aalg_id=p_ctx->aalg_getbyname(p_ctx->aalg_buf, strlen(p_ctx->aalg_buf));
	    if (aalg_id<0) {
		p_ctx->err="hash_alg not found";
		goto out;
	    }
	    DBG(DBG_CRYPT, DBG_log("parser_alg_info_add() "
				   "aalg_getbyname(\"%s\")=%d",
				   p_ctx->aalg_buf,
				   aalg_id));
	}
	if (p_ctx->modp_getbyname && *p_ctx->modp_buf) {
	    modp_id=p_ctx->modp_getbyname(p_ctx->modp_buf, strlen(p_ctx->modp_buf));
	    if (modp_id<0) {
		p_ctx->err="modp group not found";
		goto out;
	    }

	    DBG(DBG_CRYPT, DBG_log("parser_alg_info_add() "
				   "modp_getbyname(\"%s\")=%d",
				   p_ctx->modp_buf,
				   modp_id));

	    if (modp_id && !(gd=lookup_group(modp_id))) {
		p_ctx->err="found modp group id, but not supported";
		goto out;
	    }
	}

	(*alg_info_add)(alg_info
			,ealg_id, p_ctx->eklen
			,aalg_id, p_ctx->aklen
			,modp_id, permitike);
	return 0;
 out:
	return -1;
}

int
alg_info_parse_str (struct alg_info *alg_info
		    , const char *alg_str
		    , const char **err_p
		    , void (*parser_init)(struct parser_context *p_ctx)
		    , void (*alg_info_add)(struct alg_info *alg_info
					  , int ealg_id, int ek_bits
					  , int aalg_id, int ak_bits
					  , int modp_id
					  , bool permitmann)
		    , const struct oakley_group_desc *(*lookup_group)(u_int16_t group)
		    , bool permitmann)
{
	struct parser_context ctx;
	int ret;
	const char *ptr;
	static char err_buf[256];
	*err_buf=0;

	(*parser_init)(&ctx);

	if (err_p) *err_p=NULL;

	/* use default if nul esp string */
	if (!*alg_str) {
	    (*alg_info_add)(alg_info, 0, 0, 0, 0, 0, 0);
	}

	for(ret=0,ptr=alg_str;ret<ST_EOF;) {
	    ctx.ch=*ptr++;
	    ret= parser_machine(&ctx);
	    switch(ret) {
	    case ST_FLAG_STRICT:
		alg_info->alg_info_flags |= ALG_INFO_F_STRICT;
		break;

	    case ST_END:
	    case ST_EOF:
		DBG(DBG_CRYPT, DBG_log("alg_info_parse_str() "
				       "ealg_buf=%s aalg_buf=%s"
				       "eklen=%d  aklen=%d",
				       ctx.ealg_buf, ctx.aalg_buf,
				       ctx.eklen, ctx.aklen));

		if (parser_alg_info_add(&ctx, alg_info
					, alg_info_add
					, lookup_group
					, permitmann)<0) {
		    snprintf(err_buf, sizeof(err_buf),
			     "%s, enc_alg=\"%s\", auth_alg=\"%s\", "
			     "modp=\"%s\"",
			     ctx.err,
			     ctx.ealg_buf,
			     ctx.aalg_buf,
			     ctx.modp_buf);
		    goto err;
		}
		/* zero out for next run (ST_END) */
		parser_init(&ctx);
		break;

	    case ST_ERR:
		snprintf(err_buf, sizeof(err_buf),
			 "%s, "
			 "just after \"%.*s\""
			 " (old_state=%s)",
			 ctx.err,
			 (int)(ptr-alg_str-1), alg_str ,
			 parser_state_name_esp(ctx.old_state) );
		
		goto err;
	    default:
		if (!ctx.ch) break;
	    }
	}
	return 0;
 err:
	if (err_p) {
	    *err_p=err_buf;
	}
	return -1;
}

static bool
alg_info_discover_pfsgroup_hack(struct alg_info_esp *aie
				, char *esp_buf
				, const char **err_p)
{
    char *pfs_name;
    static char err_buf[256];
    int ret;
    
    pfs_name=index(esp_buf, ';');
    
    if(pfs_name) {
	*pfs_name='\0';
	pfs_name++;

	/* if pfs strings AND first char is not '0' */
	if (*pfs_name && pfs_name[0]!='0') {
	    ret=modp_getbyname_esp(pfs_name, strlen(pfs_name));
	    if (ret<0) {
		/* Bomb if pfsgroup not found */
		DBG(DBG_CRYPT, DBG_log("alg_info_*_create_from_str(): "
				       "pfsgroup \"%s\" not found",
				       pfs_name));
		if (*err_p) {
		    snprintf(err_buf, sizeof(err_buf),
			     "pfsgroup \"%s\" not found",
			     pfs_name);
		    *err_p=err_buf;
		}
		return FALSE;
	    }
	    aie->esp_pfsgroup=ret;
	}
    } else
	aie->esp_pfsgroup = 0;

    return TRUE;
}


struct alg_info_esp *
alg_info_esp_create_from_str (const char *alg_str
			      , const char **err_p
			      , bool permitmann)
{
    struct alg_info_esp *alg_info_esp;
    char esp_buf[256];
    int ret =0;

    /*
     * 	alg_info storage should be sized dynamically
     * 	but this may require 2passes to know
     * 	transform count in advance.
     */
    alg_info_esp=alloc_thing (struct alg_info_esp, "alg_info_esp");

    if (!alg_info_esp) goto out;

    strcpy(esp_buf, alg_str);
    if(!alg_info_discover_pfsgroup_hack(alg_info_esp, esp_buf, err_p)) {
	return NULL;
    }

    alg_info_esp->alg_info_protoid=PROTO_IPSEC_ESP;
    ret=alg_info_parse_str((struct alg_info *)alg_info_esp
			   , esp_buf, err_p
			   , parser_init_esp
			   , alg_info_esp_add
			   , NULL
			   , permitmann);

 out:
    if (ret<0)
	{
	    pfreeany(alg_info_esp);
	    alg_info_esp=NULL;
	}
    return alg_info_esp;
    
}

struct alg_info_esp *
alg_info_ah_create_from_str (const char *alg_str
			     , const char **err_p
			     , bool permitmann)
{
    struct alg_info_esp *alg_info_esp;
    char esp_buf[256];
    int ret =0;

    /*
     * 	alg_info storage should be sized dynamically
     * 	but this may require 2passes to know
     * 	transform count in advance.
     */
    alg_info_esp=alloc_thing (struct alg_info_esp, "alg_info_esp");

    strcpy(esp_buf, alg_str);
    if(!alg_info_discover_pfsgroup_hack(alg_info_esp, esp_buf, err_p)) {
	return NULL;
    }

    alg_info_esp->alg_info_protoid=PROTO_IPSEC_AH;
    ret=alg_info_parse_str((struct alg_info *)alg_info_esp
			   , esp_buf, err_p
			   , parser_init_ah
			   , alg_info_ah_add
			   , NULL
			   , permitmann);

    if (ret<0)
	{
	    pfreeany(alg_info_esp);
	    alg_info_esp=NULL;
	}
    return alg_info_esp;
}

/*
 * 	alg_info struct can be shared by
 * 	several connections instances,
 * 	handle free() with ref_cnts
 */
void 
alg_info_addref(struct alg_info *alg_info)
{
    if (alg_info != NULL) {
	alg_info->ref_cnt++;
	DBG(DBG_CONTROL, DBG_log("alg_info_addref() "
			       "alg_info->ref_cnt=%d", alg_info->ref_cnt));
    }
}
void
alg_info_delref(struct alg_info **alg_info_p)
{
    struct alg_info *alg_info=*alg_info_p;

#if 0
    DBG(DBG_CONTROL, DBG_log("alg_info_delref(%p) "
			   , alg_info));
#endif

    if (alg_info != NULL) {
	DBG(DBG_CONTROL, DBG_log("alg_info_delref(%p) "
			       "alg_info->ref_cnt=%d"
			       , alg_info, alg_info->ref_cnt));
	passert(alg_info->ref_cnt != 0);
	alg_info->ref_cnt--;
	if (alg_info->ref_cnt==0) {
	    DBG(DBG_CONTROL, DBG_log("alg_info_delref(%p) "
				   "freeing alg_info", alg_info));
	    alg_info_free(alg_info);
	}
	*alg_info_p=NULL;
    }
}

/*	snprint already parsed transform list (alg_info)	*/
int
alg_info_snprint(char *buf, int buflen
		 , struct alg_info *alg_info
		 , bool permitike)
{
    char *ptr=buf;
    int np=0;
    struct esp_info *esp_info;
    struct ike_info *ike_info;

    int cnt;
    ptr=buf;
    switch(alg_info->alg_info_protoid) {
    case PROTO_IPSEC_ESP: 
	{
	    struct alg_info_esp *alg_info_esp=(struct alg_info_esp *)alg_info;
	    ALG_INFO_ESP_FOREACH(alg_info_esp, esp_info, cnt) {
		np=snprintf(ptr, buflen, "%s(%d), "
			    , enum_name(&auth_alg_names, esp_info->esp_aalg_id)+sizeof("AUTH_ALGORITHM_HMAC")
			    , esp_info->esp_aalg_id);
		ptr+=np;
		buflen-=np;
		if(buflen<0) goto out;
	    }
	    if (alg_info_esp->esp_pfsgroup) {
		np=snprintf(ptr, buflen, "; pfsgroup=%d; "
			    , alg_info_esp->esp_pfsgroup);
		ptr+=np;
		buflen-=np;
		if(buflen<0) goto out;
	    }
	    break;
	}

    case PROTO_IPSEC_AH: 
	{
	    struct alg_info_esp *alg_info_esp=(struct alg_info_esp *)alg_info;
	    ALG_INFO_ESP_FOREACH(alg_info_esp, esp_info, cnt) {
		np=snprintf(ptr, buflen, "%s(%d), "
			    , enum_name(&auth_alg_names, esp_info->esp_aalg_id)+sizeof("AUTH_ALGORITHM_HMAC")
			    , esp_info->esp_aalg_id);
		ptr+=np;
		buflen-=np;
		if(buflen<0) goto out;
	    }
	    if (alg_info_esp->esp_pfsgroup) {
		np=snprintf(ptr, buflen, "; pfsgroup=%d; "
			    , alg_info_esp->esp_pfsgroup);
		ptr+=np;
		buflen-=np;
		if(buflen<0) goto out;
	    }
	    break;
	}

    case PROTO_ISAKMP:
	if(permitike) {
	    ALG_INFO_IKE_FOREACH((struct alg_info_ike *)alg_info, ike_info, cnt) {
		np=snprintf(ptr, buflen, "%s(%d)_%03d-%s(%d)-%d, "
			    , enum_name(&oakley_enc_names, ike_info->ike_ealg)+sizeof("OAKLEY")
			    , ike_info->ike_ealg, (int)ike_info->ike_eklen
			    , enum_name(&auth_alg_names, ike_info->ike_halg)+sizeof("AUTH_ALGORITHM_HMAC")
			    , ike_info->ike_halg
			    , ike_info->ike_modp);
		ptr+=np;
		buflen-=np;
		if(buflen<0) goto out;
	    }
	    break;
	}
	/* FALLTHROUGH */

    default:
	np=snprintf(buf, buflen, "INVALID protoid=%d\n",
		    alg_info->alg_info_protoid);
	ptr+=np;
	buflen-=np;
	goto out;
    }
    np=snprintf(ptr, buflen, "flags=%s",
		alg_info->alg_info_flags&ALG_INFO_F_STRICT?
		"strict":"-strict");
    ptr+=np;
    buflen-=np;

 out:
    passert(buflen >= 0);
    
    return ptr-buf;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
