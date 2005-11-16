/*
 * RFC2367 PF_KEYv2 Key management API message parser
 * Copyright (C) 2003 Michael Richardson <mcr@freeswan.org>
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
 * RCSID $Id: pfkey_print.c,v 1.2 2004/04/26 05:03:40 ken Exp $
 */

char pfkey_v2_print_c_version[] = "$Id: pfkey_print.c,v 1.2 2004/04/26 05:03:40 ken Exp $";

#include <sys/types.h>

#include <openswan.h>
#include <pfkeyv2.h>
#include <pfkey.h>

void
pfkey_print(struct sadb_msg *msg, FILE *out)
{
    int len;
    struct sadb_ext *se;
    
    fprintf(out, "version=%d type=%d errno=%d satype=%d len=%d seq=%d pid=%d ",
	    msg->sadb_msg_version,
	    msg->sadb_msg_type,
	    msg->sadb_msg_errno,
	    msg->sadb_msg_satype,
	    msg->sadb_msg_len,
	    msg->sadb_msg_seq,
	    msg->sadb_msg_pid);
    
    len = IPSEC_PFKEYv2_LEN(msg->sadb_msg_len);
    len -= sizeof(struct sadb_msg);
    
    se = (struct sadb_ext *)(&msg[1]);
    while(len > sizeof(struct sadb_ext)) {
	fprintf(out, "{ext=%d len=%d ", se->sadb_ext_type, se->sadb_ext_len);
	
	/* make sure that there is enough left */
	if(IPSEC_PFKEYv2_LEN(se->sadb_ext_len) > len) {
	    fprintf(out, "short-packet(%d<%d) ", len,
		    (int)IPSEC_PFKEYv2_LEN(se->sadb_ext_len));
	    
	    /* force it to match */
	    se->sadb_ext_len = IPSEC_PFKEYv2_WORDS(len);
	    goto dumpbytes;
	}
	
	/* okay, decode what we know */
	switch(se->sadb_ext_type) {
	case SADB_EXT_SA:
	  {
	    struct sadb_sa *sa = (struct sadb_sa *)se;
	    fprintf(out, "spi=%08x replay=%d state=%d auth=%d encrypt=%d flags=%08x ref=%08x}",
		    sa->sadb_sa_spi,
		    sa->sadb_sa_replay,
		    sa->sadb_sa_state,
		    sa->sadb_sa_auth,
		    sa->sadb_sa_encrypt,
		    sa->sadb_sa_flags,
		    sa->sadb_x_sa_ref);
	  }
	  break;
	  
	case SADB_X_EXT_ADDRESS_SRC_FLOW: 
	case SADB_X_EXT_ADDRESS_DST_FLOW: 
	case SADB_X_EXT_ADDRESS_SRC_MASK: 
	case SADB_X_EXT_ADDRESS_DST_MASK:
	case SADB_EXT_ADDRESS_DST:        
	case SADB_EXT_ADDRESS_SRC:        
	  {
	    struct sadb_address *addr = (struct sadb_address *)se;
	    int    alen = IPSEC_PFKEYv2_LEN(addr->sadb_address_len)-sizeof(struct sadb_address);
	    unsigned char *bytes = (unsigned char *)&addr[1];

	    fprintf(out, "proto=%d prefixlen=%d addr=0x",
		    addr->sadb_address_proto,
		    addr->sadb_address_prefixlen);

	    while(alen > 0)
	      {
		fprintf(out, "%02x", *bytes);
		bytes++;
		alen--;
	      }
	    fprintf(out, " } ");
	  }
	  break;
	  
	case SADB_X_EXT_PROTOCOL:
	  {
	    struct sadb_protocol *sp = (struct sadb_protocol *)se;
	    fprintf(out, "proto=%d direction=%d flags=%d } ",
		    sp->sadb_protocol_proto,
		    sp->sadb_protocol_direction,
		    sp->sadb_protocol_flags);
	  }
	  break;

	case SADB_EXT_LIFETIME_CURRENT:   
	case SADB_EXT_LIFETIME_HARD:      
	case SADB_EXT_LIFETIME_SOFT:      
	  {
	    struct sadb_lifetime *life = (struct sadb_lifetime *)se;

	    fprintf(out, "allocations=%d bytes=%qd addtime=%qd usetime=%qd packets=%d",
		    life->sadb_lifetime_allocations,
		    (long long)life->sadb_lifetime_bytes,
		    (long long)life->sadb_lifetime_addtime,
		    (long long)life->sadb_lifetime_usetime,
		    life->sadb_x_lifetime_packets);
	    fprintf(out, " } ");
	  }
	  break;
	  
	  
	case SADB_EXT_RESERVED:
	case SADB_EXT_ADDRESS_PROXY:      
	case SADB_EXT_KEY_AUTH:           
	case SADB_EXT_KEY_ENCRYPT:        
	case SADB_EXT_IDENTITY_SRC:       
	case SADB_EXT_IDENTITY_DST:       
	case SADB_EXT_SENSITIVITY:        
	case SADB_EXT_PROPOSAL:           
	case SADB_EXT_SUPPORTED_AUTH:     
	case SADB_EXT_SUPPORTED_ENCRYPT:  
	case SADB_EXT_SPIRANGE:           
	case SADB_X_EXT_KMPRIVATE:
	case SADB_X_EXT_SATYPE2:
	case SADB_X_EXT_SA2:
	case SADB_X_EXT_ADDRESS_DST2:     
	case SADB_X_EXT_DEBUG:
	default:
	  {
	    unsigned int elen;
	    unsigned char *bytes;
	    
	  dumpbytes:
	    
	    elen = IPSEC_PFKEYv2_LEN(se->sadb_ext_len)-sizeof(struct sadb_ext);
	    bytes = (unsigned char *)&se[1];
	    
	    fprintf(out, "bytes=0x");
	    while(elen > 0)
	      {
		fprintf(out, "%02x", *bytes);
		bytes++;
		elen--;
	      }
	    fprintf(out, " } ");
	  }
	  break;
	}

	/* skip to next extension header */
	{
	  unsigned int elen = IPSEC_PFKEYv2_LEN(se->sadb_ext_len);

	  if(elen < sizeof(struct sadb_ext)) {
	    fprintf(out, "illegal-length(%d) ",elen);
	    elen = sizeof(struct sadb_ext);
	  }

	  se = (struct sadb_ext *)(((unsigned char *)se)+elen);
	  len -= elen;
	}
    }
    fprintf(out, "\n");
}


    
