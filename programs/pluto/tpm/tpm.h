/*
 * TCL Pluto Mix
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
 * RCSID $Id: tpm.h,v 1.11 2005/10/12 15:26:13 mcr Exp $
 */

#include "constants.h"

extern void init_tpm(void);
extern void free_tpm(void);

struct state;
struct connection;
struct msg_digest;

extern stf_status tpm_call_out(const char *name
			       , struct state *st
			       , struct connection *conn
			       , struct msg_digest *md);

struct packet_byte_stream;
extern stf_status tpm_call_out_crypt(const char *name
				     , struct state *st
				     , struct packet_byte_stream *pbs
				     , int offset, int length);

extern void *tpm_relocateHash(struct packet_byte_stream *pbs);
extern void tpm_findID(struct packet_byte_stream *pbs, struct packet_byte_stream *idpbs);


struct isakmp_hdr;
extern stf_status tpm_call_out_notify(const char *name
				      , struct state *st
				      , struct packet_byte_stream *pbs
				      , struct isakmp_hdr *hdr);
				      
extern int tpm_enabled;

#ifdef TPM
#define TCLCALLOUT(name,st,conn,md) do if(tpm_enabled) { \
    stf_status ret; \
    ret = tpm_call_out(name,st,conn,md); \
    switch(ret) { \
    case STF_IGNORE: \
      goto tpm_ignore;\
    case STF_STOLEN:  \
      goto tpm_stolen;\
    default: \
      /* nothing */\
      break;\
    } \
    \
  } while(0)

#define TCLCALLOUT_notify(name,st,pbs,hdr) do if(tpm_enabled) { \
    stf_status ret; \
    ret = tpm_call_out_notify(name,st,pbs,hdr);	\
    switch(ret) { \
    case STF_IGNORE: \
      goto tpm_ignore;\
    case STF_STOLEN:  \
      goto tpm_stolen;\
    default: \
      /* nothing */\
      break;\
    } \
    \
  } while(0)
#define TCLCALLOUT_crypt(name,st,pbs,off,len) do if(tpm_enabled) { tpm_call_out_crypt(name,st,pbs,off,len); } while(0)
#else
#define TCLCALLOUT(name,st,conn,md) /* nothing */
#define TCLCALLOUT_crypt(name,st,pbs,off,len) /* nothing */
#define TCLCALLOUT_notify(name,st,pbs,hdr) /* nothing */
#endif

extern void tpm_eval(const char *string);





