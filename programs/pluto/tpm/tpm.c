/* TCL Pluto Mix (TPM)
 * Copyright (C) 2005 Michael C. Richardson <mcr@xelerance.com.
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
 * RCSID $Id: tpm.c,v 1.10 2005/10/06 19:40:19 mcr Exp $
 */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>

#include <openswan.h>
#include <errno.h>

#include <tcl.h>
#include "constants.h"
#include "packet.h"
#include "oswlog.h"
#include "oswalloc.h"
#include "tpm.h"
#include "tpm_int.h"
#include "paths.h"

Tcl_Interp *PlutoInterp;

int tpm_enabled=FALSE;

void init_tpm(void)
{
    char initfile[PATH_MAX];
    int  val;

    PlutoInterp = Tcl_CreateInterp();
    State_SafeInit(PlutoInterp);
  
    tpm_initCallbacks(PlutoInterp);

    snprintf(initfile, sizeof(initfile), "%s/tpm.tcl", ipsec_dir);
    if(access(initfile, R_OK)!=0) {
	if(errno == ENOENT) {
	    openswan_log("No file '%s' found, TPM disabled\n", initfile);
	} else {
	    openswan_log("TPM disabled: cannot open TPM file '%s':%s\n"
			 , initfile
			 , strerror(errno));
	}
	return;
    }

    openswan_log("Loading TPM file: '%s'\n", initfile);
    val = Tcl_EvalFile(PlutoInterp, initfile);
    switch(val) {
    case TCL_OK:
	openswan_log("TPM enabled\n");
	tpm_enabled = TRUE;
	return;
	
    case TCL_ERROR:
    case TCL_RETURN:
    case TCL_BREAK:
    case TCL_CONTINUE:
	openswan_log("TPM load error: %s\n", Tcl_GetObjResult(PlutoInterp));
	break;
    }
    return;
}

void free_tpm(void)
{
    if(PlutoInterp) {
	Tcl_DeleteInterp(PlutoInterp);
    }
    PlutoInterp=NULL;
}

void tpm_eval(const char *string)
{
    int val;

    if(PlutoInterp == NULL) {
	openswan_log("TPM not yet initialized, can not evaluate '%s'\n", string);
	return;
    }

    openswan_log("TPM evaluating '%s'\n", string);
    val = Tcl_Eval(PlutoInterp, string);
    
    switch(val) {
    case TCL_OK:
	if(!tpm_enabled) {
	    /* likely reason is that they user called "source" to load
	     * some new code.
	     */
	    openswan_log("TPM enabled\n");
	    tpm_enabled = TRUE;
	}
	return;
	
    case TCL_ERROR:
    case TCL_RETURN:
    case TCL_BREAK:
    case TCL_CONTINUE:
	openswan_log("TPM eval error: %s\n", Tcl_GetObjResult(PlutoInterp));
	break;
    }
}

stf_status tpm_call_it(Tcl_Obj **objv, int objc)
{
    int   ret;
    const char *res;

    passert(objc>=4);

    DBG(DBG_CONTROLMORE, DBG_log("TPM call %s %s %s %s"
			     , Tcl_GetString(objv[0])
			     , Tcl_GetString(objv[1])
			     , Tcl_GetString(objv[2])
			     , Tcl_GetString(objv[3])));
		 
    ret = Tcl_EvalObjv(PlutoInterp, objc, objv, TCL_EVAL_GLOBAL);

    res = Tcl_GetStringResult(PlutoInterp);
    
    DBG(DBG_CONTROL, DBG_log("TPM %s(%s,%s,%s) => %s"
			     , Tcl_GetString(objv[0])
			     , Tcl_GetString(objv[1])
			     , Tcl_GetString(objv[2])
			     , Tcl_GetString(objv[3])
			     , res));
		 
    if(strcmp(res, "ignore")==0 || strcmp(res, "nothing")==0 || res[0]=='\0') {
	/* just quietly return */
	return STF_OK;
    }

    openswan_log("TPM result: %s",res);
    if(ret != TCL_OK) {
	openswan_log("TPM result failed");
    }

    if(strcmp(res, "stf_stolen")==0) {
	return STF_STOLEN;
    }

    if(strcmp(res, "stf_ignore")==0) {
	return STF_IGNORE;
    }

    return STF_OK;
}

stf_status tpm_call_out(const char *name
			, struct state *st
			, struct connection *conn
			, struct msg_digest *md)
{
    Tcl_Obj  **objv;
    int   objc=0, ret;
    char *res;
    Tcl_Obj *to;

    passert(name != NULL);

    objv = alloc_bytes(sizeof(Tcl_Obj *)*4, "tcl objv");
    objv[0]=Tcl_NewStringObj(name, -1);
    objv[1]=tpm_StateToInstanceObj(st);
    objv[2]=tpm_ConnectionToInstanceObj(conn);
    objv[3]=tpm_MessageDigestToInstanceObj(md);
    Tcl_IncrRefCount(objv[0]);
    Tcl_IncrRefCount(objv[1]);
    Tcl_IncrRefCount(objv[2]);
    Tcl_IncrRefCount(objv[3]);

    objc=4;

    ret = tpm_call_it(objv, objc);

    while(objc > 0) {
	objc--;
	if(objv[objc]!=NULL) {
	    Tcl_DecrRefCount(objv[objc]);
	    objv[objc]=NULL;
	}
    }
    pfree(objv);

    passert(name != NULL);

    return ret;
}

stf_status tpm_call_out_crypt(const char *name
			      , struct state *st
			      , pb_stream *pbs, int off, int len)
{
    Tcl_Obj  **objv;
    int   objc=0, ret;
    char *res;
    Tcl_Obj *to;

    objv = alloc_bytes(sizeof(Tcl_Obj *)*5, "tcl objv");
    objv[0]=Tcl_NewStringObj(name, -1);

    objv[1]=tpm_StateToInstanceObj(st);
    objv[2]=tpm_PbStreamToInstanceObj(pbs);
    objv[3]=Tcl_NewIntObj(off);
    objv[4]=Tcl_NewIntObj(len);
    Tcl_IncrRefCount(objv[0]);
    Tcl_IncrRefCount(objv[1]);
    Tcl_IncrRefCount(objv[2]);
    Tcl_IncrRefCount(objv[3]);
    Tcl_IncrRefCount(objv[4]);

    objc=5;

    ret = tpm_call_it(objv, objc);

    while(objc > 0) {
	objc--;
	if(objv[objc]!=NULL) {
	    Tcl_DecrRefCount(objv[objc]);
	    objv[objc]=NULL;
	}
    }
    pfree(objv);

    return ret;
}

stf_status tpm_call_out_notify(const char *name
			       , struct state *st
			       , pb_stream *pbs
			       , struct isakmp_hdr *hdr)
{
    Tcl_Obj  **objv;
    int   objc=0, ret;
    char *res;
    Tcl_Obj *to;

    objv = alloc_bytes(sizeof(Tcl_Obj *)*4, "tcl objv");
    objv[0]=Tcl_NewStringObj(name, -1);

    objv[1]=tpm_StateToInstanceObj(st);
    objv[2]=tpm_PbStreamToInstanceObj(pbs);
    objv[3]=tpm_IsakmpHdrToInstanceObj(hdr);
    Tcl_IncrRefCount(objv[0]);
    Tcl_IncrRefCount(objv[1]);
    Tcl_IncrRefCount(objv[2]);
    Tcl_IncrRefCount(objv[3]);

    objc=4;

    ret = tpm_call_it(objv, objc);

    while(objc > 0) {
	objc--;
	if(objv[objc]!=NULL) {
	    Tcl_DecrRefCount(objv[objc]);
	    objv[objc]=NULL;
	}
    }
    pfree(objv);

    return ret;
}


/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
