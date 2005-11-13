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

char *tpm_template=
"proc preEncrypt  {state pb off len} { return \"ignore\" } \n"
"proc postEncrypt {state pb off len} { return \"ignore\" } \n"
"proc preDecrypt  {state pb off len} { return \"ignore\" } \n"
"proc postDecrypt {state pb off len} { return \"ignore\" } \n"
"proc preHash     {state pb off len} { return \"ignore\" } \n"
"proc postHash    {state pb off len} { return \"ignore\" } \n"
"proc changeState {state conn md} {       \n"
"    return \"ignore\"                    \n"
"}                                        \n"
"                                         \n"
"proc processRawPacket {state conn md} {  \n"
"    return \"ignore\"                    \n"
"}                                        \n"
"                                         \n"
"proc adjustFailure {state conn md} {     \n"
"    return \"ignore\"                    \n"
"}                                        \n"
"                                         \n"
"proc recvMessage {state conn md} {       \n"
"    return \"ignore\"                    \n"
"}                                        \n"
"                                         \n"
"proc avoidEmitting {state conn md} {     \n"
"    return \"ignore\"                    \n"
"}                                        \n"
"                                         \n"
"proc adjustTimers {state conn md} {   return \"ignore\" } \n"
"                                           \n"
"proc avoidEmittingNotify {state pbs hdr} { \n"
"    return \"ignore\"                      \n"
"}                                          \n"
"                                           \n"
"proc avoidEmittingDelete {state pbs hdr} { \n"
"    return \"ignore\"                      \n"
"}                                          \n"
;

void tpm_initCallbacks(Tcl_Interp *PlutoInterp) 
{
	int val;

	val = Tcl_Eval(PlutoInterp, tpm_template);

	switch(val) {
	case TCL_OK:
		return;
	
	case TCL_ERROR:
	case TCL_RETURN:
	case TCL_BREAK:
	case TCL_CONTINUE:
		openswan_log("tpm init callback error: %s\n", Tcl_GetObjResult(PlutoInterp));
		break;
	}
}

