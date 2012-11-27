/* Support functions for X.509 attribute certificates
 * Copyright (C) 2002 Ueli Gallizzi, Ariane Seiler
 * Copyright (C) 2003 Martin Berner, Lukas Suter
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <sys/types.h>

#include <libreswan.h>

#include "sysdep.h"
#include "lswconf.h"
#include "lswalloc.h"
#include "constants.h"
#include "lswlog.h"

#include "lswtime.h"
#include "asn1.h"
#include "oid.h"
#include "ac.h"
#include "id.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"

void  
unshare_ietfAttrList(ietfAttrList_t **listp)
{
    ietfAttrList_t *list = *listp;
       
    while (list != NULL)
    {
      ietfAttrList_t *el = alloc_thing(ietfAttrList_t, "ietfAttrList");
 
      el->attr = list->attr;
      el->attr->count++;
      el->next = NULL;
      *listp = el;
      listp = &el->next;
      list = list->next;
    }
}

