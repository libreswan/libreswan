/* Openswan command interface to Pluto
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2004-2006  Michael Richardson <mcr@xelerance.com>
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
 * RCSID $Id: whacklib.c,v 1.9 2005/09/26 03:23:39 mcr Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <assert.h>

#include <openswan.h>
#include <stdarg.h>

#include "sysdep.h"
#include "constants.h"
#include "oswalloc.h"
#include "oswlog.h"
#include "whack.h"
#include "oswlog.h"

/**
 * Pack a string to a whack messages
 * 
 * @param wp 
 * @param p a string
 * @return bool True if operation was successful
 */
static bool
pack_str(struct whackpacker *wp, char **p)
{
    const char *s = *p == NULL? "" : *p;	/* note: NULL becomes ""! */
    size_t len = strlen(s) + 1;

    if (wp->str_roof - wp->str_next < (ptrdiff_t)len)
    {
	return FALSE;	/* fishy: no end found */
    }
    else
    {
	strcpy((char *)wp->str_next, s);
	wp->str_next += len;
	*p = NULL;	/* don't send pointers on the wire! */
	return TRUE;
    }
}


/**
 * Unpack a whack message into a string
 * 
 * @param wp Whack Message
 * @param p a string into which you want the message to be placed into
 * @return bool True if operation successful
 */
static bool
unpack_str(struct whackpacker *wp, char **p)
{
    unsigned int len = wp->str_roof - wp->str_next;
    unsigned char *end;

    if(len == 0) {
	*p = (char *)NULL;
	return TRUE;
    }
	
    end = memchr(wp->str_next, '\0', len);

    if (end == NULL)
    {
	return FALSE;	/* fishy: no end found */
    }
    else
    {
	unsigned char *s = (wp->str_next == end? NULL : wp->str_next);

	*p = (char *)s;
	wp->str_next = end + 1;
	return TRUE;
    }
}



/**
 * Pack a message to be sent to whack
 * 
 * @param wp The whack message
 * @return err_t
 */
err_t pack_whack_msg (struct whackpacker *wp)
{
    err_t ugh = NULL;
    /**
     * Pack strings
     */
    wp->str_next = wp->msg->string;
    wp->str_roof = &wp->msg->string[sizeof(wp->msg->string)];

    if (!pack_str(wp, &wp->msg->name)	        /* string 1 */
	|| !pack_str(wp, &wp->msg->left.id)     /* string 2 */
	|| !pack_str(wp, &wp->msg->left.cert)   /* string 3 */
	|| !pack_str(wp, &wp->msg->left.ca)     /* string 4 */
	|| !pack_str(wp, &wp->msg->left.groups) /* string 5 */
	|| !pack_str(wp, &wp->msg->left.updown) /* string 6 */
    	|| !pack_str(wp, &wp->msg->left.virt)    /* string 7 */
	|| !pack_str(wp, &wp->msg->right.id)    /* string 8 */
    	|| !pack_str(wp, &wp->msg->right.cert)  /* string 9 */
    	|| !pack_str(wp, &wp->msg->right.ca)    /* string 10 */
    	|| !pack_str(wp, &wp->msg->right.groups)/* string 11 */
	|| !pack_str(wp, &wp->msg->right.updown)/* string 12 */
    	|| !pack_str(wp, &wp->msg->right.virt)  /* string 13 */
	|| !pack_str(wp, &wp->msg->keyid)       /* string 14 */
	|| !pack_str(wp, &wp->msg->myid)        /* string 15 */
    	|| !pack_str(wp, &wp->msg->ike)         /* string 16 */
    	|| !pack_str(wp, &wp->msg->esp)         /* string 17 */
    	|| !pack_str(wp, &wp->msg->tpmeval)     /* string 18 */
    	|| !pack_str(wp, &wp->msg->left.xauth_name)    /* string 19 */
    	|| !pack_str(wp, &wp->msg->right.xauth_name)   /* string 20 */
    	|| !pack_str(wp, &wp->msg->connalias)   /* string 21 */
    	|| !pack_str(wp, &wp->msg->left.host_addr_name)    /* string 22 */
    	|| !pack_str(wp, &wp->msg->right.host_addr_name)   /* string 23 */
	|| !pack_str(wp, &wp->msg->string1)                /* string 24 */
	|| !pack_str(wp, &wp->msg->string2)                /* string 25 */
	|| !pack_str(wp, &wp->msg->string3)                /* string 26 */
	|| !pack_str(wp, &wp->msg->dnshostname) /* string 27 ? */
	|| wp->str_roof - wp->str_next < (ptrdiff_t)wp->msg->keyval.len)    /* chunk (sort of string 19) */
    {
	ugh = "too many bytes of strings to fit in message to pluto";
	return ugh;
    }

    if(wp->msg->keyval.ptr)
    {
	memcpy(wp->str_next, wp->msg->keyval.ptr, wp->msg->keyval.len);
    }
    wp->msg->keyval.ptr = NULL;
    wp->str_next += wp->msg->keyval.len;

    return ugh;
}


/**
 * Unpack a message whack received
 * 
 * @param wp The whack message
 * @return err_t
 */
err_t unpack_whack_msg (struct whackpacker *wp)
{
    err_t ugh = NULL;

    if (wp->str_next > wp->str_roof)
    {
	ugh = builddiag("ignoring truncated message from whack: got %d bytes; expected %u"
			, (int) wp->n, (unsigned) sizeof(wp->msg));
    }
    if (!unpack_str(wp, &wp->msg->name)	          /* string 1 */
	|| !unpack_str(wp, &wp->msg->left.id)     /* string 2 */
	|| !unpack_str(wp, &wp->msg->left.cert)   /* string 3 */
	|| !unpack_str(wp, &wp->msg->left.ca)     /* string 4 */
	|| !unpack_str(wp, &wp->msg->left.groups) /* string 5 */
	|| !unpack_str(wp, &wp->msg->left.updown) /* string 6 */
    	|| !unpack_str(wp, &wp->msg->left.virt)   /* string 7 */
	|| !unpack_str(wp, &wp->msg->right.id)    /* string 8 */
    	|| !unpack_str(wp, &wp->msg->right.cert)  /* string 9 */
    	|| !unpack_str(wp, &wp->msg->right.ca)    /* string 10 */
	|| !unpack_str(wp, &wp->msg->right.groups)/* string 11 */
	|| !unpack_str(wp, &wp->msg->right.updown)/* string 12 */
    	|| !unpack_str(wp, &wp->msg->right.virt)  /* string 13 */
	|| !unpack_str(wp, &wp->msg->keyid)       /* string 14 */
	|| !unpack_str(wp, &wp->msg->myid)        /* string 15 */
    	|| !unpack_str(wp, &wp->msg->ike)         /* string 16 */
    	|| !unpack_str(wp, &wp->msg->esp)         /* string 17 */
    	|| !unpack_str(wp, &wp->msg->tpmeval)     /* string 18 */
    	|| !unpack_str(wp, &wp->msg->left.xauth_name)    /* string 19 */
    	|| !unpack_str(wp, &wp->msg->right.xauth_name)   /* string 20 */
    	|| !unpack_str(wp, &wp->msg->connalias)   /* string 21 */
    	|| !unpack_str(wp, &wp->msg->left.host_addr_name)    /* string 22 */
    	|| !unpack_str(wp, &wp->msg->right.host_addr_name)   /* string 23 */
	|| !unpack_str(wp, &wp->msg->string1)                /* string 24 */
	|| !unpack_str(wp, &wp->msg->string2)                /* string 25 */
	|| !unpack_str(wp, &wp->msg->string3)                /* string 26 */
	|| !unpack_str(wp, &wp->msg->dnshostname)  /* string 27 ? */
	|| wp->str_roof - wp->str_next != (ptrdiff_t)wp->msg->keyval.len)	/* check chunk */
    {
	ugh = "message from whack contains bad string";
    }

    return ugh;
}

void
clear_end(struct whack_end *e)
{
    zero(e);
    e->id = NULL;
    e->cert = NULL;
    e->ca = NULL;
    e->updown = NULL;
    e->host_port = IKE_UDP_PORT;
}

int
whack_get_value(char *buf, size_t bufsize)
{
    int len;
    int try;

    fflush(stdout);
    usleep(20000); /* give fflush time for flushing - has to go through awk */

    try = 3;
    len = 0;
    while(try > 0 && len==0)
    {
	fprintf(stderr, "Name enter:   ");
	
	memset(buf, 0, bufsize);
	
	if(fgets(buf, bufsize, stdin) != buf) {
	    if(errno == 0) {
		fprintf(stderr, "Can not read password from standard in\n");
		exit(RC_WHACK_PROBLEM);
	    } else {
		perror("fgets value");
		exit(RC_WHACK_PROBLEM);
	    }
	}
	
	/* send the value to pluto, including \0, but fgets adds \n */
	len = strlen(buf);
	if(len == 0)
	{
	    fprintf(stderr, "answer was empty, retry\n");
	}
    }
    if(len ==  0)
    {
	exit(RC_WHACK_PROBLEM);
    }

    return len;
}

size_t
whack_get_secret(char *buf, size_t bufsize)
{
    const char *secret;
    int len;

    fflush(stdout);
    usleep(20000); /* give fflush time for flushing */
    secret = getpass("Enter secret: ");
    secret = (secret == NULL) ? "" : secret;

    strncpy(buf, secret, bufsize);

    len = strlen(buf) + 1;
    
    return len;
}



