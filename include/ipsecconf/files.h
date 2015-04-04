/* FreeS/WAN files locations (files.h)
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2005 Michael Richardson <mcr@marajade.sandelman.ca>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Paul Wouters <pwouters@redhat.com>
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

#ifndef _STARTER_FILES_H_
#define _STARTER_FILES_H_

#ifndef IPSEC_EXECDIR
#define IPSEC_EXECDIR   "/usr/local/libexec/ipsec"
#endif

#ifndef IPSEC_CONFDIR
#define IPSEC_CONFDIR   "/etc"
#endif

#ifndef IPSEC_CONFDDIR
#define IPSEC_CONFDDIR   "/etc/ipsec.d"
#endif

#ifndef IPSEC_NSSDIR
#define IPSEC_NSSDIR   "/etc/ipsec.d"
#endif

#define DEFAULT_CTLBASE "/var/run/pluto/pluto"
#define CTL_SUFFIX      ".ctl"
#define PID_SUFFIX      ".pid"

#define CTL_FILE        DEFAULT_CTLBASE CTL_SUFFIX

#define DYNIP_DIR       "/var/run/pluto/dynip"

#endif /* _STARTER_FILES_H_ */

