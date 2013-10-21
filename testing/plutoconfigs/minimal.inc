
# Copyright (C) 2013 Paul Wouters <pwouters@redhat.com>
# 
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.

# These will override Makefile.inc values
# This is run as part of a compile test run in the test harnass on Linux only

USE_DNSSEC=false
USE_IKEPING=false
USE_KEYRR=false
USE_KLIPS=false
USE_MAST=false
USE_SAREF_KERNEL=false
USE_NETKEY=true
USE_XAUTHPAM=false
USE_FIPSCHECK=false
USE_LINUX_AUDIT=false
USE_LABELED_IPSEC=false
USE_LIBCAP_NG=false
USE_NM=false
USE_LDAP=false
USE_LIBCURL=false
USE_EXTRACRYPTO=false
USE_IPSEC_CONNECTION_LIMIT=false
#HAVE_OPENSSL=false
HAVE_OCF=false
USE_TAPROOM=false
USE_LEAK_DETECTIVE=false
USE_DMALLOC=false
USE_LEAK_DETECTIVE=false

export USE_NETKEY USE_XAUTHPAM \
       USE_FIPSCHECK USE_LINUX_AUDIT USE_LABELED_IPSEC USE_LIBCAP_NG \
       USE_NM USE_LDAP USE_LIBCURL \
       USE_EXTRACRYPTO USE_IPSEC_CONNECTION_LIMIT HAVE_STATSD \
       HAVE_OCF USE_TAPROOM USE_LEAK_DETECTIVE USE_DMALLOC USE_LEAK_DETECTIVE 
