
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

USE_DYNAMICDNS=true
USE_DNSSEC=true
USE_IKEPING=true
USE_KEYRR=true
USE_KLIPS=true
USE_MAST=true
USE_SAREF_KERNEL=true
USE_NETKEY=true
USE_VENDORID=true
USE_AGGRESSIVE=true
USE_XAUTH=true
USE_XAUTHPAM=true
USE_FIPSCHECK=true
USE_LINUX_AUDIT=true
USE_LABELED_IPSEC=true
USE_LIBCAP_NG=true
USE_NM=true
USE_MODP_RFC5114=true
USE_NAT_TRAVERSAL=true
USE_NAT_TRAVERSAL_TRANSPORT_MODE=true
USE_LDAP=true
USE_LIBCURL=true
USE_WEAKSTUFF=true
USE_NOCRYPTO=true
USE_EXTRACRYPTO=true
USE_IPSEC_CONNECTION_LIMIT=true
HAVE_STATSD=true
#HAVE_OPENSSL=true
HAVE_OCF=true
# taproom is totally broken
USE_TAPROOM=false
USE_LEAK_DETECTIVE=true
# Not available on Fedora/RHEL
#USE_DMALLOC=true
USE_LEAK_DETECTIVE=true

export USE_NETKEY USE_VENDORID USE_AGGRESSIVE USE_XAUTH USE_XAUTHPAM \
       USE_FIPSCHECK USE_LINUX_AUDIT USE_LABELED_IPSEC USE_LIBCAP_NG \
       USE_NM USE_MODP_RFC5114 USE_NAT_TRAVERSAL \
       USE_NAT_TRAVERSAL_TRANSPORT_MODE USE_LDAP USE_LIBCURL USE_WEAKSTUFF \
       USE_NOCRYPTO USE_EXTRACRYPTO USE_IPSEC_CONNECTION_LIMIT HAVE_STATSD \
       HAVE_OCF USE_TAPROOM USE_LEAK_DETECTIVE USE_DMALLOC USE_LEAK_DETECTIVE 
