#!/bin/sh

# Prepare the host for namespace (nsrun) testing; run as root
#
# Loads the kernel modules used by the tests (best effort, most are
# auto-loaded anyway).
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.

set -eu

if test "$(id -u)" -ne 0 ; then
    echo "$0: must be run as root" 1>&2
    exit 1
fi

for m in xfrm_user xfrm_interface esp4 esp6 ah4 ah6 \
	 xfrm_ipcomp ipcomp ipcomp6 veth bridge \
	 ccm gcm des_generic xcbc cmac chacha20poly1305 ; do
    modprobe -q ${m} 2>/dev/null || true
done
