#!/bin/sh

# Configure a guest's test namespace, for libreswan
#
# Copyright (C) 2026 Andrew Cagney
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

set -e

ERROR() {
    echo "$@" 1>&2
    exit 1
}

RUN() {
    echo + "$@"
    "$@"
}

BIND() {
    local src=$1
    local dst=$2
    RUN umount "${dst}" || true
    RUN mount --bind "${src}" "${dst}"
}

# note the difference, RM bind empties ${src}

RM_BIND() {
    local src=${nsdir}/$1
    local dst=$2
    RUN umount "${dst}" || true
    RUN mkdir -p "${src}"
    RUN rm -rf "${src}"/*
    RUN mount --bind "${src}" "${dst}"
}

if test $# -ne 2 ; then
    ERROR "Usage: $0 host test"
fi

host=$1
test=$2

echo host="${host}" test="${test}"

testingdir=$(realpath $(dirname $0)/..)
testdir="${testingdir}"/pluto/"${test}"
nsdir="${testdir}"/NS/"${host}"

RUN mkdir -p "${nsdir}"

# BIND "${testingdir}" /testing
# BIND "${nsdir}"/etc.ipsec.d /etc/ipsec.d
# BIND "${nsdir}"/etc.strongswan /etc/strongswan
# BIND "${nsdir}"/tmp /tmp

# bind and empty NSS directory
RM_BIND nss /var/lib/ipsec/nss

# bind and rebuild OCSPD's directory
RM_BIND ocspd /etc/ocspd
mkdir -p /etc/ocspd/private
mkdir -p /etc/ocspd/certs
mkdir -p /etc/ocspd/crls
