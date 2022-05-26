#!/bin/sh

set -xe

pkg bootstrap -y
pkg install -y gmake
pkg install -y git
pkg install -y pkgconf # aka pkg-config; grrr
pkg install -y nss
pkg install -y libevent
pkg install -y unbound
pkg install -y bison
pkg install -y flex
pkg install -y ldns
pkg install -y xmlto
pkg install -y bash
pkg install -y strongswan
pkg install -y fping
