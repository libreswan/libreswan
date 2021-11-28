#!/bin/sh

set -xe

: git crashes, do not know why
pkg_add git || true
pkg_add gmake
pkg_add nss
pkg_add unbound
pkg_add bison
pkg_add flex
pkg_add ldns
pkg_add xmlto
pkg_add pkg-config
pkg_add mozilla-rootcerts
mozilla-rootcerts install
