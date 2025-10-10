# Wrapper to build NSS 64-bit for libreswan testing
#
# Copyright (C) 2025  Andrew Cagney
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

# https://firefox-source-docs.mozilla.org/security/nss/build.html

BUILD = \
	DEBUG=1 \
	PKIX_DEBUG=1 \
	PKIX_OBJECT_LEAK_TEST=1 \
	USE_64=1 \
	BUILD_OPT=0 \
	./nss/build.sh

.PHONY: build

build: | nspr/ nss/
	$(BUILD) --enable-libpkix

.PHONY: clean

clean:
	$(BUILD) -cc
	rm -rf dist/

.PHONY: distclean

distclean: clean
	rm -rf nss/
	rm -rf nspr/

.PHONY: check

check:
	HOST=localhost \
	DOMSUF=localdomain \
	USE_64=1 \
	./nss/tests/all.sh

.PHONY: download

download: nspr/ nss/

nspr/:
	hg clone https://hg.mozilla.org/projects/nspr
nss/:
	hg clone https://hg.mozilla.org/projects/nss
