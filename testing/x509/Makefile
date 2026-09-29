# Libreswan top level Makefile
#
# Copyright (C) 2025-2026  Andrew Cagney
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

include ../../mk/dirs.mk
include $(top_srcdir)/mk/config.mk

X509DIR ?= .

overrides += CERTUTIL=$(CERTUTIL)
overrides += PK12UTIL=$(PK12UTIL)
overrides += CRLUTIL=$(CRLUTIL)

PKI = $(overrides) ./bin/pki.sh $(X509DIR)

.PHONY: all
all:
	: #
	: # Generate root certificates
	: #
	: #   DIRs CAs DOMAIN IS_CA KU EKU=/ PARAM...
	: #
	$(PKI) root: 'real fake'   mainca   testing.libreswan.org  Y  certSigning,crlSigning,critical  /  -k rsa -Z SHA256 -g 3072
	$(PKI) root: 'real fake'   mainec   testing.libreswan.org  Y  certSigning,crlSigning,critical  /  -k ec  -Z SHA256 -q secp384r1
ifeq ($(USE_EDDSA),true)
	$(PKI) root: real          mained   testing.libreswan.org  Y  certSigning,crlSigning,critical  /  -k ed
endif
	$(PKI) root: other         otherca  other.libreswan.org    Y  certSigning,crlSigning,critical  /  -k rsa -Z SHA256 -g 3072
	: # broken root CA, ca not be used to verify
	$(PKI) root: broken        bc-n-ca  testing.libreswan.org  n  /                                /  -k rsa -Z SHA256 -g 3072
	: # generate intermediate et.al. certs
	$(PKI)
	$(overrides) ./bin/crl.sh $(X509DIR)
	$(overrides) ./bin/selfsigned.sh $(X509DIR)/selfsigned

.PHONY: clean
clean:
	: careful output mixed with repo files
	rm -rf $(X509DIR)/pki
	rm -rf $(X509DIR)/selfsigned
	rm -rf $(X509DIR)/strongswan
