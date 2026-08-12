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

X509DIR ?= .

.PHONY: all
all:
	./generate.sh $(X509DIR)
	./crl.sh $(X509DIR)
	./selfsigned.sh $(X509DIR)/selfsigned

.PHONY: clean
clean:
	: careful output mixed with repo files
	rm -rf $(X509DIR)/pki
	rm -rf $(X509DIR)/selfsigned
	rm -rf $(X509DIR)/strongswan
