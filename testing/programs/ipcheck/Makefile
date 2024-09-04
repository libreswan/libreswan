# ip tests Makefile, for libreswan
#
# Copyright (C) 2018 Andrew Cagney
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

# XXX: Hack to suppress the man page.  Should one be added?
PROGRAM_MANPAGE =

PROGRAM = _ipcheck

OBJS += ipcheck.o
OBJS += ip_sockaddr_check.o
OBJS += ip_address_check.o
OBJS += ip_endpoint_check.o
OBJS += ip_range_check.o
OBJS += ip_subnet_check.o
OBJS += ip_selector_check.o
OBJS += ip_said_check.o
OBJS += ip_info_check.o
OBJS += ip_protoport_check.o
OBJS += ip_port_check.o
OBJS += ip_port_range_check.o
OBJS += ip_cidr_check.o
OBJS += ip_protocol_check.o
OBJS += ip_packet_check.o

OBJS += $(LIBRESWANLIB)
OBJS += $(LSWTOOLLIBS)

ifdef top_srcdir
include $(top_srcdir)/mk/program.mk
else
include ../../../mk/program.mk
endif

local-check: $(PROGRAM)
	$(builddir)/$(PROGRAM) --dns=yes
