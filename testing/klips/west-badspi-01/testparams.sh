#!/bin/sh

TEST_TYPE=klipstest
TESTNAME=west-badspi-01
TESTHOST=west
EXITONEMPTY=--exitonempty
ARPREPLY=--arpreply 

PUB_INPUT=../inputs/02-sunrise-sunset-esp.pcap
REF_PUB=icmp-warn.txt
REF_CONSOLE_OUTPUT=setup-console.txt
REF26_CONSOLE_OUTPUT=setup-console.txt
REF_CONSOLE_FIXUPS="kern-list-fixups.sed nocr.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS script-only.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-spi-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-look-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS east-prompt-splitline.pl"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-debug-sanitize.sed"
INIT_SCRIPT=ipsec-cfg.sh



