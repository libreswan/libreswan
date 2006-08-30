#!/bin/sh

TESTNAME=west-icmp-03
TESTHOST=west
TEST_TYPE=klipstest
TEST_PURPOSE=regress
EXITONEMPTY=--exitonempty
PRIVATE_ARPREPLY=true

PUB_INPUT=../inputs/08-east-west-esp-ipcomp.pcap
REF_PRIV_OUTPUT=spi1-cleartext.txt
REF_CONSOLE_OUTPUT=spi1-console.txt
REF26_CONSOLE_OUTPUT=spi1-console.txt
REF_CONSOLE_FIXUPS="kern-list-fixups.sed nocr.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS script-only.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-spi-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-debug-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-look-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS east-prompt-splitline.pl"
TCPDUMPFLAGS="-n -E 3des-cbc-hmac96:0x4043434545464649494a4a4c4c4f4f515152525454575758"
INIT_SCRIPT=spi1-in.sh

#NETJIGDEBUG=true


