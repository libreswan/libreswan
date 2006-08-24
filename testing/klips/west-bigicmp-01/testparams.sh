#!/bin/sh

TEST_TYPE=klipstest
TESTNAME=west-bigicmp-01
TESTHOST=west
EXITONEMPTY=--exitonempty
ARPREPLY=--arpreply 

#THREEEIGHT=true

PUB_INPUT=../inputs/espfrags1.pcap
REF_PRIV_OUTPUT=spi1-cleartext.txt
REF_CONSOLE_OUTPUT=spi1-console.txt
REF26_CONSOLE_OUTPUT=spi1-console.txt
REF_CONSOLE_FIXUPS="kern-list-fixups.sed nocr.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS script-only.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-spi-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-debug-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-look-sanitize.sed"
TCPDUMPFLAGS="-n -E 3des-cbc-hmac96:0x4043434545464649494a4a4c4c4f4f515152525454575758 -v"
INIT_SCRIPT=spi1-in.sh

#NETJIGDEBUG=true


