#!/bin/sh

TEST_TYPE=klipstest
TESTNAME=west-ah-icmp-01
TESTHOST=west
EXITONEMPTY=--exitonempty

PRIVATE_ARPREPLY=--arpreply 

PUB_INPUT=../inputs/08-sunrise-sunset-ah-md5.pcap
REF_PRIV_OUTPUT=ah1-cleartext.txt
REF_CONSOLE_OUTPUT=ah1-console.txt
REF_CONSOLE_FIXUPS="kern-list-fixups.sed nocr.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS script-only.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-spi-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-look-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS east-prompt-splitline.pl"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-debug-sanitize.sed"
TCPDUMPFLAGS="-n "
INIT_SCRIPT=ah1-in.sh

#NETJIGDEBUG=true


