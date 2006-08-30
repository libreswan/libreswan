#!/bin/sh

TEST_TYPE=klipstest
TESTNAME=west-ah-icmp-02
TESTHOST=west
EXITONEMPTY=--exitonempty
PRIVATE_ARPREPLY=--arpreply 

PUB_INPUT=../inputs/08-sunrise-sunset-ah-sha1.pcap
REF_PRIV_OUTPUT=ah2-cleartext.txt
REF_CONSOLE_OUTPUT=ah2-console.txt
REF_CONSOLE_FIXUPS="kern-list-fixups.sed nocr.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS script-only.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-spi-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-look-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS east-prompt-splitline.pl"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-debug-sanitize.sed"
TCPDUMPFLAGS="-n "
INIT_SCRIPT=ah2-in.sh

#NETJIGDEBUG=true


