#!/bin/sh

TEST_TYPE=klipstest
TESTNAME=west-icmp-05
TESTHOST=west
EXITONEMPTY=--exitonempty
PRIVATE_ARPREPLY=true

#THREEEIGHT=true
PUB_INPUT=../inputs/08-sunrise-sunset-aes.pcap
REF_PRIV_OUTPUT=spi1-cleartext.txt

REF_CONSOLE_OUTPUT=spi1-console.txt
REF26_CONSOLE_OUTPUT=spi1-console26.txt

REF_CONSOLE_FIXUPS="script-only.sed nocr.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-spi-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-look-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS east-prompt-splitline.pl"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-debug-sanitize.sed"
TCPDUMPFLAGS="-n"
INIT_SCRIPT=spi1-in.sh

#NETJIGDEBUG=true


