#!/bin/sh

TEST_TYPE=klipstest
TESTNAME=west-rcv-nfmark-set-02
TESTHOST=west
EXITONEMPTY=--exitonempty
ARPREPLY=--arpreply 

PUB_INPUT=../inputs/public-two-1.pcap
REF_PRIV_OUTPUT=icmp-priv-flow.txt
REF_PUB_OUTPUT=icmp-pub-flow.txt
#THREEEIGHT=true

REF_CONSOLE_OUTPUT=nfmark-console.txt

REF_CONSOLE_FIXUPS="kern-list-fixups.sed nocr.sed script-only.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-spi-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-look-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS east-prompt-splitline.pl"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-debug-sanitize.sed"
TCPDUMPFLAGS="-e"

INIT_SCRIPT=rcv.sh

#NETJIGDEBUG=true


