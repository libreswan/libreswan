#!/bin/sh

TEST_TYPE=klipstest
TESTNAME=west-reject-02
TESTHOST=west
TEST_PURPOSE=regress
TEST_PROB_REPORT=89

EXITONEMPTY=--exitonempty
PRIV_INPUT=../inputs/ikeinit-japan-sunrise.pcap
REF_PUB_OUTPUT=spi1-output.txt

#THREEEIGHT=true

REF_PRIV_OUTPUT=icmp-output.txt
REF_PRIV_FILTER=../../klips/fixups/one-to-eight-icmp.pl

REF_CONSOLE_OUTPUT=spi1-console.txt
REF26_CONSOLE_OUTPUT=spi1-console.txt
REF_CONSOLE_FIXUPS="kern-list-fixups.sed nocr.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS script-only.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-spi-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-look-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS east-prompt-splitline.pl"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-debug-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS tcpdump-three-eight.sed"
TCPDUMPFLAGS="-n"
INIT_SCRIPT=spi1.sh



