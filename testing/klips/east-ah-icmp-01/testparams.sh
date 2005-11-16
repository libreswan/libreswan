#!/bin/sh

TEST_PURPOSE=regress
TEST_PROB_REPORT=0
TEST_TYPE=klipstest

TESTNAME=east-ah-icmp-01
TESTHOST=east
EXITONEMPTY=--exitonempty
THREEEIGHT=true
PRIV_INPUT=../inputs/01-sunrise-sunset-ping.pcap
REF_PUB_OUTPUT=ah1-output.txt
REF26_PUB_OUTPUT=ah1-output26.txt
REF_CONSOLE_OUTPUT=ah1-console.txt
REF_CONSOLE_FIXUPS="kern-list-fixups.sed nocr.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-spi-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-look-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS east-prompt-splitline.pl"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-debug-sanitize.sed"
TCPDUMPFLAGS="-n "
INIT_SCRIPT=ah1.sh



