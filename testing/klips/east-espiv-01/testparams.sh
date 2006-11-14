#!/bin/sh

TEST_TYPE=klipstest
TESTNAME=east-espiv-01
TEST_PURPOSE=exploit
TEST_EXPLOIT_URL="http://www.hut.fi/~svaarala/espiv.pdf"

TESTHOST=east
EXITONEMPTY=--exitonempty
PRIV_INPUT=../inputs/01-sunrise-sunset-ping.pcap

REF_PUB_OUTPUT=spi1-output.txt
REF_PUB_FILTER=./examineIV.pl
REF_CONSOLE_OUTPUT=spi1-console.txt
REF26_CONSOLE_OUTPUT=spi1-console.txt
REF_CONSOLE_FIXUPS="kern-list-fixups.sed nocr.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS script-only.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-spi-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-debug-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-look-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS east-prompt-splitline.pl"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS tcpdump-three-eight.sed"
TCPDUMPFLAGS="-n -x -X -s 1600"
INIT_SCRIPT=spi1.sh



