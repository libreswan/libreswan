#!/bin/sh

TEST_PURPOSE=regress
TEST_PROB_REPORT=0
TEST_TYPE=klipstest

TESTNAME=east-icmp-03
TESTHOST=east
EXITONEMPTY=--exitonempty
PRIV_INPUT=../inputs/08-sunrise-sunset-ping-big.pcap

REF_PUB_OUTPUT=spi1-output.txt

REF_CONSOLE_OUTPUT=spi1-console.txt
REF26_CONSOLE_OUTPUT=spi1-console.txt

REF_CONSOLE_FIXUPS="nocr.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS script-only.sed "
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-spi-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-debug-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS east-prompt-splitline.pl"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-look-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS tcpdump-three-eight.sed"
TCPDUMPFLAGS="-n -E 3des-cbc-hmac96:0x4043434545464649494a4a4c4c4f4f515152525454575758"
INIT_SCRIPT=spi1.sh



