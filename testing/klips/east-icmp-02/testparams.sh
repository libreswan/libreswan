#!/bin/sh

TEST_PURPOSE=goal
TEST_GOAL_ITEM=160
TEST_TYPE=klipstest

TESTNAME=east-icmp-02
TESTHOST=east
EXITONEMPTY=--exitonempty
PRIV_INPUT=../inputs/01-sunrise-sunset-ping.pcap
REF_PUB_OUTPUT=spi1-output.txt
REF_CONSOLE_OUTPUT=spi1-console.txt
REF26_CONSOLE_OUTPUT=spi1-console.txt
REF_CONSOLE_FIXUPS="kern-list-fixups.sed nocr.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS script-only.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-spi-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-debug-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-look-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS east-prompt-splitline.pl"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS tcpdump-three-eight.sed"
TCPDUMPFLAGS="-n -E 3des-cbc-hmac96:0x43434545464649494a4a4c4c4f4f51515252545457575840"
REF_PUB_FILTER=./sanitize-second-esp.pl
INIT_SCRIPT=spi1.sh

#FINAL_SCRIPT=sleephalt.sh



