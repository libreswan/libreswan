#!/bin/sh

TEST_PURPOSE=regress
TEST_PROB_REPORT=0
TEST_TYPE=umlplutotest

TESTNAME=food-groups-never-01
EASTHOST=east
WESTHOST=west

REF_WEST_OUTPUT=../../klips/outputs/westnet-null.txt
WEST_ARPREPLY=true

REF_PUB_OUTPUT=../../klips/outputs/publicnet-west-east-ping.txt
REF_PUB_FILTER=../../klips/fixups/no-arp-pcap2.pl
#PUBLIC_ARPREPLY=true

REF_EAST_CONSOLE_OUTPUT=east-console.txt

THREEEIGHT=true

REF_CONSOLE_FIXUPS="kern-list-fixups.sed nocr.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-look-esp-sanitize.pl"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS east-prompt-splitline.pl"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-setup-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS host-ping-sanitize.sed"


EAST_INIT_SCRIPT=eastinit.sh
WEST_INIT_SCRIPT=westinit.sh

EAST_RUN_SCRIPT=eastrun.sh

