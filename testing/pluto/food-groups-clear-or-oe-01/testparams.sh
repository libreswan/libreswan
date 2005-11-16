#!/bin/sh

TEST_PURPOSE=regress
TEST_PROB_REPORT=0
TEST_TYPE=umlplutotest

TESTNAME=food-groups-clear-or-oe-01
EASTHOST=east
WESTHOST=west

#EAST_INPUT=../../klips/inputs/01-sunrise-sunset-ping.pcap
#REF_WEST_OUTPUT=../../klips/outputs/westnet-east-sunset-ping.txt
#REF_WEST_FILTER=../../klips/fixups/no-arp-pcap.pl
#REF_PUB_OUTPUT=../../klips/outputs/publicnet-east-sunset-ping.txt
#REF_PUB_FILTER=../../klips/fixups/no-arp-pcap.pl

REF_EAST_CONSOLE_OUTPUT=east-console.txt
REF_WEST_CONSOLE_OUTPUT=west-console.txt

REF_CONSOLE_FIXUPS="kern-list-fixups.sed nocr.sed cutout.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-look-esp-sanitize.pl"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS east-prompt-splitline.pl"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-debug-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS host-ping-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS host-dig-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-setup-sanitize.sed"

EAST_INIT_SCRIPT=eastinit.sh
WEST_INIT_SCRIPT=westinit.sh

EAST_RUN_SCRIPT=eastrun.sh
#EAST_FINAL_SCRIPT=eastfinal.sh

#WEST_FINAL_SCRIPT=eastfinal.sh

ADDITIONAL_HOSTS="sunset nic"

