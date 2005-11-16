#!/bin/sh

TEST_PURPOSE=regress
TEST_PROB_REPORT=0
TEST_TYPE=umlplutotest

TESTNAME=food-groups-oe-or-die-01
EASTHOST=east
WESTHOST=west

REF_WEST_OUTPUT=westnet-ping.txt

REF_WEST_FILTER=../../klips/fixups/no-arp-pcap2.pl
THREEEIGHT=true

REF_EAST_CONSOLE_OUTPUT=east-console.txt

REF_CONSOLE_FIXUPS="kern-list-fixups.sed nocr.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-look-esp-sanitize.pl"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS east-prompt-splitline.pl"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-setup-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS host-ping-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS host-dig-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS cutout.sed"

EAST_INIT_SCRIPT=eastinit.sh
WEST_INIT_SCRIPT=westinit.sh

EAST_RUN_SCRIPT=eastrun.sh

EAST_FINAL_SCRIPT=eastfinal.sh
WEST_FINAL_SCRIPT=westfinal.sh

NETJIG_EXTRA=recordpublic.txt

ADDITIONAL_HOSTS="sunset nic"

