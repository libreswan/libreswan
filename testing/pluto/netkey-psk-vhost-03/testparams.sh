#!/bin/sh

TEST_PURPOSE=regress
TEST_PROB_REPORT=0
TEST_TYPE=umlXhost

TESTNAME=netkey-psk-pluto-06

#THREEEIGHT=true

XHOST_LIST="ROAD EAST"
EASTHOST=east
ROADHOST=road

REF_EAST_CONSOLE_OUTPUT=east-console.txt
REF26_EAST_CONSOLE_OUTPUT=east-console.txt
REF_ROAD_CONSOLE_OUTPUT=road-console.txt
REF26_ROAD_CONSOLE_OUTPUT=road-console.txt

REF_CONSOLE_FIXUPS="kern-list-fixups.sed nocr.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS east-prompt-splitline.pl"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS cutout.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-debug-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS script-only.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-setup-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS pluto-whack-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS host-ping-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-look-esp-sanitize.pl"

EAST_INIT_SCRIPT=eastinit.sh
ROAD_INIT_SCRIPT=roadinit.sh

ROAD_RUN_SCRIPT=roadrun.sh
EAST_RUN2_SCRIPT=final1.sh

EAST_FINAL_SCRIPT=final.sh
ROAD_FINAL_SCRIPT=final.sh

ADDITIONAL_HOSTS="nic"

