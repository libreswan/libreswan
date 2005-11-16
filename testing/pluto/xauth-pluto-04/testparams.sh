#!/bin/sh

TEST_PURPOSE=goal
TEST_PROB_REPORT=0
TEST_TYPE=umlXhost

TESTNAME=xauth-pluto-04

XHOST_LIST="ROAD EAST"

REF_CONSOLE_FIXUPS="kern-list-fixups.sed nocr.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS east-prompt-splitline.pl"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS cutout.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-setup-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS pluto-whack-sanitize.sed"

EASTHOST=east
EAST_INIT_SCRIPT=eastinit.sh
EAST_FINAL_SCRIPT=final.sh
REF_EAST_CONSOLE_OUTPUT=east-console.txt

ROADHOST=road
ROAD_INIT_SCRIPT=roadinit.sh
ROAD_RUN_SCRIPT=roadrun.sh
ROAD_FINAL_SCRIPT=final.sh
REF_ROAD_CONSOLE_OUTPUT=road-console.txt

ADDITIONAL_HOSTS="nic"

NETJIG_EXTRA=../basic-pluto-01/debugpublic.txt


