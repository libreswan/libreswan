#!/bin/sh

TEST_PURPOSE=regress
TEST_TYPE=umlXhost
TEST_PROB_REPORT=249

TESTNAME=pluto-rekey-01

XHOST_LIST="ROAD EAST SUNRISE"

REF_CONSOLE_FIXUPS="kern-list-fixups.sed nocr.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS east-prompt-splitline.pl"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS cutout.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-setup-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS host-ping-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS host-dig-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS pluto-whack-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-lwdnsq-sanitize.pl"

EASTHOST=east
EAST_INIT_SCRIPT=../oe-road-01/eastinit.sh
EAST_RUN2_SCRIPT=eastrun2.sh
EAST_FINAL_SCRIPT=../oe-road-01/roadfinal.sh
REF_EAST_CONSOLE_OUTPUT=east-console.txt

ROADHOST=road
ROAD_INIT_SCRIPT=../myid-road-04/roadinit.sh
ROAD_RUN_SCRIPT=../myid-road-04/roadrun.sh
ROAD_RUN3_SCRIPT=roadrun3.sh
ROAD_FINAL_SCRIPT=../myid-road-04/roadfinal.sh
REF_ROAD_CONSOLE_OUTPUT=road-console.txt

SUNRISEHOST=sunrise
SUNRISE_INIT_SCRIPT=../oe-road-01/sunriseinit.sh

ADDITIONAL_HOSTS="nic"

NETJIG_EXTRA=../basic-pluto-01/debugpublic.txt




