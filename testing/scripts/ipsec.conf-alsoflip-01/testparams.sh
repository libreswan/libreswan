#!/bin/sh

TEST_PURPOSE=regress
TEST_PROB_REPORT=0
TEST_TYPE=ctltest

TESTNAME=ipsec.conf-alsoflip-01
TESTHOST=east

REF_CONSOLE_OUTPUT=east-console.txt

REF_CONSOLE_FIXUPS="nocr.sed script-only.sed ipsec-setup-sanitize.sed "
REF_CONSOLE_FIXUPS="${REF_CONSOLE_FIXUPS} pluto-log-sanitize.sed"
REF_CONSOLE_FIXUPS="${REF_CONSOLE_FIXUPS} ipsec-ver-remove.sed"

INIT_SCRIPT=alsoflip_test.sh
