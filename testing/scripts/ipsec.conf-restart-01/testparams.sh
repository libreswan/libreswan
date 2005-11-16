#!/bin/sh

TEST_PURPOSE=regress
TEST_PROB_REPORT=0
TEST_TYPE=ctltest

TESTNAME=ipsec.conf-restart-01
TESTHOST=east

REF_CONSOLE_OUTPUT=east-console.txt

REF_CONSOLE_FIXUPS="nocr.sed script-only.sed ipsec-setup-sanitize.sed pluto-log-sanitize.sed"
REF_CONSOLE_FIXUPS="${REF_CONSOLE_FIXUPS} ipsec-ver-sanitize.sed"


INIT_SCRIPT=restart_test.sh
