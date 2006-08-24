#!/bin/sh

TEST_PURPOSE=regress
TEST_PROB_REPORT=0
TEST_TYPE=klipstest

TESTNAME=tncfg-01
TESTHOST=east
EXITONEMPTY=--exitonempty
REF_CONSOLE_OUTPUT=console.txt
REF26_CONSOLE_OUTPUT=console.txt

REF_CONSOLE_FIXUPS="kern-list-fixups.sed nocr.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS script-only.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS east-prompt-splitline.pl"

INIT_SCRIPT=tncfg.sh

