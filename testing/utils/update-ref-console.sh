#!/bin/sh

#
# $Id: update-ref-console.sh,v 1.2 2002/10/10 16:09:59 mcr Exp $
#
# use this script to update the console reference output from the last
# run of tests, for a list of tests (directories) supplied on the
# command line, space delimited.  Start this from testing/klips, listing
# all the test names (directories), space-separated.

. ../utils/functions.sh

console_copy_func() {
    test=$1;           shift
    consoleprefix=$1;  shift
    reffile=$1;        shift

    echo $test/OUTPUT/${consoleprefix}console-fixed.txt '->' $test/$reffile
    cp -a $test/OUTPUT/${consoleprefix}console-fixed.txt $test/$reffile
}

foreach_ref_console console_copy_func $@

# $Log: update-ref-console.sh,v $
# Revision 1.2  2002/10/10 16:09:59  mcr
# 	refactored update-ref-console to use new foreach_ref_console
# 	function in functions.sh, added a simple way to invoke it,
# 	and also used it in repatch-console.sh.
#
# Revision 1.1  2002/09/20 17:05:18  rgb
# # This script is to update the console reference output from the last
# # run of tests, for a list of tests (directories) supplied on the
# # command line, space delimited.
#
#
