#!/bin/sh

# Update the /testing/pluto/log.ref files from those just created in
# /tmp/log by the "pluto_unit_tests.sh" script.
#
# run this script in a UML after running pluto_unit_tests.sh
#
# $Id: update-in-place.sh,v 1.1 2003/05/21 15:45:57 mcr Exp $
#
#

mount -o rw,remount /testing
cd /tmp/log
for i in */w?-log
do
	cp $i /tmp/log.ref/$i
done


# $Log: update-in-place.sh,v $
# Revision 1.1  2003/05/21 15:45:57  mcr
# 	update the log.ref files from the newly generated files in
# 	/tmp/log. Run this in a UML.
#
#
#
