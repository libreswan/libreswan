#!/bin/sh

#
# $Id: redocon.sh,v 1.10 2005/05/01 03:27:29 mcr Exp $
#
# use this script to run a single test from within that test directory.
# note that this assumes a "klipstest" type test.
#

. ../../../umlsetup.sh
. ../setup.sh
. $UTILS/functions.sh
. testparams.sh

compat_variables;

if [ -z "${TEST_TYPE}" ]
then
    echo runme.sh now requires that testparams.sh defines TEST_TYPE=
fi

if [ -n "${REF_EAST_CONSOLE_OUTPUT}" ]
then
    consolediff east OUTPUT${KLIPS_MODULE}/eastconsole.txt $REF_EAST_CONSOLE_OUTPUT
fi

if [ -n "${REF26_EAST_CONSOLE_OUTPUT}" ]
then
    KERNVER=26 consolediff east OUTPUT${KLIPS_MODULE}/26eastconsole.txt $REF26_EAST_CONSOLE_OUTPUT
fi

if [ -n "${REF_WEST_CONSOLE_OUTPUT}" ]
then
    consolediff west OUTPUT${KLIPS_MODULE}/westconsole.txt $REF_WEST_CONSOLE_OUTPUT
fi

if [ -n "${REF26_WEST_CONSOLE_OUTPUT}" ]
then
    KERNVER=26 consolediff west OUTPUT${KLIPS_MODULE}/26westconsole.txt $REF26_WEST_CONSOLE_OUTPUT
fi

if [ -n "${REF_ROAD_CONSOLE_OUTPUT}" ]
then
    consolediff road OUTPUT${KLIPS_MODULE}/roadconsole.txt $REF_ROAD_CONSOLE_OUTPUT
fi

if [ -n "${REF26_ROAD_CONSOLE_OUTPUT}" ]
then
    KERNVER=26 consolediff road OUTPUT${KLIPS_MODULE}/26roadconsole.txt $REF26_ROAD_CONSOLE_OUTPUT
fi

if [ -n "${REF_JAPAN_CONSOLE_OUTPUT}" ]
then
    consolediff japan OUTPUT${KLIPS_MODULE}/japanconsole.txt $REF_JAPAN_CONSOLE_OUTPUT
fi

if [ -n "${REF26_JAPAN_CONSOLE_OUTPUT}" ]
then
    KERNVER=26 consolediff japan OUTPUT${KLIPS_MODULE}/26japanconsole.txt $REF26_JAPAN_CONSOLE_OUTPUT
fi

if [ -n "${REF_CONSOLE_OUTPUT}" ] && [ -f OUTPUT${KLIPS_MODULE}/console.txt ]
then
    consolediff "" OUTPUT${KLIPS_MODULE}/console.txt $REF_CONSOLE_OUTPUT
fi

if [ -n "${REF26_CONSOLE_OUTPUT}" ] && [ -f OUTPUT${KLIPS_MODULE}/26console.txt ]
then
    KERNVER=26 consolediff "" OUTPUT${KLIPS_MODULE}/26console.txt $REF26_CONSOLE_OUTPUT
fi

if [ -n "${REF_PUB_OUTPUT}" ]
then
    base=`basename ${REF_PUB_OUTPUT} .txt`
    pcap_filter public "${REF_PUB_OUTPUT}" $base "${REF_PUB_FILTER}"
fi

if [ -n "${REF_PRIV_OUTPUT}" ]
then
    base=`basename ${REF_PRIV_OUTPUT} .txt`
    pcap_filter private "${REF_PRIV_OUTPUT}" $base "${REF_PRIV_FILTER}"
fi

if [ -n "${REF_EAST_OUTPUT}" ]
then
    base=`basename ${REF_EAST_OUTPUT} .txt`
    pcap_filter east "${REF_EAST_OUTPUT}" $base "${REF_EAST_FILTER}"
fi

if [ -n "${REF_WEST_OUTPUT}" ]
then
    base=`basename ${REF_WEST_OUTPUT} .txt`
    pcap_filter west "${REF_WEST_OUTPUT}" $base "${REF_WEST_FILTER}"
fi



# $Log: redocon.sh,v $
# Revision 1.10  2005/05/01 03:27:29  mcr
# 	check for appropriate files before trying to use them.
#
# Revision 1.9  2005/04/22 13:30:00  mcr
# 	try to redo 2.6 kernel console messages as well.
#
# Revision 1.8  2005/04/06 17:59:48  mcr
# 	look at REF26 values too.
#
# Revision 1.7  2003/05/05 17:59:35  mcr
# 	also process the "japan" console.
#
# Revision 1.6  2003/02/27 09:15:47  mcr
# 	process ROAD console output as well.
#
# Revision 1.5  2002/11/28 19:57:08  mcr
# 	refactored out "pcap_filter" as common code so that
# 	it could be called from "redocon" script.
#
# Revision 1.4  2002/11/03 00:25:47  mcr
# 	rather than guessing which console files are in use for
# 	klipstest, vs umlplutotest, just test the REF_* variables.
#
# Revision 1.3  2002/10/16 21:59:47  mcr
# 	changes to console output to accomodate 2.4.19-uml12.
#
# Revision 1.2  2002/10/10 16:25:03  mcr
# 	make sure to call compatvariables before using testparams.sh
# 	settings.
#
# Revision 1.1  2002/08/29 23:46:15  mcr
# 	repeat the CONSOLEDIFF operations - used for debugging filters
#
# Revision 1.2  2002/05/23 14:26:39  mcr
# 	verify that $TEST_TYPE is actually set.
#
# Revision 1.1  2002/05/05 23:12:05  mcr
# 	runme.sh script now common for all test types.
#
# 

