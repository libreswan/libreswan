#!/bin/sh 

# This script is used to setup the regression testing environment
# invoke the tests and record the results. It expects the following
# variables to be in the environment.
#
#    $BUILDSPOOL
#    $BRANCH            the name of the branch, or HEAD.
#    $YEAR              today's year.
#    $MONTH             today's month.
#    $TODAY             today's date.
#
# it is expected that $BUILDSPOOL/freeswan contains a checked out copy
# of the source tree that is ready for building. 
#
# In general, this script is in fact running from
#    $BUILDSPOOL/freeswan/testing/utils/regress-stage2.sh
#
# invoked from regress-nightly.sh. The two stages permit the regress-nightly.sh
# scritpt, which must be invoked from outside of the CVS tree to change
# very seldom.
#
# This script will further look for $HOME/freeswan-regress-env.sh for a list 
# of variables to include.
#
# This should include
#

# die if anything dies.
set -e

mkdir -p $BUILDSPOOL/UMLPOOL

TOPMODULE=${TOPMODULE-openswan-2}

umlsetup=$BUILDSPOOL/${TOPMODULE}/umlsetup.sh

echo "#" `date`                                                     >$umlsetup
echo "POOLSPACE=$BUILDSPOOL/UMLPOOL"                               >>$umlsetup
echo "BUILDTOP=$BUILDSPOOL/${TOPMODULE} export BUILDTOP"               >>$umlsetup

# ${TOPMODULE}-regress-eng.sh should have the following variables
# defined. This should be the only local configuration required.
# 
# KERNPOOL=/abigail/kernel/linux-2.4.17
# UMLPATCH=/abigail/user-mode-linux/uml-patch-2.4.17-4.bz2
# BASICROOT=/abigail/user-mode-linux/root-6.0
# SHAREDIR=${BASICROOT}/usr/share
#
# Please see doc/umltesting.html for details on filling in these variables.
#

if [ -f $HOME/${TOPMODULE}-regress-env.sh ]
then
    cat $HOME/${TOPMODULE}-regress-env.sh                              >>$umlsetup
    . $HOME/${TOPMODULE}-regress-env.sh
fi

echo "FREESWANDIR=\$BUILDTOP"                                      >>$umlsetup
echo "REGULARHOSTS='sunrise sunset nic sec beet carrot'"           >>$umlsetup
echo "OPENSWANHOSTS='east west japan road north'"                  >>$umlsetup

# setup regression test recording area.
REGRESSRESULTS=${REGRESSTREE}/${BRANCH}/${YEAR}/${MONTH}/${TODAY} export REGRESSRESULTS
echo "REGRESSRESULTS=${REGRESSRESULTS}"				>>$umlsetup


mkdir -p ${REGRESSRESULTS}

perl -e 'print time()."\n";' >${REGRESSRESULTS}/datestamp

cd $BUILDSPOOL/${TOPMODULE} && make check

perl $BUILDSPOOL/${TOPMODULE}/testing/utils/regress-summarize-results.pl $REGRESSRESULTS notest









