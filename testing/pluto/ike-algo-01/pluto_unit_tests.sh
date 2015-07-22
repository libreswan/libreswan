#!/bin/sh

TESTING=${TESTING:-/testing}
PATH=${TESTING}/pluto/bin:$PATH export PATH
TESTNAME=ike-algo-01

export PLUTO="ipsec pluto"
export WHACK="ipsec whack"
${TESTING}/pluto/bin/ifconfigs up
. CONFIG

cd /tmp
mkdir -p $TESTNAME
cd $TESTNAME

export HELPERS="--nhelpers 0 "

mkdir -p log.ref
mkdir -p log
LD=log
ln -s ${TESTING}/pluto/$TESTNAME/isakmp-aggr-psk-east.txt log.ref/pr-log
ln -s ${TESTING}/pluto/$TESTNAME/isakmp-aggr-psk-west.txt log.ref/pi-log
ln -s ${TESTING}/pluto/$TESTNAME/isakmp-aggr-psk-whack.txt log.ref/wi-log
ln -s ${TESTING}/pluto/ipsec.secrets .
ln -s ${TESTING}/pluto/ipsec.d/west .
ln -s ${TESTING}/pluto/ipsec.d/east .

# make sure that we can core dump!
ulimit -c unlimited

# start Initiator pluto (daemon forks to return control)
$DOPLUTO west >$LD/pi-log 2>&1

me --name ike-algo-01 --psk --ike 3des-md5  $EASTHOST $TO $WESTHOST $TIMES2 ;
me --name ike-algo-02 --psk --ike 3des-sha1 $EASTHOST $TO $WESTHOST $TIMES2 ;
me --name ike-algo-03 --psk --ike 3des-sha  $EASTHOST $TO $WESTHOST $TIMES2 ;
me --name ike-algo-04 --psk --ike aes-md5   $EASTHOST $TO $WESTHOST $TIMES2 ;
me --name ike-algo-05 --psk --ike aes-sha1  $EASTHOST $TO $WESTHOST $TIMES2 ;
me --name ike-algo-06 --psk --ike aes-sha   $EASTHOST $TO $WESTHOST $TIMES2 ;
me --status

$DOWHACK shutdown

if [ -f pluto/west/core ];
then
	echo CORE west
	echo CORE west
	echo CORE west
fi

