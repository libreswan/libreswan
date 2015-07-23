#!/bin/sh

: ==== start ====

export PLUTO="ipsec pluto"
export WHACK="ipsec whack"
if [ -d $MYBOX/testing ]; then TESTING=$MYBOX/testing; else TESTING=/testing;fi
PATH=${TESTING}/pluto/bin:$PATH export PATH

${TESTING}/pluto/bin/ifconfigs up

cd /tmp
mkdir log
ln -f -s ${TESTING}/pluto/log.ref       .
ln -f -s ${TESTING}/pluto/ipsec.secrets .
ln -f -s ${TESTING}/pluto/ipsec.d/west .
ln -f -s ${TESTING}/pluto/ipsec.d/east .

. doauto --diff isakmp-psk isakmp-rsa isakmp-rsa-case
. doauto --diff isakmp-rsa-dot ipsec-psk ipsec-rsa ipsec-rsa-time-neg
. doauto --diff ipsec-rsa-time-trunc ipsec-rsa-time-neg-dontrekey
. doauto --diff ipsec-rsa-delete ipsec-rsa-c ipsec-rsa-co
. doauto --diff ipsec-psk-rw ipsec-psk-id-rw ipsec-rsa-rw
: ==== end ====
