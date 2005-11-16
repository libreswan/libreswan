#!/bin/sh

: ==== start ====

PATH=/testing/pluto/bin:$PATH export PATH

export PLUTO="ipsec pluto"
export WHACK="ipsec whack"
/testing/pluto/bin/ifconfigs up

cd /tmp
mkdir log
ln -s /testing/pluto/log.ref       .
ln -s /testing/pluto/ipsec.secrets .
ln -s /testing/pluto/ipsec.d/west .
ln -s /testing/pluto/ipsec.d/east .

. doauto --diff isakmp-psk isakmp-rsa isakmp-rsa-case
. doauto --diff isakmp-rsa-dot ipsec-psk ipsec-rsa ipsec-rsa-time-neg 
. doauto --diff ipsec-rsa-time-trunc ipsec-rsa-time-neg-dontrekey 
. doauto --diff ipsec-rsa-delete ipsec-rsa-c ipsec-rsa-co 
. doauto --diff ipsec-psk-rw ipsec-psk-id-rw ipsec-rsa-rw
: ==== end ====
