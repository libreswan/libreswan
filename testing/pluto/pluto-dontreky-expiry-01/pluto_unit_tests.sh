: ==== start ====

PATH=/testing/pluto/bin:$PATH export PATH

export PLUTO="ipsec pluto"
export WHACK="ipsec whack"

/testing/pluto/bin/ifconfigs up

cd /tmp
mkdir log
ln -s /testing/pluto/log.ref       .
ln -s /testing/pluto/ipsec.secrets .

. doauto --diff ipsec-rsa-time-neg ipsec-rsa-time-trunc 
. doauto --diff ipsec-rsa-time-neg-dontrekey ipsec-rsa-time-trunc-dontrekey

: ==== end ====
