#!/bin/sh

: ==== start ====

PATH=/testing/pluto/bin:$PATH export PATH

named

export PLUTO="ipsec pluto"
export WHACK="ipsec whack"
/testing/pluto/bin/ifconfigs up

cd /tmp
mkdir log
ln -s /testing/pluto/log.ref       .
ln -s /testing/pluto/ipsec.secrets .
ln -s /testing/pluto/ipsec.d/west .
ln -s /testing/pluto/ipsec.d/east .

. doauto --diff k4096-dns isakmp-dnsrsa isakmp-dnsrsa-case isakmp-dnsrsa-dot
. doauto --diff ipsec-dnsrsa ipsec-dnsrsa-delete ipsec-dnsrsa-c ipsec-dnsrsa-co
. doauto --diff ipsec-dnsrsa-rw
. doauto --diff ipsec-oppo ipsec-oppo-seq ipsec-oppo-twice
. doauto --diff ipsec-oppo-narrow ipsec-oppo-miss
. doauto --diff oe oe-noo clear block-pl reject-pl ipsec-oppo-group
. doauto --diff isakmp-rsa-myid
. doauto --diff regr-oppo-narrow regr-shunt-oppo regr-template-32-32

: ==== end ====
