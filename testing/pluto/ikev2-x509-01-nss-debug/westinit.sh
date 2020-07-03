/testing/guestbin/swan-prep --x509
certutil -D -n east -d sql:/etc/ipsec.d
# confirm that the network is alive
../../pluto/bin/wait-until-alive -I 192.0.1.254 192.0.2.254
# ensure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# confirm clear text does not get through
../../pluto/bin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
ipsec _stackmanager start
mkdir /tmp/tmpnss-west
export NSS_DISABLE_UNLOAD=no
export NSS_SDB_USE_CACHE=yes
export TMPDIR=/tmp/tmpnss-west
export NSS_DEBUG_PKCS11_MODULE="NSS Internal PKCS #11 Module"
export LOGGING=1
export SOCKETTRACE=1
export NSPR_LOG_FILE=/tmp/nspr.log
export NSS_OUTPUT_FILE=/tmp/nss.log
# 2 3 and 4 are more verbose
export NSPR_LOG_MODULES="nss_mod_log:4"
ipsec pluto --config /etc/ipsec.conf
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add ikev2-westnet-eastnet-x509-cr
ipsec whack --impair suppress-retransmits
echo "initdone"
