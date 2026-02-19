/testing/guestbin/swan-prep --x509
ipsec certutil -D -n west
mkdir /tmp/tmpnss-east
export NSS_DISABLE_UNLOAD=no
export NSS_SDB_USE_CACHE=yes
export TMPDIR=/tmp/tmpnss-east
export NSS_DEBUG_PKCS11_MODULE="NSS Internal PKCS #11 Module"
export LOGGING=1
export SOCKETTRACE=1
export NSPR_LOG_FILE=/tmp/nspr.log
export NSS_OUTPUT_FILE=/tmp/nss.log
# 2 3 and 4 are more verbose
export NSPR_LOG_MODULES="nss_mod_log:4"
ipsec pluto --config /etc/ipsec.conf
../../guestbin/wait-until-pluto-started
ipsec auto --add ikev2-westnet-eastnet-x509-cr
echo "initdone"
