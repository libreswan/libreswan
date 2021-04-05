/testing/guestbin/swan-prep
# confirm CKAID is in NSS database
certutil -K -d sql:/etc/ipsec.d
ipsec start
../../guestbin/wait-until-pluto-started
# will fail due to bug
ipsec auto --add westnet-eastnet-ikev2-ckaid
# load our key via workaround
ipsec auto --add workaround-load-my-pubkey
# will work now :/
ipsec auto --add westnet-eastnet-ikev2-ckaid
echo "initdone"
