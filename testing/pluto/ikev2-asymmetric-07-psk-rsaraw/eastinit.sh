/testing/guestbin/swan-prep
# we add the PSK here, so we pick up the proper default secrets containing east's raw key
echo '# when get_preshared_key() can deal with asymmetric, we can narrow it down' >> /etc/ipsec.secrets
echo ': PSK "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"' >> /etc/ipsec.secrets
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
ipsec auto --status | grep westnet-eastnet-ikev2
echo "initdone"
