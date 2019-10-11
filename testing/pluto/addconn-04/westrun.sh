# did pluto forked addconn pickup right config file location and load the connection
ipsec status | grep westnet-eastnet-ipv4-psk-ikev2 | grep "eroute owner"
# does status show /tmp/test.conf as config file used for startup
ipsec status | grep configfile
echo done
