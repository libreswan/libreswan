../../guestbin/ipsec-look.sh
# on east, it should show it failed the NSS IPsec profile and used the NSS TLS profile
hostname | grep east > /dev/null && grep "verify_end_cert trying profile" /tmp/pluto.log
