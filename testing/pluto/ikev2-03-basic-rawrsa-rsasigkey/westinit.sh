/testing/guestbin/swan-prep
rm /etc/ipsec.secrets
ipsec start
/testing/pluto/bin/wait-until-pluto-started
