rm -f /var/lib/ipsec/nss/*

ipsec initnss # succeed
ipsec initnss # fail

rm /var/lib/ipsec/nss/*.db
ipsec initnss # succeed with warning
