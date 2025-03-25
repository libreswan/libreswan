/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainca/nic.p12

# defaults

ipsec start
../../guestbin/wait-until-pluto-started
ipsec status | grep ocsp
ipsec stop
grep '^[^|].*OCSP' /tmp/pluto.log

# ocsp-cache-{min,max} defaults

ipsec pluto --config ocsp-cache.conf
ipsec status | grep ocsp
ipsec whack --shutdown

ipsec pluto --ocsp-cache-min-age=100  --ocsp-cache-max-age=1000
ipsec status | grep ocsp
ipsec whack --shutdown

# ocsp-uri= broken

./run.sh ocsp-uri-broken.conf

# ocsp-trustname= broken

./run.sh ocsp-trustname-broken.conf

# both ocsp-trustname= and ocsp-uri broken

./run.sh ocsp-broken.conf

# ocsp-uri= wrong

./run.sh ocsp-uri-wrong.conf

# ocsp-uri= missing

./run.sh ocsp-uri-missing.conf

# ocsp-trustname= missing

./run.sh ocsp-trustname-missing.conf
