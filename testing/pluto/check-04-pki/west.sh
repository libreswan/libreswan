ipsec_cert() { ipsec certutil -L ; for n in "$@" ; do printf "*\n*\n* ${n}\n*\n*\n" ; ipsec certutil -L -n ${n} |  sed -e '/^ *[^a-fA-F0-9][a-fA-F0-9][a-fA-F0-9]:/ d' ; done ; }

/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/west.all.p12
/testing/x509/import.sh real/mainca/nic.all.p12
ipsec_cert mainca west nic

/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/otherca/otherwest.all.p12
ipsec_cert otherca otherwest

/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/badca/badwest.all.p12
ipsec_cert badca badwest

/testing/guestbin/swan-prep --nokeys
ipsec certutil -A -n west_chain_int_1 -t ,, -i /testing/x509/certs/west_chain_int_1.crt
ipsec_cert west_chain_int_1

/testing/guestbin/swan-prep --nokeys
ipsec certutil -A -n west_chain_int_2 -t ,, -i /testing/x509/certs/west_chain_int_2.crt
ipsec_cert west_chain_int_2

/testing/guestbin/swan-prep --nokeys
ipsec pk12util -W foobar -i /testing/x509/pkcs12/west_chain_endcert.p12
ipsec_cert west_chain_endcert
