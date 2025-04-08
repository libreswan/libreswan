ipsec_cert() { ipsec certutil -L ; for n in "$@" ; do printf "*\n*\n* ${n}\n*\n*\n" ; set ipsec certutil -L -n ${n} ; echo " $@" ; "$@" ; done ; }

/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/west.p12
/testing/x509/import.sh real/mainca/nic.p12
ipsec_cert mainca west nic

/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh otherca/otherwest.p12
ipsec_cert otherca otherwest

/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/west_chain_int_1.end.cert
ipsec_cert west_chain_int_1

/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/west_chain_int_2.end.cert
ipsec_cert west_chain_int_2

/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/west_chain_endcert.p12
ipsec_cert west_chain_endcert
