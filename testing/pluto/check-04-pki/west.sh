/testing/guestbin/swan-prep --nokeys
ipsec certutil -A -i /testing/x509/cacerts/mainca.crt -n mainca -t "CT,,"
ipsec pk12util -W foobar -i /testing/x509/pkcs12/mainca/west.p12
ipsec certutil -L
ipsec certutil -L -n mainca | sed -e '/^ *[^a-fA-F0-9][a-fA-F0-9][a-fA-F0-9]:/ d'
ipsec certutil -L -n west | sed -e '/^ *[^a-fA-F0-9][a-fA-F0-9][a-fA-F0-9]:/ d'

/testing/guestbin/swan-prep --nokeys
ipsec certutil -A -i /testing/x509/cacerts/otherca.crt -n otherca -t "CT,,"
ipsec pk12util -W foobar -i /testing/x509/pkcs12/otherca/otherwest.p12
ipsec certutil -L
ipsec certutil -L -n otherca | sed -e '/^ *[^a-fA-F0-9][a-fA-F0-9][a-fA-F0-9]:/ d'
ipsec certutil -L -n otherwest | sed -e '/^ *[^a-fA-F0-9][a-fA-F0-9][a-fA-F0-9]:/ d'

/testing/guestbin/swan-prep --nokeys
ipsec certutil -A -i /testing/x509/cacerts/badca.crt -n badca -t "CT,,"
ipsec pk12util -W foobar -i /testing/x509/pkcs12/badca/badwest.p12
ipsec certutil -L
ipsec certutil -L -n badca | sed -e '/^ *[^a-fA-F0-9][a-fA-F0-9][a-fA-F0-9]:/ d'
ipsec certutil -L -n badwest | sed -e '/^ *[^a-fA-F0-9][a-fA-F0-9][a-fA-F0-9]:/ d'
