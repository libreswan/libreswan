/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/west.all.p12
/testing/x509/import.sh real/mainca/nic.all.p12
ipsec certutil -L
ipsec certutil -L -n mainca | sed -e '/^ *[^a-fA-F0-9][a-fA-F0-9][a-fA-F0-9]:/ d'
ipsec certutil -L -n west | sed -e '/^ *[^a-fA-F0-9][a-fA-F0-9][a-fA-F0-9]:/ d'
ipsec certutil -L -n nic | sed -e '/^ *[^a-fA-F0-9][a-fA-F0-9][a-fA-F0-9]:/ d'

/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/otherca/otherwest.all.p12
ipsec certutil -L
ipsec certutil -L -n otherca | sed -e '/^ *[^a-fA-F0-9][a-fA-F0-9][a-fA-F0-9]:/ d'
ipsec certutil -L -n otherwest | sed -e '/^ *[^a-fA-F0-9][a-fA-F0-9][a-fA-F0-9]:/ d'

/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/badca/badwest.all.p12
ipsec certutil -L
ipsec certutil -L -n badca | sed -e '/^ *[^a-fA-F0-9][a-fA-F0-9][a-fA-F0-9]:/ d'
ipsec certutil -L -n badwest | sed -e '/^ *[^a-fA-F0-9][a-fA-F0-9][a-fA-F0-9]:/ d'
