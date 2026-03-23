# scrub the nssdb
/testing/guestbin/swan-prep --nokeys

key=east

# start with the raw key
cp /testing/x509/real/mainca/${key}.key OUTPUT/${key}.key
# create a CSR and using that ...
openssl req -new -subj "/CN=${key}" -key OUTPUT/${key}.key -out OUTPUT/${key}.csr < /dev/null
openssl req -text -in OUTPUT/${key}.csr -noout | grep ${key}
# ... create a self signed cert
openssl x509 -req -days 365 -in OUTPUT/${key}.csr -signkey OUTPUT/${key}.key -out OUTPUT/${key}.crt
# turn that into a PKCS#12
openssl pkcs12 -export -password pass:foobar -in OUTPUT/${key}.crt -inkey OUTPUT/${key}.key -name ${key} -out OUTPUT/${key}.p12

key=west

# start with the raw key
cp /testing/x509/real/mainca/${key}.key OUTPUT/${key}.key
# create a CSR and using that ...
openssl req -new -subj "/CN=${key}" -key OUTPUT/${key}.key -out OUTPUT/${key}.csr < /dev/null
openssl req -text -in OUTPUT/${key}.csr -noout | grep ${key}
# ... create a self signed cert
openssl x509 -req -days 365 -in OUTPUT/${key}.csr -signkey OUTPUT/${key}.key -out OUTPUT/${key}.crt
# turn that into a PKCS#12
openssl pkcs12 -export -password pass:foobar -in OUTPUT/${key}.crt -inkey OUTPUT/${key}.key -name ${key} -out OUTPUT/${key}.p12

# import it
ipsec pk12util -i OUTPUT/west.p12 -W foobar
ipsec pk12util -i OUTPUT/east.p12 -W foobar
ipsec certutil -K

# patch up and (re)install ipsec.conf

EAST_CKAID=$(ipsec certutil -K | awk '/ east/ { print $4 }')
WEST_CKAID=$(ipsec certutil -K | awk '/ west/ { print $4 }')
sed -e "s/@@EAST_CKAID@@/${EAST_CKAID}/" -e "s/@@WEST_CKAID@@/${WEST_CKAID}/" ipsec.conf > OUTPUT/ipsec.conf

ipsec start
../../guestbin/wait-until-pluto-started
cp -v OUTPUT/ipsec.conf /etc/ipsec.conf
ipsec add westnet-eastnet-ikev2
ipsec connectionstatus westnet-eastnet-ikev2
echo "initdone"
