/testing/guestbin/swan-prep --nokeys

# scrub the nssdb (is there a swan-prep option?)
rm /etc/ipsec.d/*.db
modutil -create -dbdir /etc/ipsec.d -force

key=east

# start with the raw key
cp ../../x509/keys/${key}.key OUTPUT/
cat OUTPUT/${key}.key
# create a CSR and using that ...
openssl req -new -subj "/CN=${key}" -key OUTPUT/${key}.key -out OUTPUT/${key}.csr < /dev/null
openssl req -text -in OUTPUT/${key}.csr -noout | grep ${key}
# ... create a self signed cert
openssl x509 -req -days 365 -in OUTPUT/${key}.csr -signkey OUTPUT/${key}.key -out OUTPUT/${key}.crt
# turn that into a PKCS#12
openssl pkcs12 -export -password pass:foobar -in OUTPUT/${key}.crt -inkey OUTPUT/${key}.key -name ${key} -out OUTPUT/${key}.p12

key=west

# start with the raw key
cp ../../x509/keys/${key}.key OUTPUT/
cat OUTPUT/${key}.key
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

# patch up ipsec.conf
ipsec certutil -K | awk "/ east/ { print \$4 }" > OUTPUT/east.ckaid
ipsec certutil -K | awk "/ west/ { print \$4 }" > OUTPUT/west.ckaid
sed -i -e "s/@east-ckaid@/`cat OUTPUT/east.ckaid`/" /etc/ipsec.conf
sed -i -e "s/@west-ckaid@/`cat OUTPUT/west.ckaid`/" /etc/ipsec.conf

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
ipsec auto --status
echo "initdone"
