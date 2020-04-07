#!/bin/sh -x

# used by ikev2-x509-39-OU-comma

nssdir="$(dirname $0)/nss"
mydir="$(dirname $0)"
mkdir -p ${nssdir}
rm -f ${nssdir}/*
ipsec initnss --nssdir ${nssdir}
echo "dsadasdasdasdadasdasdasdasdsadfwerwerjfdksdjfksdlfhjsdk" > ${nssdir}/cert.noise
certutil -S -k rsa -n cacert -s "CN=cacert" -v 12 -d . -t "C,C,C" -x -d sql:${nssdir}  -z ${nssdir}/cert.noise -f ${mydir}/nss-pw 
certutil -S -k rsa -c cacert -n 'client' --extSAN 'dns:client.libreswan.org' -m 101 -s 'C=CZ, ST=Moravia, L=Brno, O=Test Example, OU="Global, Support, Services", CN=client' -v 12 -t 'u,u,u' -d sql:${nssdir} -z ${nssdir}/cert.noise -f ${mydir}/nss-pw 
certutil -S -k rsa -c cacert -n 'server' --extSAN 'dns:server.libreswan.org' -m 102 -s 'C=CZ, ST=Moravia, L=Brno, O=Test Example, OU="Global, Support, Services", CN=server' -v 12 -t 'u,u,u' -d sql:${nssdir} -z ${nssdir}/cert.noise -f ${mydir}/nss-pw 
pk12util -o ${nssdir}/client.p12 -n client -d sql:${nssdir} -W 'foobar' -K 'foobar' 
pk12util -o ${nssdir}/server.p12 -n server -d sql:${nssdir} -W 'foobar' -K 'foobar' 
# tmp
certutil -S -k rsa -n cacertX -s "CN=cacertX" -v 12 -d . -t "C,C,C" -x -d sql:${nssdir}  -z ${nssdir}/cert.noise -f ${mydir}/nss-pw 
certutil -S -k rsa -c cacertX -n 'clientX' --extSAN 'dns:clientX.libreswan.org' -m 103 -s 'C=CZ, ST=Moravia, L=Brno, O=Test Example, OU="Global Support Services", CN=clientX' -v 12 -t 'u,u,u' -d sql:${nssdir} -z ${nssdir}/cert.noise -f ${mydir}/nss-pw 
certutil -S -k rsa -c cacertX -n 'serverX' --extSAN 'dns:serverX.libreswan.org' -m 104 -s 'C=CZ, ST=Moravia, L=Brno, O=Test Example, OU="Global Support Services", CN=serverX' -v 12 -t 'u,u,u' -d sql:${nssdir} -z ${nssdir}/cert.noise -f ${mydir}/nss-pw 
pk12util -o ${nssdir}/clientX.p12 -n clientX -d sql:${nssdir} -W 'foobar' -K 'foobar' 
pk12util -o ${nssdir}/serverX.p12 -n serverX -d sql:${nssdir} -W 'foobar' -K 'foobar' 
# on clients to import
# pk12util -i /testing/x509/nss/client.p12 -d sql:/etc/ipsec.d -K 'foobar' -W 'foobar'
# certutil -M -d sql:/etc/ipsec.d -n cacert -t 'CT,,'
