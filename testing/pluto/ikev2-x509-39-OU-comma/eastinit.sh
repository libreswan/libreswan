/testing/guestbin/swan-prep --nokeys

# Always zap and recreate special comma certs. Saved under OUTPUT/nss
# and left waiting for clients (west et.al.) which an import using:
# ipsec pk12util -i OUTPUT/nss/client.p12 -K 'foobar' -W 'foobar'
# ipsec certutil -M -n cacert -t 'CT,,'

# new scratch DB
rm -f OUTPUT/nss
mkdir OUTPUT/nss
certutil -N -d sql:OUTPUT/nss -f /dev/null
# generate keys
echo "dsadasdasdasdadasdasdasdasdsadfwerwerjfdksdjfksdlfhjsdk" > OUTPUT/nss/cert.noise
certutil -S -k rsa -n cacert -s "CN=cacert" -v 12 -d . -t "C,C,C" -x -d sql:OUTPUT/nss  -z OUTPUT/nss/cert.noise -f /dev/null
certutil -S -k rsa -c cacert -n 'client' --extSAN 'dns:client.libreswan.org' -m 101 -s 'C=CZ, ST=Moravia, L=Brno, O=Test Example, OU="Global, Support, Services", CN=client' -v 12 -t 'u,u,u' -d sql:OUTPUT/nss -z OUTPUT/nss/cert.noise -f /dev/null
certutil -S -k rsa -c cacert -n 'server' --extSAN 'dns:server.libreswan.org' -m 102 -s 'C=CZ, ST=Moravia, L=Brno, O=Test Example, OU="Global, Support, Services", CN=server' -v 12 -t 'u,u,u' -d sql:OUTPUT/nss -z OUTPUT/nss/cert.noise -f /dev/null
pk12util -o OUTPUT/nss/client.p12 -n client -d sql:OUTPUT/nss -W 'foobar' -K 'foobar'
pk12util -o OUTPUT/nss/server.p12 -n server -d sql:OUTPUT/nss -W 'foobar' -K 'foobar'
# tmp
certutil -S -k rsa -n cacertX -s "CN=cacertX" -v 12 -d . -t "C,C,C" -x -d sql:OUTPUT/nss  -z OUTPUT/nss/cert.noise -f /dev/null
certutil -S -k rsa -c cacertX -n 'clientX' --extSAN 'dns:clientX.libreswan.org' -m 103 -s 'C=CZ, ST=Moravia, L=Brno, O=Test Example, OU="Global Support Services", CN=clientX' -v 12 -t 'u,u,u' -d sql:OUTPUT/nss -z OUTPUT/nss/cert.noise -f /dev/null
certutil -S -k rsa -c cacertX -n 'serverX' --extSAN 'dns:serverX.libreswan.org' -m 104 -s 'C=CZ, ST=Moravia, L=Brno, O=Test Example, OU="Global Support Services", CN=serverX' -v 12 -t 'u,u,u' -d sql:OUTPUT/nss -z OUTPUT/nss/cert.noise -f /dev/null
pk12util -o OUTPUT/nss/clientX.p12 -n clientX -d sql:OUTPUT/nss -W 'foobar' -K 'foobar'
pk12util -o OUTPUT/nss/serverX.p12 -n serverX -d sql:OUTPUT/nss -W 'foobar' -K 'foobar'

# init and import real server
ipsec initnss > /dev/null 2> /dev/null
ipsec pk12util -i OUTPUT/nss/server.p12 -K 'foobar' -W 'foobar'
ipsec certutil -M -n cacert -t 'CT,,'

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add x509
echo "initdone"
