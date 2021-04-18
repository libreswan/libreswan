#!/bin/sh

LC_CTYPE=C
export LC_CTYPE

#once unbound work properly replace the next lines; XXX: huh?
sed -i 's/5353/53/' /etc/nsd/nsd.conf /etc/nsd/server.d/nsd-server-libreswan.conf

echo starting dns

systemctl start nsd

echo ==== cut ====
for f in /etc/nsd/server.d/nsd-server-libreswan.conf /etc/nsd/nsd.conf ; do
    echo $f
    grep port: $f
    grep 53 $f
done
systemctl status -l nsd-keygen
systemctl status -l nsd
echo ==== tuc ====

# only interested in errors
$(dirname $0)/wait-for.sh --match 'notice: nsd started' -- systemctl status nsd > /dev/null

# grr, dig writes dns lookup failures to stdout.  Need to save stdout
# and then, depending on the exit code, display it.

domain=road.testing.libreswan.org

echo digging for ${domain} IPSECKEY

dig @127.0.0.1 ${domain} IPSECKEY > /tmp/dns.log
status=$?

test ${status} -ne 0 || echo ==== cut ====
cat /tmp/dns.log
systemctl status -l nsd-keygen
systemctl status -l nsd
test ${status} -ne 0 || echo ==== tuc ====

# These dig return code descriptions are lifted directly from the
# manual page.

case ${status} in
    0) echo Everything went well, including things like NXDOMAIN.
       echo Found $(grep "^${domain}" /tmp/dns.log | wc -l) records
       ;;
    1) echo Usage error. ;;
    8) echo Could not open batch file. ;;
    9) echo No reply from server. ;;
    10) echo Internal error. ;;
    *) echo Unknown return code: $? ;;
esac

# this prints the NSD server version
echo ==== cut ====
dig @192.1.2.254 chaos version.server txt
echo ==== tuc ====

exit ${status}
