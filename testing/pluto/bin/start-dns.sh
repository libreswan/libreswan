#!/bin/sh

#once unbound work properly replace the next lines; XXX: huh?
sed -i 's/5353/53/' /etc/nsd/nsd.conf

echo starting dns

systemctl start nsd

# grr, dig writes dns lookup failures to stdout.  Need to save stdout
# and then, depending on the exit code, display it.

domain=road.testing.libreswan.org

echo digging for ${domain} IPSECKEY

dig @127.0.0.1 ${domain} IPSECKEY > /tmp/dns.log
status=$?

# These dig return code descriptions are lifted directly from the
# manual page.

case ${status} in
    0) echo Everything went well, including things like NXDOMAIN. ;;
    1) echo Usage error. ;;
    8) echo Could not open batch file. ;;
    9) echo No reply from server. ;;
    10) echo Internal error. ;;
    *) echo Unknown return code: $? ;;
esac

# dump the result; possibly sanitized

if test ${status} -ne 0; then
    cat /tmp/dns.log
    systemctl status nsd
else
    echo Found $(grep "^${domain}" /tmp/dns.log | wc -l) records
    echo ==== cut ====
    cat /tmp/dns.log
    echo ==== tuc ====
fi

# this prints the NSD server version
echo ==== cut ====
dig @192.1.2.254 chaos version.server txt
echo ==== tuc ====
