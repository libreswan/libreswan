#!/bin/sh

if test $# -lt 1 ; then
    cat <<EOF 1>&2
Usage:
  $0 --start [ KEY ]
  $0 --log
EOF
    echo "Usage: $0 {--start,--log}" 1>&2
    echo "Usage: $0 {--start,--log}" 1>&2
    exit 1
fi

run()
{
    echo "" "$@"
    "$@"
}

start()
{
    local key=nic
    if test "$#" -gt 0 ; then
	key=$1
    fi
    run cp /testing/x509/keys/${key}.key /etc/ocspd/private/nic_key.pem
    run cp /testing/x509/certs/${key}.crt /etc/ocspd/certs/nic.pem
    run cp /testing/x509/real/mainca/root.cert /etc/ocspd/certs/mainca.pem
    run cp /testing/x509/ocspd.conf /etc/ocspd/ocspd.conf
    run openssl crl -inform DER -in /testing/x509/crls/cacrlvalid.crl -outform PEM -out /etc/ocspd/crls/revoked_crl.pem
    run restorecon -R /etc/ocspd
    run ocspd -v -d -c /etc/ocspd/ocspd.conf
}

log()
{
    {
	journalctl /sbin/ocspd --no-pager
    } | {
	tee OUTPUT/`hostname`.ocspd.log
    } | {
	sed -n \
	    -e '/: request for certificate/ s/.*: //p' \
	    -e '/: status / s/.*: //p' \
	    -e '/: INFO::CORE/ s/.*: //p' \
	    -e '/: ERROR/ s/.*: //p'
    }
}

case "$1" in
    --start)
	shift
	start "$@"
	;;
    --log)
	shift
	log "$@"
	;;
esac
