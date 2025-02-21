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
    if test "$#" -gt 0 ; then
	key=$1
	run cp /testing/x509/keys/${key}.key /etc/ocspd/private/nic_key.pem
	run cp /testing/x509/certs/${key}.crt /etc/ocspd/certs/nic.pem
	run cp /testing/x509/real/mainca/root.cert /etc/ocspd/certs/mainca.pem
    else
	key=nic
	run cp /testing/x509/real/mainca/${key}.end.key /etc/ocspd/private/nic_key.pem
	run cp /testing/x509/real/mainca/${key}.end.cert /etc/ocspd/certs/nic.pem
	run cp /testing/x509/real/mainca/root.cert /etc/ocspd/certs/mainca.pem
    fi
    run cp /testing/x509/ocspd.conf /etc/ocspd/ocspd.conf
    run openssl crl -inform DER -in /testing/x509/real/mainca/crl-is-up-to-date.crl -outform PEM -out /etc/ocspd/crls/revoked_crl.pem
    run restorecon -R /etc/ocspd
    run ocspd -v -d -c /etc/ocspd/ocspd.conf
}

log()
{
    east=$(cat /testing/x509/real/mainca/east.serial)
    west=$(cat /testing/x509/real/mainca/west.serial)
    nic=$(cat /testing/x509/real/mainca/nic.serial)
    revoked=$(cat /testing/x509/real/mainca/revoked.serial)
    east_chain_endcert=$(cat /testing/x509/certs/east_chain_endcert.serial)
    west_chain_endcert=$(cat /testing/x509/certs/west_chain_endcert.serial)
    {
	journalctl /sbin/ocspd --no-pager
    } | {
	tee OUTPUT/`hostname`.ocspd.log
    } | {
	sed \
	    -e '/: OpenCA OCSPD/,/: Configuration loaded/d' \
	    -e '/ got connd /d' \
	    -e '/: INFO::Local Address/d' \
	    -e '/: INFO::OPENCA_SRV_INFO_TREAD/d' \
	    \
    	    -e 's;\([ ]\)'${east}'$;\1<EAST>;' \
	    -e 's;\([ ]\)'${west}'$;\1<WEST>;' \
	    -e 's;\([ ]\)'${nic}'$;\1<NIC>;' \
	    -e 's;\([ ]\)'${revoked}'$;\1<REVOKED>;' \
	    -e 's;\([ ]\)'${east_chain_endcert}'$;\1<EAST_CHAIN_ENDCERT>;' \
	    -e 's;\([ ]\)'${west_chain_endcert}'$;\1<WEST_CHAIN_ENDCERT>;' \
	    \
    	    -e 's;\([ ]\)'${east}'\([] ]\);\1<EAST>\2;' \
	    -e 's;\([ ]\)'${west}'\([] ]\);\1<WEST>\2;' \
	    -e 's;\([ ]\)'${nic}'\([] ]\);\1<NIC>\2;' \
	    -e 's;\([ ]\)'${revoked}'\([] ]\);\1<REVOKED>\2;' \
	    -e 's;\([ ]\)'${east_chain_endcert}'\([] ]\);\1<EAST_CHAIN_ENDCERT>\2;' \
	    -e 's;\([ ]\)'${west_chain_endcert}'\([] ]\);\1<WEST_CHAIN_ENDCERT>\2;' \
	    \
	    -e 's;^.*: ;;'
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
