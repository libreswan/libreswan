#!/bin/sh

if test $# -lt 1 ; then
    cat <<EOF 1>&2
Usage:
  $0 start [ KEY ]
  $0 log
EOF
    exit 1
fi

RUN() {
    echo "" "$@"
    "$@"
}

CUT() {
    echo ==== cut ====
}

TUC() {
    echo ==== tuc ====
}

START() {
    if test "$#" -gt 0 ; then
	key=$1
    else
	key=nic
    fi
    {
	CUT
	# silent but deadly; on NS there are no files
	RUN find /etc/ocspd -ls
	RUN rm -rf /etc/ocspd/*
	RUN mkdir -p /etc/ocspd/private /etc/ocspd/certs /etc/ocspd/crls
	TUC
    }
    RUN cp /testing/x509/real/mainca/${key}.key /etc/ocspd/private/nic_key.pem
    RUN cp /testing/x509/real/mainca/${key}.end.cert /etc/ocspd/certs/nic.pem
    RUN cp /testing/x509/real/mainca/root.cert /etc/ocspd/certs/mainca.pem
    RUN cp /testing/x509/ocspd.conf /etc/ocspd/ocspd.conf
    RUN openssl crl -inform DER -in /testing/x509/real/mainca/crl-is-up-to-date.crl -outform PEM -out /etc/ocspd/crls/revoked_crl.pem
    RUN restorecon -R /etc/ocspd
    {
	CUT
	RUN find /etc/ocspd -ls
	TUC
    }
    RUN ocspd -v -d -c /etc/ocspd/ocspd.conf
}

LOG() {
    east=$(cat /testing/x509/real/mainca/east.serial)
    west=$(cat /testing/x509/real/mainca/west.serial)
    nic=$(cat /testing/x509/real/mainca/nic.serial)
    revoked=$(cat /testing/x509/real/mainca/revoked.serial)
    east_chain_endcert=$(cat /testing/x509/real/mainca/east_chain_endcert.serial)
    west_chain_endcert=$(cat /testing/x509/real/mainca/west_chain_endcert.serial)
    {
	journalctl /sbin/ocspd --no-pager
    } | {
	tee OUTPUT/`hostname`.ocspd.log
    } | {
	# strip date prefix before replacing certificate serial
	# numbers; else pattern will match date/time instead.
	sed \
	    -e '/: OpenCA OCSPD/,/: Configuration loaded/d' \
	    -e '/ got connd /d' \
	    -e '/: INFO::Local Address/d' \
	    -e '/: INFO::OPENCA_SRV_INFO_TREAD/d' \
	    \
	    -e 's;^.*: ;;' \
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
	    -e 's;\([ ]\)'${west_chain_endcert}'\([] ]\);\1<WEST_CHAIN_ENDCERT>\2;'
    }
}

case "$1" in
    *start)
	shift
	START "$@"
	;;
    *log)
	shift
	LOG "$@"
	;;
esac
